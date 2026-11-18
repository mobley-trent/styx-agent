package app

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/containerlayer"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
)

// TestEngagementSessionTrustsTheProxyAndCapturesEgress covers the activation
// half of docs/browser-and-proxy.md §4.2, §4.4 and §7: an engagement session
// carries the CA mount, the proxy environment, and a capture under the project
// tree, its decisions reach the audit trail, and /mode safe stops the listener
// and flushes the capture.
func TestEngagementSessionTrustsTheProxyAndCapturesEgress(t *testing.T) {
	dir := t.TempDir()
	engPath := writeFile(t, dir, "engagement.yaml", inSessionEngagement)

	rt := &appFakeRuntime{}
	opts := buildOptions(t, dir, fakemodel.New())
	opts.Engagement = engPath
	opts.ContainerRuntime = func() (containerlayer.Runtime, error) { return rt, nil }
	opts.ContainerFirewall = appFakeFirewall{}
	opts.ContainerProxyAddr = "127.0.0.1:0"

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	// The session starts lazily, on the first exec; starting it is what brings
	// the proxy, the CA trust, and the capture up.
	if _, err := h.container.Start(context.Background()); err != nil {
		t.Fatalf("start session = %v", err)
	}

	proxyURL := h.container.ProxyURL()
	if proxyURL == "" {
		t.Fatal("engagement session has no egress proxy")
	}
	capture := h.container.Capture()
	if capture == nil {
		t.Fatal("engagement session kept no capture")
	}

	if len(rt.containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(rt.containers))
	}
	spec := rt.containers[0]
	if !strings.Contains(strings.Join(spec.Binds, " "), containerlayer.ContainerCAPath) {
		t.Errorf("container binds = %v, want the read-only CA mount", spec.Binds)
	}
	if !strings.Contains(strings.Join(spec.Env, " "), "HTTPS_PROXY="+proxyURL) {
		t.Errorf("container env = %v, want the proxy settings", spec.Env)
	}

	segment := filepath.Join(containerlayer.CapturePath(dir, h.SessionID()), "capture-1.jsonl")
	if _, err := os.Stat(segment); err != nil {
		t.Errorf("capture segment: %v", err)
	}

	// Decisions are audited; traffic is not (§9).
	reasons := proxyReasons(readAuditRecords(t, dir))
	for _, want := range []string{"proxy-start", "ca-install"} {
		if !reasons[want] {
			t.Errorf("audit reasons = %v, want the %q decision", reasons, want)
		}
	}

	if _, err := h.command("mode", "safe"); err != nil {
		t.Fatalf("/mode safe = %v", err)
	}
	if _, err := capture.Write(containerlayer.Exchange{ID: "after-teardown"}); err == nil {
		t.Error("the capture is still writable after /mode safe; teardown must flush it")
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy URL %q: %v", proxyURL, err)
	}
	if _, err := net.DialTimeout("tcp", u.Host, 500*time.Millisecond); err == nil {
		t.Errorf("proxy at %s outlived the session", u.Host)
	}
	if !proxyReasons(readAuditRecords(t, dir))["proxy-stop"] {
		t.Error("teardown was not recorded as a proxy-stop decision")
	}
}

// proxyReasons is the set of reasons the audit trail carries for the proxy's
// own decisions.
func proxyReasons(records []audit.Record) map[string]bool {
	reasons := map[string]bool{}
	for _, record := range records {
		if record.Tool == "proxy" {
			reasons[record.Reason] = true
		}
	}
	return reasons
}
