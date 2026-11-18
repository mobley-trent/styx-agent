package containerlayer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// engagementInterception builds an interception configuration for a session
// test: a fresh CA and a capture directory.
func engagementInterception(t *testing.T) (*CA, *InterceptionOptions) {
	t.Helper()
	ca, err := OpenCA(CAOptions{Root: t.TempDir(), ProjectDir: "/work/acme", Engagement: "acme-q4"})
	if err != nil {
		t.Fatalf("OpenCA() = %v", err)
	}
	return ca, &InterceptionOptions{CA: ca, CaptureDir: filepath.Join(t.TempDir(), "captures", "session-1")}
}

// TestEngagementSessionBindsAndInstallsTheCA covers the trust half (§4.4): the
// certificate is mounted read-only at the anchor path and installed by
// `update-ca-certificates` before the session is handed back.
func TestEngagementSessionBindsAndInstallsTheCA(t *testing.T) {
	rt := newFakeRuntime()
	fw := &fakeFirewall{}
	auditor := &recordingAuditor{}
	ca, intercept := engagementInterception(t)

	opts := enforcedOptions(rt, fw)
	opts.Interception = intercept
	opts.Auditor = auditor

	s, err := StartSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("StartSession() = %v", err)
	}
	defer func() { _ = s.Close() }()

	specs := rt.containerSpecs()
	if len(specs) != 1 {
		t.Fatalf("containers = %d, want 1", len(specs))
	}
	wantBind := ca.CertPath() + ":" + ContainerCAPath + ":ro"
	if !hasBind(specs[0].Binds, wantBind) {
		t.Errorf("container binds = %v, want the read-only CA mount %q", specs[0].Binds, wantBind)
	}
	for _, bind := range specs[0].Binds {
		if strings.Contains(bind, ca.KeyPath()) {
			t.Error("the CA key was mounted into the container; only the certificate may leave the PKI directory")
		}
	}

	install := ""
	for _, exec := range rt.execs {
		if joined := strings.Join(exec.Cmd, " "); strings.Contains(joined, "update-ca-certificates") {
			install = joined
		}
	}
	if install == "" {
		t.Fatalf("execs = %+v, want the CA install", rt.execs)
	}
	if !strings.Contains(install, ContainerCAPath) {
		t.Errorf("install command = %q, want it to read the mount %q", install, ContainerCAPath)
	}

	events := auditor.ofKind(EventCAInstalled)
	if len(events) != 1 {
		t.Fatalf("ca-install events = %+v, want exactly one", events)
	}
	if events[0].Listener != ContainerCAPath || events[0].Detail != ca.CertPath() {
		t.Errorf("ca-install event = %+v, want the mount and the host certificate path", events[0])
	}
}

// TestSessionRefusesAnUnconfirmedCAInstall is the refuse-never-silent half
// (§4.4, §8): an install the harness cannot confirm fails the session, names
// the mount and the install step, and leaves nothing running behind it.
func TestSessionRefusesAnUnconfirmedCAInstall(t *testing.T) {
	rt := newFakeRuntime()
	rt.execHook = func(req ExecRequest) (ExecResult, bool) {
		if strings.Contains(strings.Join(req.Cmd, " "), "update-ca-certificates") {
			return ExecResult{Stdout: "update-ca-certificates: command not found", ExitCode: 127}, true
		}
		return ExecResult{}, false
	}
	auditor := &recordingAuditor{}
	_, intercept := engagementInterception(t)

	opts := enforcedOptions(rt, &fakeFirewall{})
	opts.Interception = intercept
	opts.Auditor = auditor

	_, err := StartSession(context.Background(), opts)
	if err == nil {
		t.Fatal("StartSession() = nil error, want a refusal when the CA install cannot be confirmed")
	}
	for _, want := range []string{ContainerCAPath, "update-ca-certificates", "exit 127"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal = %v, want it to name %q", err, want)
		}
	}
	if networks, containers := rt.snapshot(); networks != 0 || containers != 0 {
		t.Errorf("refused session left %d networks and %d containers, want none", networks, containers)
	}
	failed := auditor.ofKind(EventCAInstalled)
	if len(failed) != 1 || failed[0].Reason != "failed" {
		t.Errorf("ca-install events = %+v, want the failed attempt recorded", failed)
	}
	if len(auditor.ofKind(EventProxyStop)) == 0 {
		t.Error("the refused session left its proxy unrecorded; want a proxy-stop decision")
	}
}

// TestEngagementSessionNarrowsTheFirewallToTheProxyListener covers the routing
// half (§4.2): while capture is on, the container may reach the proxy's
// listener and nothing else, so a tool that ignores the proxy environment is
// denied at the edge instead of passing uncaptured.
func TestEngagementSessionNarrowsTheFirewallToTheProxyListener(t *testing.T) {
	rt := newFakeRuntime()
	fw := &fakeFirewall{}
	_, intercept := engagementInterception(t)

	opts := enforcedOptions(rt, fw)
	opts.Interception = intercept

	s, err := StartSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("StartSession() = %v", err)
	}
	defer func() { _ = s.Close() }()

	proxyURL := s.ProxyURL()
	if proxyURL == "" {
		t.Fatal("engagement session has no egress proxy")
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy URL %q: %v", proxyURL, err)
	}
	listener, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		t.Fatalf("proxy listener %q: %v", u.Hostname(), err)
	}

	if len(fw.applied) != 1 {
		t.Fatalf("firewall applied = %+v, want one spec", fw.applied)
	}
	allowed := fw.applied[0].Allowed
	if len(allowed) != 1 || allowed[0] != netip.PrefixFrom(listener, listener.BitLen()) {
		t.Errorf("firewall allowlist = %v, want only the proxy listener %s", allowed, listener)
	}

	specs := rt.containerSpecs()
	if len(specs) != 1 {
		t.Fatalf("containers = %d, want 1", len(specs))
	}
	for _, prefix := range []string{"HTTP_PROXY=" + proxyURL, "HTTPS_PROXY=" + proxyURL, "http_proxy=" + proxyURL, "https_proxy=" + proxyURL} {
		if !hasEnvPrefix(specs[0].Env, prefix) {
			t.Errorf("container env = %v, want %q", specs[0].Env, prefix)
		}
	}

	if _, err := os.Stat(filepath.Join(intercept.CaptureDir, "capture-1.jsonl")); err != nil {
		t.Errorf("capture segment: %v", err)
	}
}

// TestSafeModeSessionAlsoRoutesThroughTheProxy covers the other half of "both
// modes": safe mode runs the tunnel and sets the environment, but keeps no
// capture and no CA, and the pinned allowlist still stands at the firewall.
func TestSafeModeSessionAlsoRoutesThroughTheProxy(t *testing.T) {
	rt := newFakeRuntime()
	fw := &fakeFirewall{}

	opts := enforcedOptions(rt, fw)

	s, err := StartSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("StartSession() = %v", err)
	}
	defer func() { _ = s.Close() }()

	proxyURL := s.ProxyURL()
	if proxyURL == "" {
		t.Fatal("safe-mode session has no egress proxy")
	}
	if s.Capture() != nil {
		t.Error("safe mode kept a capture; there is nothing to attribute it to")
	}
	specs := rt.containerSpecs()
	if len(specs) != 1 {
		t.Fatalf("containers = %d, want 1", len(specs))
	}
	if !hasEnvPrefix(specs[0].Env, "HTTPS_PROXY="+proxyURL) {
		t.Errorf("container env = %v, want the proxy settings", specs[0].Env)
	}
	if len(fw.applied) != 1 || len(fw.applied[0].Allowed) != 1 || fw.applied[0].Allowed[0] != netip.MustParsePrefix("10.0.0.0/24") {
		t.Errorf("firewall allowlist = %+v, want the pinned set unchanged with no capture to protect", fw.applied)
	}
	for _, bind := range specs[0].Binds {
		if strings.Contains(bind, ContainerCAPath) {
			t.Errorf("safe-mode container binds = %v, want no engagement CA", specs[0].Binds)
		}
	}
}

// TestSessionCaptureRecordsProxiedTrafficAndStopsOnClose is the §12 acceptance
// at session level: a request made through the environment the container
// carries lands in the capture, and teardown stops the listener and flushes
// the segment.
func TestSessionCaptureRecordsProxiedTrafficAndStopsOnClose(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello from the target")
	}))
	defer upstream.Close()

	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	ca, intercept := engagementInterception(t)
	intercept.UpstreamTLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	rt := newFakeRuntime()
	opts := enforcedOptions(rt, &fakeFirewall{})
	opts.Allowed = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	opts.Interception = intercept

	s, err := StartSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("StartSession() = %v", err)
	}

	proxyURL, err := url.Parse(s.ProxyURL())
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	// Exactly what a container tool does with the session's environment: dial
	// the proxy, and trust the engagement CA it was handed.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(upstream.URL + "/secret?token=abc")
	if err != nil {
		t.Fatalf("GET through the session proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "hello from the target") {
		t.Fatalf("proxied response = %d %q, want the target's body", resp.StatusCode, body)
	}

	//nolint:gosec // the capture segment is the one this session opened.
	recorded, err := os.ReadFile(filepath.Join(intercept.CaptureDir, "capture-1.jsonl"))
	if err != nil {
		t.Fatalf("read capture segment: %v", err)
	}
	if !strings.Contains(string(recorded), "/secret?token=abc") {
		t.Errorf("capture = %s, want the proxied exchange recorded", recorded)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if _, err := net.DialTimeout("tcp", proxyURL.Host, 500*time.Millisecond); err == nil {
		t.Errorf("proxy at %s still accepts connections after teardown", proxyURL.Host)
	}
}

// hasBind reports whether a bind list carries an exact mount.
func hasBind(binds []string, want string) bool {
	for _, bind := range binds {
		if bind == want {
			return true
		}
	}
	return false
}
