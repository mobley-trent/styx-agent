package containerlayer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHermeticEngagementCATrust is the §4.4 acceptance against the pinned
// sandbox image: the engagement CA is mounted read-only, update-ca-certificates
// really installs it, and container tooling then validates a live MITM
// exchange. The fake-runtime tests pin the harness's wiring; this one pins the
// distro tools that wiring depends on, which nothing else exercises.
//
// It is hermetic — a loopback TLS stub on the host and the harness proxy, no
// real target — and skips wherever root or Docker are absent. The CI egress job
// runs it as root; the gate job skips it.
func TestHermeticEngagementCATrust(t *testing.T) {
	skipWithoutEgressPrivileges(t)

	ctx := context.Background()
	docker, err := NewDocker()
	if err != nil {
		t.Skipf("docker client unavailable: %v", err)
	}
	defer func() { _ = docker.Close() }()
	if err := docker.Available(ctx); err != nil {
		t.Skipf("docker daemon unavailable: %v", err)
	}

	image := DefaultImage
	if override := os.Getenv("STYX_EGRESS_TEST_IMAGE"); override != "" {
		image = override
	}
	if err := pullImage(ctx, docker, image); err != nil {
		t.Skipf("cannot obtain test image %s: %v", image, err)
	}

	// The destination the container cannot reach directly: a loopback TLS stub
	// on the host, which only the proxy dials. A 200 therefore proves the
	// container validated a leaf the engagement CA signed, not the target's own
	// certificate.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "trusted through the engagement CA")
	}))
	defer upstream.Close()
	trustUpstream := x509.NewCertPool()
	trustUpstream.AddCert(upstream.Certificate())

	ca, err := OpenCA(CAOptions{
		Root:       t.TempDir(),
		ProjectDir: t.TempDir(),
		Engagement: "ca-trust",
	})
	if err != nil {
		t.Fatalf("OpenCA() = %v", err)
	}
	auditor := &recordingAuditor{}
	captureDir := filepath.Join(t.TempDir(), "captures", "ca-trust")

	session, err := StartSession(ctx, SessionOptions{
		Runtime:   docker,
		Image:     image,
		Name:      "ca-trust",
		Allowed:   []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		Workspace: t.TempDir(),
		Auditor:   auditor,
		Interception: &InterceptionOptions{
			CA:          ca,
			CaptureDir:  captureDir,
			UpstreamTLS: &tls.Config{RootCAs: trustUpstream, MinVersion: tls.VersionTLS12},
		},
	})
	if err != nil {
		t.Fatalf("StartSession() = %v, want the CA install confirmed in %s", err, image)
	}
	t.Cleanup(func() { _ = session.Close() })

	if events := auditor.ofKind(EventCAInstalled); len(events) != 1 || events[0].Reason == "failed" {
		t.Fatalf("ca-install events = %+v, want exactly one confirmed installation", events)
	}

	// Independent of the harness's own hashed-link confirmation: the anchor is
	// in the bundle the image's tooling reads.
	if out := runInContainer(ctx, t, session, "openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt "+ContainerCAPath); !strings.Contains(out, ": OK") {
		t.Fatalf("openssl verify = %q, want the engagement CA trusted by the bundle", out)
	}

	// The mount is read-only inside the container, even for its root: only the
	// certificate left the PKI directory (§4.4).
	if out := runInContainer(ctx, t, session, "echo tampered >> "+ContainerCAPath+" 2>&1 || true"); !strings.Contains(out, "Read-only file system") {
		t.Errorf("writing to the CA mount = %q, want a read-only failure", out)
	}

	// A real request from the image's own curl through the proxy is accepted —
	// which it cannot be unless the install took: without the anchor, curl
	// refuses the proxy's leaf with a certificate error.
	status := runInContainer(ctx, t, session,
		"curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "+upstream.URL+"/audit?token=abc")
	if strings.TrimSpace(status) != "200" {
		t.Fatalf("container curl through the interception proxy = %q, want 200", status)
	}

	// The traffic it produced is the session's evidence, not just a status code.
	//nolint:gosec // the segment is the one this session opened under the test's temp dir.
	recorded, err := os.ReadFile(filepath.Join(captureDir, "capture-1.jsonl"))
	if err != nil {
		t.Fatalf("read capture segment: %v", err)
	}
	if !strings.Contains(string(recorded), "/audit?token=abc") {
		t.Errorf("capture = %s, want the proxied exchange recorded", recorded)
	}
}
