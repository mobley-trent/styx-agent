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

	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
)

// Hermetic container checks for the engagement CA (§4.4). They are the only
// place the image itself is exercised — the fake runtime pins the harness's
// wiring, these pin the distro tools it depends on — so they run where Docker
// and root are available (the root-Docker CI job) and skip everywhere else.

// brokenImageRef is the base the sandbox image is built from, before its
// packages are installed: no ca-certificates, no openssl, no trust bundle. It
// stands in for an image whose CA install cannot be confirmed, and the digest
// keeps it that way.
const brokenImageRef = "kalilinux/kali-rolling@sha256:1ff4a2be3849333687b3ed2b31bb5af0cd1b7c0a11ec7713feb5abe5a6b2795c"

// hermeticDocker returns a Docker runtime with image available, skipping when
// the daemon or the image is out of reach.
func hermeticDocker(t *testing.T, image string) *Docker {
	t.Helper()
	ctx := context.Background()
	docker, err := NewDocker()
	if err != nil {
		t.Skipf("docker client unavailable: %v", err)
	}
	t.Cleanup(func() { _ = docker.Close() })
	if err := docker.Available(ctx); err != nil {
		t.Skipf("docker daemon unavailable: %v", err)
	}
	if err := pullImage(ctx, docker, image); err != nil {
		t.Skipf("cannot obtain test image %s: %v", image, err)
	}
	return docker
}

// testImage is the check's image, overridable for a local run against another
// pin.
func testImage(env, fallback string) string {
	if override := os.Getenv(env); override != "" {
		return override
	}
	return fallback
}

// TestHermeticEngagementCATrust is the §4.4 acceptance against the pinned
// sandbox image: the engagement CA is mounted read-only, update-ca-certificates
// really installs it, and container tooling then validates a live MITM
// exchange.
//
// It is hermetic — a loopback TLS stub on the host and the harness proxy, no
// real target — and skips wherever root or Docker are absent.
func TestHermeticEngagementCATrust(t *testing.T) {
	skipWithoutEgressPrivileges(t)

	ctx := context.Background()
	image := testImage("STYX_EGRESS_TEST_IMAGE", DefaultImage)
	docker := hermeticDocker(t, image)

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

// TestHermeticCAInstallRefusal is the refuse-never-silent half (§4.4, §8)
// against a real image: one that cannot install the anchor must fail the
// session, name the mount and the step, and leave no container or network
// behind. The fake runtime asserts the same shape from a hook; this proves the
// shell the harness actually runs really exits non-zero there.
func TestHermeticCAInstallRefusal(t *testing.T) {
	skipWithoutEgressPrivileges(t)

	ctx := context.Background()
	image := testImage("STYX_BROKEN_IMAGE_TEST_IMAGE", brokenImageRef)
	docker := hermeticDocker(t, image)

	ca, err := OpenCA(CAOptions{
		Root:       t.TempDir(),
		ProjectDir: t.TempDir(),
		Engagement: "ca-refusal",
	})
	if err != nil {
		t.Fatalf("OpenCA() = %v", err)
	}
	auditor := &recordingAuditor{}
	name := "ca-refusal"
	id := sessionID(name)

	_, err = StartSession(ctx, SessionOptions{
		Runtime:   docker,
		Image:     image,
		Name:      name,
		Allowed:   []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		Workspace: t.TempDir(),
		Auditor:   auditor,
		Interception: &InterceptionOptions{
			CA:         ca,
			CaptureDir: filepath.Join(t.TempDir(), "captures", name),
		},
	})
	if err == nil {
		t.Fatalf("StartSession() = nil error, want a refusal: %s ships no update-ca-certificates", image)
	}
	for _, want := range []string{
		"installing the engagement CA failed",
		ContainerCAPath,
		"update-ca-certificates",
		"not found",
		"refusing the session",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal = %v, want it to name %q", err, want)
		}
	}

	if failed := auditor.ofKind(EventCAInstalled); len(failed) != 1 || failed[0].Reason != "failed" {
		t.Errorf("ca-install events = %+v, want the failed attempt recorded", failed)
	}
	if len(auditor.ofKind(EventProxyStop)) == 0 {
		t.Error("the refused session left its proxy unrecorded; want a proxy-stop decision")
	}

	// Nothing outlives the refusal: not the container, not the network.
	containers, err := docker.cli.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("name", "styx-session-"+id)),
	})
	if err != nil {
		t.Fatalf("list containers: %v", err)
	}
	if len(containers) != 0 {
		t.Errorf("refused session left %d container(s), want none", len(containers))
	}
	if _, err := docker.cli.NetworkInspect(ctx, "styx-net-"+id, network.InspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Errorf("network inspect after refusal = %v, want the session network gone", err)
	}
}
