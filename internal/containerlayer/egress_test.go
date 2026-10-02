package containerlayer

import (
	"context"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/image"
)

// TestHermeticEgressEnforcement is the §5.2 acceptance test: with real Docker
// and a programmable firewall, a self-spun listener on the session network is
// reachable and an unroutable TEST-NET destination dies at the firewall.
//
// It is hermetic — no real internet — and skips gracefully wherever privileges
// or the firewall backend are absent (local macOS, unprivileged CI). The CI
// gate runs it in a root Docker job.
func TestHermeticEgressEnforcement(t *testing.T) {
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

	runner := CommandRunner{}
	if _, err := DetectFirewall(ctx, runner); err != nil {
		t.Skipf("no programmable firewall backend: %v", err)
	}

	image := DefaultImage
	if override := os.Getenv("STYX_EGRESS_TEST_IMAGE"); override != "" {
		image = override
	}
	if err := pullImage(ctx, docker, image); err != nil {
		t.Skipf("cannot obtain test image %s: %v", image, err)
	}

	// Compute the session's own subnet so the allowlist can include it: the
	// helper listener will run on the session network inside that subnet.
	name := "egress-test"
	id := sessionID(name)
	subnet, _ := sessionSubnet(id)
	netPrefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		t.Fatalf("session subnet %q: %v", subnet, err)
	}

	session, err := StartSession(ctx, SessionOptions{
		Runtime:   docker,
		Image:     image,
		Name:      name,
		Allowed:   []netip.Prefix{netPrefix},
		Firewall:  nil, // detect: enforced isolation on a root runner
		Workspace: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("StartSession() = %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	if session.Isolation() != IsolationContainer {
		t.Fatalf("isolation = %q, want container on a root runner with nft", session.Isolation())
	}

	// A helper listener on the same network: this is the "allowed target".
	serverID, serverIP := startHelperListener(t, ctx, docker, image, session.NetworkID())
	t.Cleanup(func() { _ = docker.RemoveContainer(ctx, serverID) })

	// Allowed: the self-spun listener answers.
	reach := runInContainer(t, ctx, session,
		`python3 -c "import urllib.request; print(urllib.request.urlopen('http://`+serverIP+`:8000', timeout=10).status)"`)
	if !strings.Contains(reach, "200") {
		t.Errorf("pinned listener result = %q, want HTTP 200 from the allowed target", reach)
	}

	// Denied: TEST-NET-1 is unroutable and not on the allowlist, so the
	// firewall drops it.
	denied := runInContainer(t, ctx, session,
		`python3 -c "import socket; socket.setdefaulttimeout(5); socket.create_connection(('192.0.2.1', 80))"`)
	if !strings.Contains(denied, "exit code") && !strings.Contains(strings.ToLower(denied), "error") && !strings.Contains(strings.ToLower(denied), "timed out") {
		t.Errorf("TEST-NET result = %q, want a connection failure (the firewall dropped it)", denied)
	}
}

// skipWithoutEgressPrivileges skips unless the environment can enforce and run
// egress: Linux, root, a working nft/iptables, and a Docker daemon.
func skipWithoutEgressPrivileges(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping hermetic egress test in short mode")
	}
	if runtime.GOOS != "linux" {
		t.Skip("egress enforcement requires Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("egress enforcement requires root (CAP_NET_ADMIN)")
	}
}

// runInContainer runs a shell command in the session container and returns its
// rendered output.
func runInContainer(t *testing.T, ctx context.Context, session *Session, command string) string {
	t.Helper()
	out, err := session.Shell(ctx, command)
	if err != nil {
		t.Fatalf("session.Shell(%q) = %v", command, err)
	}
	return out
}

// startHelperListener starts a container on networkID serving HTTP on port
// 8000, and returns its container ID and in-network IP.
func startHelperListener(t *testing.T, ctx context.Context, docker *Docker, image, networkID string) (string, string) {
	t.Helper()
	id, err := docker.CreateContainer(ctx, ContainerSpec{
		Image:     image,
		Name:      "styx-egress-listener",
		NetworkID: networkID,
		Cmd:       []string{"python3", "-m", "http.server", "8000"},
	})
	if err != nil {
		t.Fatalf("create helper listener: %v", err)
	}
	if err := docker.StartContainer(ctx, id); err != nil {
		t.Fatalf("start helper listener: %v", err)
	}

	// Wait briefly for the interface address to appear.
	var ip string
	for i := 0; i < 20; i++ {
		ip = containerIP(ctx, docker, id, networkID)
		if ip != "" {
			return id, ip
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("helper listener never got an address on %s", networkID)
	return id, ""
}

// containerIP reads a container's address on a specific network.
func containerIP(ctx context.Context, docker *Docker, id, networkID string) string {
	inspect, err := docker.cli.ContainerInspect(ctx, id)
	if err != nil {
		return ""
	}
	for _, ep := range inspect.NetworkSettings.Networks {
		if ep.NetworkID == networkID {
			return ep.IPAddress
		}
	}
	return ""
}

// pullImage pulls an image if it is not already present, best-effort.
func pullImage(ctx context.Context, docker *Docker, ref string) error {
	rc, err := docker.cli.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	_, _ = io.Copy(io.Discard, rc)
	return nil
}
