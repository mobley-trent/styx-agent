package containerlayer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// Isolation is a session's egress-enforcement level (§5.2, §9.5). Its string
// values match audit.Isolation, so the app can record one as the other without
// this package importing audit.
type Isolation string

const (
	// IsolationContainer is per-session container execution with the egress
	// allowlist programmed at the host's network edge.
	IsolationContainer Isolation = "container"
	// IsolationDegraded is container execution without host-edge egress
	// enforcement: the container runs with no external network and the
	// harness-mediated fallback proxy is its only egress path.
	IsolationDegraded Isolation = "degraded-isolation"
	// IsolationUnavailable is returned when the runtime itself could not be
	// reached. It is never a silent state: exec tools refuse.
	IsolationUnavailable Isolation = "unavailable"
)

// CommandRunner is the production Runner: it shells a host command out.
type CommandRunner struct{}

// Run implements Runner.
func (CommandRunner) Run(ctx context.Context, stdin string, args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("containerlayer: no command")
	}
	//nolint:gosec // the command and arguments are harness-controlled, not model input.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ContainerSpec describes the session container the runtime must create (§5.2).
// It never carries a Docker socket bind: the harness owns the socket, the
// container must not.
type ContainerSpec struct {
	// Image is the session image.
	Image string
	// Name is the container name, unique per session.
	Name string
	// NetworkID is the session network the container attaches to. It is never
	// the default bridge and never host networking.
	NetworkID string
	// Cmd is the container's long-running command; it keeps the container
	// alive so execs have a target.
	Cmd []string
	// Env is the container environment (proxy settings, PATH, ...).
	Env []string
	// Binds are host mounts. The workspace is the only intended mount; a
	// Docker socket bind is rejected before creation.
	Binds []string
	// DNS is the container's resolver, when the harness authoritative
	// resolver is running (§5.2).
	DNS []string
	// WorkingDir is the in-container working directory.
	WorkingDir string
}

// ExecRequest is one command run inside the session container.
type ExecRequest struct {
	// Cmd is the argv to run.
	Cmd []string
	// Env is extra environment for the exec.
	Env []string
	// WorkDir is the in-container working directory.
	WorkDir string
}

// ExecResult is one exec's outcome.
type ExecResult struct {
	// Stdout and Stderr are the captured streams.
	Stdout string
	Stderr string
	// ExitCode is the process exit status.
	ExitCode int
}

// Runtime is the container engine the session drives. The Docker SDK
// implementation is the production one; tests substitute a fake, so session
// orchestration is fully testable without a Docker daemon.
type Runtime interface {
	// Available reports whether the engine is reachable.
	Available(ctx context.Context) error
	// CreateNetwork creates the per-session network and returns its ID.
	CreateNetwork(ctx context.Context, req NetworkRequest) (string, error)
	// RemoveNetwork deletes a network, ignoring one that is already gone.
	RemoveNetwork(ctx context.Context, id string) error
	// CreateContainer creates (but does not start) the session container.
	CreateContainer(ctx context.Context, spec ContainerSpec) (string, error)
	// StartContainer starts a created container.
	StartContainer(ctx context.Context, id string) error
	// Exec runs one command in a container.
	Exec(ctx context.Context, id string, req ExecRequest) (ExecResult, error)
	// RemoveContainer force-removes a container.
	RemoveContainer(ctx context.Context, id string) error
	// Close releases the runtime's client resources.
	Close() error
}

// NetworkRequest describes the per-session bridge network (§5.2). Internal
// networks have no external route; the degraded fallback uses them.
type NetworkRequest struct {
	// Name is the network name.
	Name string
	// Bridge is the host interface name Docker gives the bridge. Setting it
	// explicitly is what lets the egress rules scope to this session.
	Bridge string
	// Internal disables external connectivity for the network. Degraded
	// isolation runs the container on an internal network.
	Internal bool
	// Subnet and Gateway pin the network's addressing. Pinning them lets the
	// fallback proxy bind a deterministic address the container can reach.
	Subnet  string
	Gateway string
}

// ErrDockerSocketBind is returned when a container spec tries to mount the
// Docker socket. The socket is the harness's authority; a session container
// that could reach it would escape every boundary at once (§5.2).
var ErrDockerSocketBind = fmt.Errorf("containerlayer: refusing to mount the Docker socket into a session container")

// validateContainerSpec rejects a spec that would break the isolation
// contract. It runs before any container is created, so a bad spec never
// leaves a running container behind.
func validateContainerSpec(spec ContainerSpec) error {
	if strings.TrimSpace(spec.Image) == "" {
		return fmt.Errorf("containerlayer: container image is required")
	}
	if strings.TrimSpace(spec.NetworkID) == "" {
		return fmt.Errorf("containerlayer: container network is required (never the default bridge, never host networking)")
	}
	for _, bind := range spec.Binds {
		if isDockerSocket(bind) {
			return fmt.Errorf("%w: %s", ErrDockerSocketBind, bind)
		}
	}
	return nil
}

// isDockerSocket reports whether a bind mount exposes the Docker socket.
func isDockerSocket(bind string) bool {
	src, _, _ := strings.Cut(bind, ":")
	src = strings.TrimSpace(src)
	if base := pathBase(src); base == "docker.sock" {
		return true
	}
	switch src {
	case "/var/run/docker.sock", "/run/docker.sock":
		return true
	}
	return false
}

// pathBase is path.Base without importing path for one call.
func pathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// sessionID derives a stable, short identifier from session material, so two
// sessions never collide on a bridge or table name.
func sessionID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:5]) // 10 hex characters
}

// bridgeName is the host bridge interface for a session id. Linux interface
// names are capped at 15 characters; `styx` plus 10 hex is 14.
func bridgeName(id string) string { return "styx" + id }

// sessionSubnet derives a /24 (or /64 for IPv6) for a session id. It is a
// deterministic private range, so the fallback proxy can bind the gateway
// address without asking Docker for it.
func sessionSubnet(id string) (subnet, gateway string) {
	sum := sha256.Sum256([]byte("subnet:" + id))
	// 172.30.0.0/16 carved into /24s, avoiding Docker's usual 172.17–172.29.
	third := int(sum[0]%200) + 30 // 30..229
	return fmt.Sprintf("172.%d.0.0/24", third), fmt.Sprintf("172.%d.0.1", third)
}

// extraAllowed parses operator-configured egress destinations. A malformed
// entry is skipped: the allowlist is a widening, and an unparseable widening
// must never be silently applied as something else.
func extraAllowed(entries []string) []netip.Prefix {
	var out []netip.Prefix
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p)
			continue
		}
		if ip, err := netip.ParseAddr(e); err == nil {
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	return out
}
