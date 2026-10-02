package containerlayer

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Default constant container settings. The image is overridable; the harness
// does not build or ship images (§5.1: runtimes present in the container
// image).
const (
	// DefaultImage carries a shell and python3, so `bash` and `code_exec`
	// work out of the box. Operators pin their own security-tooling image.
	DefaultImage = "docker.io/library/python:3.12-slim"
	// DefaultContainerWorkspace is where the project is mounted.
	DefaultContainerWorkspace = "/workspace"
	// DefaultKeepAlive keeps the session container running as an exec target.
	DefaultKeepAlive = "sleep infinity"
)

// SessionOptions configures one per-session container (§5.2).
type SessionOptions struct {
	// Runtime is the container engine. Required.
	Runtime Runtime
	// Image is the session image; empty means DefaultImage.
	Image string
	// Name seeds the session's container, network, bridge, and table names.
	// It must be unique per session. Required.
	Name string
	// Workspace is the host directory mounted into the container, at
	// ContainerWorkspace.
	Workspace string
	// ContainerWorkspace is the in-container mount point; empty means
	// DefaultContainerWorkspace.
	ContainerWorkspace string
	// Allowed is the pinned egress set: the engagement's pins and prefixes
	// plus the run's own endpoints.
	Allowed []netip.Prefix
	// Firewall programs the host edge. Nil means detect one; tests inject a
	// fake.
	Firewall Firewall
	// FirewallRunner is the command seam detection uses when Firewall is nil.
	// Nil means the real command runner.
	FirewallRunner Runner
	// ProxyAddr optionally pins the fallback proxy's listen address; empty
	// binds the session gateway on an ephemeral port.
	ProxyAddr string
}

// Session is one running per-session container plus its egress enforcement: a
// host-edge allowlist when the firewall is programmable, or an internal
// network with the harness's egress proxy when it is not. It implements the
// agent's executor seam (Shell/Code), so the exec tools depend on behavior
// without this package leaking into agent.
type Session struct {
	rt Runtime

	containerID string
	networkID   string
	bridge      string
	spec        EgressSpec
	firewall    Firewall
	proxy       *EgressProxy
	isolation   Isolation
	workspace   string
	keepAlive   string

	mu     sync.Mutex
	closed bool
}

// StartSession brings up the session container and its egress path. It never
// returns a session whose isolation is silently unenforced: if the firewall
// cannot be programmed it falls back to degraded isolation (an internal
// network plus the harness proxy), and if that cannot be established either it
// refuses.
func StartSession(ctx context.Context, opts SessionOptions) (*Session, error) {
	if opts.Runtime == nil {
		return nil, errors.New("containerlayer: session options need a runtime")
	}
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("containerlayer: session options need a name")
	}
	if err := opts.Runtime.Available(ctx); err != nil {
		return nil, err
	}

	image := opts.Image
	if strings.TrimSpace(image) == "" {
		image = DefaultImage
	}
	workspace := opts.ContainerWorkspace
	if strings.TrimSpace(workspace) == "" {
		workspace = DefaultContainerWorkspace
	}

	id := sessionID(opts.Name)
	bridge := bridgeName(id)
	subnet, gateway := sessionSubnet(id)
	spec := EgressSpec{Bridge: bridge, Allowed: opts.Allowed}

	s := &Session{rt: opts.Runtime, bridge: bridge, spec: spec, workspace: workspace, keepAlive: DefaultKeepAlive}

	// Try enforced isolation first: an external bridge with the allowlist
	// programmed at the host edge.
	fw := opts.Firewall
	if fw == nil {
		runner := opts.FirewallRunner
		if runner == nil {
			runner = CommandRunner{}
		}
		detected, err := DetectFirewall(ctx, runner)
		if err != nil {
			// No backend: degrade visibly rather than run unenforced.
			return s.startDegraded(ctx, opts, image, workspace, subnet, gateway, err)
		}
		fw = detected
	}

	networkID, err := opts.Runtime.CreateNetwork(ctx, NetworkRequest{
		Name: "styx-net-" + id, Bridge: bridge, Subnet: subnet, Gateway: gateway,
	})
	if err != nil {
		return nil, err
	}
	s.networkID = networkID

	if err := fw.Apply(ctx, spec); err != nil {
		// The rules did not take: remove whatever a half-programmed backend
		// left, tear the network back down, and degrade — never leave a
		// container running on an unenforced bridge or a stray rule set.
		_ = fw.Remove(ctx, spec)
		_ = opts.Runtime.RemoveNetwork(ctx, networkID)
		s.networkID = ""
		return s.startDegraded(ctx, opts, image, workspace, subnet, gateway, err)
	}
	s.firewall = fw
	s.isolation = IsolationContainer

	if err := s.startContainer(ctx, opts, image, workspace, nil); err != nil {
		return nil, s.fail(ctx, err)
	}
	return s, nil
}

// startDegraded falls back to the internal-network + egress-proxy path (§5.2).
// The container gets no external route; the proxy is its only way out and
// forwards only to pinned addresses. If any step fails, StartSession refuses.
func (s *Session) startDegraded(ctx context.Context, opts SessionOptions, image, workspace, subnet, gateway string, cause error) (*Session, error) {
	networkID, err := opts.Runtime.CreateNetwork(ctx, NetworkRequest{
		Name: "styx-net-" + sessionID(opts.Name), Bridge: s.bridge,
		Internal: true, Subnet: subnet, Gateway: gateway,
	})
	if err != nil {
		return nil, fmt.Errorf("containerlayer: degraded isolation unavailable (firewall: %v): %w", cause, err)
	}
	s.networkID = networkID

	proxy, err := NewEgressProxy(EgressProxyOptions{
		Addr:  proxyListenAddr(opts.ProxyAddr, gateway),
		Check: prefixChecker(s.spec.Allowed),
	})
	if err != nil {
		return nil, s.fail(ctx, fmt.Errorf("containerlayer: degraded isolation unavailable: %w", err))
	}
	if err := proxy.Start(); err != nil {
		return nil, s.fail(ctx, err)
	}
	s.proxy = proxy
	s.isolation = IsolationDegraded

	// Inside the internal network the gateway is the container's route to the
	// proxy; the proxy URL is what the exec tools' clients dial.
	env := []string{
		"HTTP_PROXY=" + proxy.URL(),
		"HTTPS_PROXY=" + proxy.URL(),
		"http_proxy=" + proxy.URL(),
		"https_proxy=" + proxy.URL(),
	}
	if err := s.startContainer(ctx, opts, image, workspace, env); err != nil {
		return nil, s.fail(ctx, err)
	}
	return s, nil
}

// startContainer creates and starts the session container on the selected
// network. It is shared by the enforced and degraded paths; only the network
// and the proxy environment differ.
func (s *Session) startContainer(ctx context.Context, opts SessionOptions, image, workspace string, proxyEnv []string) error {
	var binds []string
	if strings.TrimSpace(opts.Workspace) != "" {
		binds = append(binds, opts.Workspace+":"+workspace)
	}
	spec := ContainerSpec{
		Image:      image,
		Name:       "styx-session-" + sessionID(opts.Name),
		NetworkID:  s.networkID,
		Cmd:        []string{"sh", "-c", s.keepAlive},
		Env:        proxyEnv,
		Binds:      binds,
		WorkingDir: workspace,
	}
	id, err := s.rt.CreateContainer(ctx, spec)
	if err != nil {
		return err
	}
	s.containerID = id
	if err := s.rt.StartContainer(ctx, id); err != nil {
		return err
	}
	return nil
}

// fail tears the session down and returns err, so a half-built session never
// leaks a network, proxy, or container.
func (s *Session) fail(ctx context.Context, err error) error {
	_ = s.Close()
	return err
}

// Isolation is the enforcement level this session established.
func (s *Session) Isolation() Isolation { return s.isolation }

// Bridge is the host interface the session's egress rules scope to.
func (s *Session) Bridge() string { return s.bridge }

// NetworkID is the session network's identifier.
func (s *Session) NetworkID() string { return s.networkID }

// ContainerID is the session container's identifier.
func (s *Session) ContainerID() string { return s.containerID }

// ProxyURL is the fallback proxy's URL, empty when egress is enforced at the
// host edge.
func (s *Session) ProxyURL() string {
	if s.proxy == nil {
		return ""
	}
	return s.proxy.URL()
}

// Shell runs a shell command in the session container (the `bash` tool).
func (s *Session) Shell(ctx context.Context, command string) (string, error) {
	return s.Exec(ctx, ExecRequest{Cmd: []string{"sh", "-c", command}, WorkDir: s.workspace})
}

// Code runs a snippet in the session container (the `code_exec` tool). python3
// is the default; see langCommand for the supported set.
func (s *Session) Code(ctx context.Context, lang, code string) (string, error) {
	cmd, err := langCommand(lang, code)
	if err != nil {
		return "", err
	}
	return s.Exec(ctx, ExecRequest{Cmd: cmd, WorkDir: s.workspace})
}

// Exec runs one command and renders its result for the model. A non-zero exit
// is reported in the result text rather than as an error, so the model sees
// the output; transport failures are errors.
func (s *Session) Exec(ctx context.Context, req ExecRequest) (string, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return "", errors.New("containerlayer: session is closed")
	}
	if s.containerID == "" {
		s.mu.Unlock()
		return "", errors.New("containerlayer: session container is not running")
	}
	containerID := s.containerID
	s.mu.Unlock()

	res, err := s.rt.Exec(ctx, containerID, req)
	if err != nil {
		return "", err
	}
	return formatExecResult(res), nil
}

// formatExecResult renders an exec's output. A non-zero exit appends a status
// line so a failing command is visible in the transcript, not silently
// mistaken for success.
func formatExecResult(res ExecResult) string {
	out := res.Stdout
	if res.Stderr != "" {
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += res.Stderr
	}
	out = strings.TrimRight(out, "\n")
	if res.ExitCode != 0 {
		if out != "" {
			out += "\n"
		}
		out += fmt.Sprintf("[exit code %d]", res.ExitCode)
	}
	if out == "" {
		return "(no output)"
	}
	return out
}

// Close tears the session down in the order that leaves no residue: the
// container first (it holds the network), then the host-edge rules, then the
// fallback proxy, then the network. It is idempotent.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	containerID, networkID, firewall, proxy, spec := s.containerID, s.networkID, s.firewall, s.proxy, s.spec
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var errs []error
	if containerID != "" {
		if err := s.rt.RemoveContainer(ctx, containerID); err != nil {
			errs = append(errs, err)
		}
	}
	if firewall != nil {
		if err := firewall.Remove(ctx, spec); err != nil {
			errs = append(errs, err)
		}
	}
	if proxy != nil {
		if err := proxy.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if networkID != "" {
		if err := s.rt.RemoveNetwork(ctx, networkID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// prefixChecker returns a predicate over a normalized prefix set: an address
// is allowed when a pinned prefix contains it.
func prefixChecker(prefixes []netip.Prefix) func(netip.Addr) bool {
	norm := EgressSpec{Allowed: prefixes}.normalized().Allowed
	return func(addr netip.Addr) bool {
		addr = addr.Unmap()
		for _, p := range norm {
			if p.Addr().Is4() != addr.Is4() {
				continue
			}
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
}

// proxyListenAddr picks the fallback proxy's listen address: the operator's
// override, else the session gateway on an ephemeral port.
func proxyListenAddr(override, gateway string) string {
	if strings.TrimSpace(override) != "" {
		return override
	}
	return netip.MustParseAddr(gateway).String() + ":0"
}

// langCommand maps a `code_exec` language onto the in-container command that
// runs the snippet. python3 is first and the default (§5.1).
func langCommand(lang, code string) ([]string, error) {
	if strings.TrimSpace(code) == "" {
		return nil, errors.New("code is required")
	}
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "", "python", "python3":
		return []string{"python3", "-c", code}, nil
	case "sh", "bash", "shell":
		return []string{"sh", "-c", code}, nil
	case "node", "nodejs", "javascript", "js":
		return []string{"node", "-e", code}, nil
	case "ruby":
		return []string{"ruby", "-e", code}, nil
	case "perl":
		return []string{"perl", "-e", code}, nil
	case "go", "golang":
		// Go needs a file; base64 keeps the snippet free of shell quoting
		// hazards.
		encoded := base64.StdEncoding.EncodeToString([]byte(code))
		script := fmt.Sprintf(`d=$(mktemp -d) && printf %%s %s | base64 -d > "$d/main.go" && cd "$d" && go run .`, encoded)
		return []string{"sh", "-c", script}, nil
	default:
		return nil, fmt.Errorf("code_exec: unsupported lang %q (supported: python3, sh, node, ruby, perl, go)", lang)
	}
}
