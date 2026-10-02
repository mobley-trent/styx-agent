// Package netfetch implements the harness-side network fetchers behind the
// scope-checked tools: web_fetch (an HTTP GET) and ssh_logs (a read-only
// remote command over the operator's SSH client).
//
// Boundary rule: netfetch is the harness-side counterpart to containerlayer's
// container edge. It never executes model output as a shell and never widens
// scope — every destination it resolves must land inside the pinned engagement
// scope before a connection or command is attempted. containerlayer remains
// the only package that programs host networking (Docker networks, nftables,
// the fallback proxy); this package only performs ordinary outbound requests.
package netfetch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// Defaults for a fetch.
const (
	// DefaultTimeout bounds one fetch or remote command.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxBytes caps a fetched body (1 MiB).
	DefaultMaxBytes = 1 << 20
)

// Scope reports whether a concrete destination is authorized by the active
// engagement. It is the same "in scope" predicate the policy engine uses, so
// the fetcher and the engine cannot disagree.
type Scope interface {
	// InScope reports whether an IP literal or hostname is in scope.
	InScope(addr string) bool
}

// Resolver resolves a hostname to addresses. It is the DNS seam: production
// uses the host resolver, tests pin a deterministic table.
type Resolver interface {
	// LookupHost returns the addresses a hostname resolves to.
	LookupHost(ctx context.Context, host string) ([]netip.Addr, error)
}

// CommandRunner runs a subprocess. It is the SSH transport seam.
type CommandRunner interface {
	// Run executes a command and returns its combined output.
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// Options configures a Fetcher.
type Options struct {
	// Scope is the pinned engagement scope. Nil means no engagement is
	// active: no destination check is applied (the policy prompt, not the
	// fetcher, is what guards a safe-mode fetch).
	Scope Scope
	// Resolver is the DNS seam; nil means the host resolver.
	Resolver Resolver
	// Runner is the subprocess seam; nil means os/exec.
	Runner CommandRunner
	// Timeout bounds one fetch; zero means DefaultTimeout.
	Timeout time.Duration
	// MaxBytes caps a fetched body; zero means DefaultMaxBytes.
	MaxBytes int64
}

// Fetcher implements agent.Fetcher and agent.LogFetcher. It is immutable after
// construction and safe for concurrent use.
type Fetcher struct {
	opts Options
}

// New builds a fetcher.
func New(opts Options) *Fetcher {
	if opts.Resolver == nil {
		opts.Resolver = DefaultResolver{}
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	return &Fetcher{opts: opts}
}

// DefaultResolver resolves through the host resolver.
type DefaultResolver struct{}

// LookupHost resolves a name to addresses via the host resolver.
func (DefaultResolver) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct{}

// Run executes a command and returns its combined output. A non-zero exit is
// reported as an error with the output attached, so the harness never mistakes
// a failed read for an empty one.
//
//nolint:gosec // the command name and arguments are harness-constructed, never model output.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", name, err)
	}
	return string(out), nil
}

// Fetch retrieves an http(s) URL. In engagement mode the destination is
// re-resolved and every address must be in scope; the connection is then made
// to the verified address, so a name that rebinds between resolution and
// connect cannot smuggle traffic out of scope (§7.2). Redirects are refused
// for the same reason.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("web_fetch: invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("web_fetch: unsupported scheme %q (want http or https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("web_fetch: URL has no host")
	}

	var pinned netip.Addr
	if f.opts.Scope != nil {
		pinned, err = f.authorized(ctx, host)
		if err != nil {
			return "", fmt.Errorf("web_fetch: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("web_fetch: build request: %w", err)
	}
	client := f.client(host, pinned, u.Scheme)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("web_fetch: %s: %w", host, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.opts.MaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("web_fetch: read %s: %w", host, err)
	}
	truncated := int64(len(body)) > f.opts.MaxBytes
	if truncated {
		body = body[:f.opts.MaxBytes]
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[HTTP %s] %s\n\n", resp.Status, u.Redacted())
	if truncated {
		fmt.Fprintf(&b, "[web_fetch: body truncated at %d bytes]\n", f.opts.MaxBytes)
	}
	b.Write(body)
	return b.String(), nil
}

// client builds the HTTP client for one fetch. A pinned address forces the
// dial to that address while keeping the original host for the Host header and
// TLS SNI; redirected requests are refused.
func (f *Fetcher) client(host string, pinned netip.Addr, scheme string) *http.Client {
	tr := &http.Transport{ForceAttemptHTTP2: false}
	if pinned.IsValid() {
		dialer := &net.Dialer{Timeout: f.opts.Timeout}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = defaultPort(scheme)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(pinned.String(), port))
		}
		//nolint:gosec // ServerName is the already-verified destination host.
		tr.TLSClientConfig = &tls.Config{ServerName: host}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   f.opts.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("refusing to follow a redirect (it could leave the engagement scope)")
		},
	}
}

// Logs runs a read-only command on a remote host. The command is already
// validated against the allowlist by the ssh_logs tool; this method
// re-verifies scope and runs the operator's ssh client.
func (f *Fetcher) Logs(ctx context.Context, target string, command []string) (string, error) {
	if len(command) == 0 {
		return "", errors.New("ssh_logs: empty command")
	}
	host := targetHost(target)
	if host == "" {
		return "", errors.New("ssh_logs: target host is required")
	}
	if f.opts.Scope != nil {
		if _, err := f.authorized(ctx, host); err != nil {
			return "", fmt.Errorf("ssh_logs: %w", err)
		}
	}

	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		// accept-new pins the host key on first sight rather than failing an
		// unattended run; the operator's known_hosts still governs later use.
		"-o", "StrictHostKeyChecking=accept-new",
		target,
	}
	args = append(args, command...)

	runCtx, cancel := context.WithTimeout(ctx, f.opts.Timeout)
	defer cancel()
	out, err := f.opts.Runner.Run(runCtx, "ssh", args...)
	if err != nil {
		return "", fmt.Errorf("ssh_logs: %s: %w", target, err)
	}
	return out, nil
}

// authorized resolves a hostname and returns one pinned in-scope address. It
// refuses when the name does not resolve or any resolved address is out of
// scope — a mixed answer is not partially trusted.
func (f *Fetcher) authorized(ctx context.Context, host string) (netip.Addr, error) {
	addrs, err := f.opts.Resolver.LookupHost(ctx, host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("cannot resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("%s resolves to no addresses", host)
	}
	for _, a := range addrs {
		if !f.opts.Scope.InScope(a.Unmap().String()) {
			return netip.Addr{}, fmt.Errorf("%s resolves to %s, outside the engagement scope", host, a)
		}
	}
	return addrs[0].Unmap(), nil
}

// targetHost strips an SSH user and port from a target, tolerating bracketed
// IPv6 forms.
func targetHost(raw string) string {
	s := strings.TrimSpace(raw)
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 0 {
			return s[1:end]
		}
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

// defaultPort is the port for a scheme when a dial address carries none.
func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}
