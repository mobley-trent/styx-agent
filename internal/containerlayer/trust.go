package containerlayer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// CA trust and egress forcing (docs/browser-and-proxy.md §4.2, §4.4).
//
// The engagement's interception proxy is worthless if the container cannot
// validate the leaves it presents: a tool that fails TLS either stops working
// or, worse, is run with verification off. So the CA is bound into the
// container read-only and installed into the trust bundle at session start,
// and an install the harness cannot confirm refuses the session.

const (
	// ContainerCAPath is where the engagement's CA is mounted, read-only. It
	// is the path `update-ca-certificates` reads local anchors from.
	ContainerCAPath = "/usr/local/share/ca-certificates/styx-engagement.crt"

	// caInstallScript installs the mounted anchor and confirms it landed:
	// the bundle update must succeed, and the CA's own hashed link must exist
	// afterwards. Two checks in one shell so a partial install is one
	// decision, and a distro that ignores the anchor refuses the session
	// rather than silently trusting nothing.
	caInstallScript = `update-ca-certificates && test -e "/etc/ssl/certs/$(openssl x509 -in ` + ContainerCAPath + ` -noout -hash).0"`
)

// errInterceptionWithoutCapture is returned when interception is configured
// but the session has no capture to write: a MITM that records nothing is not
// a shape this layer runs.
var errInterceptionWithoutCapture = errors.New("containerlayer: interception needs a capture")

// InterceptionOptions is the engagement half of a session's egress (§4.2,
// §4.4): the CA the container trusts and the proxy presents, and the capture
// every exchange lands in. Nil on a session keeps the safe-mode shape — a
// plain tunnel with no capture.
type InterceptionOptions struct {
	// CA signs the leaves the proxy presents and is the certificate the
	// container trusts. Required.
	CA *CA
	// CaptureDir is the session's capture directory,
	// .styx/out/captures/<session>. Required; the session owns its lifetime
	// and flushes it on teardown.
	CaptureDir string
	// UpstreamTLS overrides how the proxy validates destinations. Nil uses the
	// host's roots; tests pin a pool.
	UpstreamTLS *tls.Config
	// Now stamps capture records; nil means time.Now.
	Now func() time.Time
}

// caBind is the read-only mount of the engagement CA. Only the certificate is
// mounted: the key never leaves its directory (§4.4).
func caBind(certPath string) string { return certPath + ":" + ContainerCAPath + ":ro" }

// proxyEnvironment is the container's proxy configuration (§4.2): the
// convention every scanner and CLI honors, in the upper and lower case spellings
// tools actually read. It is the routing, not the enforcement — the firewall is
// what makes it unavoidable while capture is on.
func proxyEnvironment(proxyURL string) []string {
	return []string{
		"HTTP_PROXY=" + proxyURL,
		"HTTPS_PROXY=" + proxyURL,
		"http_proxy=" + proxyURL,
		"https_proxy=" + proxyURL,
	}
}

// captureOnlyAllowlist is what the session firewall permits while capture is
// on: the proxy's own listener and nothing else, so a tool that ignores the
// proxy environment is denied at the edge instead of passing uncaptured
// (§4.2). Where the firewall cannot be programmed, degraded isolation already
// leaves the internal network with the proxy as its only path (spec §5.2).
func captureOnlyAllowlist(proxyURL string) ([]netip.Prefix, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("containerlayer: parse egress proxy URL %q: %w", proxyURL, err)
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("containerlayer: the session firewall needs the proxy's listener address, got %q: %w", proxyURL, err)
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return nil, fmt.Errorf("containerlayer: the session firewall needs a concrete proxy listener, got %q", proxyURL)
	}
	return []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}, nil
}

// trustCA installs the mounted CA into the container's trust bundle and
// confirms it, refusing the session when the harness cannot vouch for the
// result (§4.4, §8). It is a no-op in safe mode.
func (s *Session) trustCA(ctx context.Context, opts SessionOptions) error {
	if opts.Interception == nil {
		return nil
	}
	ca := opts.Interception.CA
	res, err := s.rt.Exec(ctx, s.containerID, ExecRequest{Cmd: []string{"sh", "-c", caInstallScript}})
	if err != nil {
		return s.caFailure(ca, ExecResult{}, err)
	}
	if res.ExitCode != 0 {
		return s.caFailure(ca, res, nil)
	}
	return s.record(ProxyEvent{Kind: EventCAInstalled, Listener: ContainerCAPath, Detail: ca.CertPath()})
}

// caFailure is the refusal: it names the mount and the install step, records
// the attempted install as a decision, and returns the error the session start
// fails with.
func (s *Session) caFailure(ca *CA, res ExecResult, cause error) error {
	failure := fmt.Sprintf("exit %d", res.ExitCode)
	output := strings.TrimSpace(res.Stdout)
	if stderr := strings.TrimSpace(res.Stderr); stderr != "" {
		if output != "" {
			output += "\n"
		}
		output += stderr
	}
	if cause != nil {
		failure = cause.Error()
		output = ""
	}
	err := fmt.Errorf(
		"containerlayer: installing the engagement CA failed: the certificate %s, mounted read-only at %s, was not confirmed by `update-ca-certificates` (%s)%s; refusing the session rather than running with TLS that fails or silently skips verification",
		ca.CertPath(), ContainerCAPath, failure, outputSuffix(output))
	_ = s.record(ProxyEvent{Kind: EventCAInstalled, Listener: ContainerCAPath, Reason: "failed", Detail: err.Error()})
	return err
}

// outputSuffix renders captured install output for the refusal message.
func outputSuffix(output string) string {
	if output == "" {
		return ""
	}
	return ": " + output
}

// record appends one proxy decision to the session's audit trail. A failed
// write fails the decision it belongs to, like every other audit write (§9).
func (s *Session) record(ev ProxyEvent) error {
	if s.auditor == nil {
		return nil
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	return s.auditor.RecordProxyEvent(ev)
}
