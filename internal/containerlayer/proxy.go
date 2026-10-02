package containerlayer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// ErrNotAllowed is the proxy's refusal: the requested destination did not
// resolve into the pinned scope (including a DNS-rebinding attempt, where the
// name resolves to an address outside the pins).
var ErrNotAllowed = errors.New("containerlayer: destination is outside the pinned egress scope")

// EgressProxy is the degraded-isolation egress path (§5.2): the session
// container has no external network, and this proxy — running on the host, on
// the session bridge's gateway — is its only way out. It resolves every
// destination itself and forwards only to pinned addresses.
//
// It forwards to the *resolved, verified* address, not to the hostname, so a
// rebind between the check and the dial cannot redirect traffic; and it
// re-verifies on every request, so a name that later resolves outside the
// pins is rejected then.
type EgressProxy struct {
	check   func(netip.Addr) bool
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	dial    func(ctx context.Context, network, address string) (net.Conn, error)

	mu         sync.Mutex
	listener   net.Listener
	server     *http.Server
	url        string
	listenAddr string
	transport  *http.Transport
}

// EgressProxyOptions configures one proxy. Check is required; the resolver and
// dialer default to the host's, and tests replace them.
type EgressProxyOptions struct {
	// Addr is the host address to listen on, e.g. "172.30.0.1:0".
	Addr string
	// Check reports whether a resolved address is in the pinned scope.
	Check func(netip.Addr) bool
	// Resolve resolves a destination hostname. Nil uses the host resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Dial connects to a verified address. Nil uses net.Dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewEgressProxy builds a proxy. It does not listen until Start.
func NewEgressProxy(opts EgressProxyOptions) (*EgressProxy, error) {
	if opts.Check == nil {
		return nil, errors.New("containerlayer: egress proxy needs a scope check")
	}
	p := &EgressProxy{
		check:   opts.Check,
		resolve: opts.Resolve,
		dial:    opts.Dial,
	}
	if p.resolve == nil {
		p.resolve = defaultResolve
	}
	if p.dial == nil {
		var d net.Dialer
		p.dial = d.DialContext
	}
	p.listenAddr = opts.Addr
	p.transport = &http.Transport{
		// The harness is authoritative: never consult environment proxies.
		Proxy: nil,
		// No connection reuse: every request must re-resolve and re-verify,
		// or a rebind could ride a pooled connection.
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return p.dialVerified(ctx, network, address)
		},
	}
	return p, nil
}

// defaultResolve resolves a host to addresses with the host resolver.
func defaultResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// Start begins listening and serving in the background.
func (p *EgressProxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener != nil {
		return nil
	}
	ln, err := net.Listen("tcp", p.listenAddress())
	if err != nil {
		return fmt.Errorf("containerlayer: start egress proxy: %w", err)
	}
	p.listener = ln
	p.url = "http://" + ln.Addr().String()
	server := &http.Server{Handler: p, ReadHeaderTimeout: defaultProxyTimeout}
	p.server = server
	go func() {
		// Serve returns when Close is called; the error is not actionable
		// from here. Capture server locally: Close nils p.server, and reading
		// the field here would race it.
		_ = server.Serve(ln)
	}()
	return nil
}

// SetListenAddr sets the address Start will listen on. It must be called
// before Start.
func (p *EgressProxy) SetListenAddr(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listenAddr = addr
}

// listenAddress is the address Start listens on: the configured one, else an
// ephemeral loopback port.
func (p *EgressProxy) listenAddress() string {
	if p.listenAddr == "" {
		return "127.0.0.1:0"
	}
	return p.listenAddr
}

// URL is the proxy's reachable base URL, empty before Start.
func (p *EgressProxy) URL() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.url
}

// Close stops the proxy. It is idempotent.
func (p *EgressProxy) Close() error {
	p.mu.Lock()
	server, ln := p.server, p.listener
	p.server, p.listener = nil, nil
	p.mu.Unlock()
	if server == nil {
		return nil
	}
	_ = ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), defaultProxyTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("containerlayer: stop egress proxy: %w", err)
	}
	return nil
}

// ServeHTTP handles one proxy request: CONNECT tunnels and absolute-URI HTTP
// forwards, both through dialVerified.
func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleForward(w, r)
}

// handleConnect opens a tunnel to a verified destination.
func (p *EgressProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target, err := p.dialVerified(r.Context(), "tcp", r.Host)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	defer func() { _ = target.Close() }()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxying not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	tunnel(client, target)
}

// handleForward forwards an absolute-URI request. The transport's dialer
// verifies the destination, so a disallowed target never connects.
func (p *EgressProxy) handleForward(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Header = r.Header.Clone()
	removeHopHeaders(outReq.Header)
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	removeHopHeaders(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// dialVerified resolves address, checks every candidate against the pinned
// scope, and dials the first allowed one. An address literal is checked
// directly. Nothing outside the pins is ever dialed.
func (p *EgressProxy) dialVerified(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("containerlayer: proxy target %q: %w", address, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !p.allowed(ip) {
			return nil, fmt.Errorf("%w: %s", ErrNotAllowed, ip)
		}
		return p.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
	}

	addrs, err := p.resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("containerlayer: proxy resolve %q: %w", host, err)
	}
	var last error
	for _, addr := range addrs {
		if !p.allowed(addr) {
			last = fmt.Errorf("%w: %s resolves to %s", ErrNotAllowed, host, addr)
			continue
		}
		conn, err := p.dial(ctx, network, net.JoinHostPort(addr.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("containerlayer: proxy resolve %q: no addresses", host)
	}
	return nil, last
}

// allowed reports whether an address is in the pinned scope. IPv4-mapped IPv6
// is unmapped first, so `::ffff:10.0.0.1` cannot slip past a v4 pin.
func (p *EgressProxy) allowed(addr netip.Addr) bool {
	return p.check(addr.Unmap())
}

// writeProxyError maps a dial failure onto a status: scope refusals are 403,
// everything else 502.
func writeProxyError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	if errors.Is(err, ErrNotAllowed) {
		status = http.StatusForbidden
	}
	http.Error(w, err.Error(), status)
}

// tunnel copies bytes both ways until either side closes.
func tunnel(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	wg.Wait()
}

// closeWrite half-closes a connection when the underlying type supports it.
func closeWrite(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// removeHopHeaders strips hop-by-hop headers from a proxied message
// (RFC 7230 §6.1).
func removeHopHeaders(h http.Header) {
	for _, k := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(k)
	}
}

const defaultProxyTimeout = 30 * time.Second
