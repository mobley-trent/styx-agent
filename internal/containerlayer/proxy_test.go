package containerlayer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
)

// pinnedListener starts a loopback listener that accepts one connection, so a
// dial to it proves the proxy forwarded to a pinned address.
func pinnedListener(t *testing.T) (host string, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	h, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return h, p
}

func testProxy(t *testing.T, check func(netip.Addr) bool) *EgressProxy {
	t.Helper()
	p, err := NewEgressProxy(EgressProxyOptions{Addr: "127.0.0.1:0", Check: check})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProxyDialForwardsOnlyToPinnedIPs(t *testing.T) {
	host, port := pinnedListener(t)
	p := testProxy(t, allowChecker("127.0.0.1"))
	ctx := context.Background()

	conn, err := p.dialVerified(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("dialVerified(pinned) = %v, want a connection", err)
	}
	_ = conn.Close()

	// A different address in the same /8 must be refused: the allowlist is
	// addresses, not a network the dialer could wander into.
	if _, err := p.dialVerified(ctx, "tcp", "127.0.0.2:"+port); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("dialVerified(unpinned 127.0.0.2) = %v, want ErrNotAllowed", err)
	}
}

func TestProxyRejectsRebind(t *testing.T) {
	host, port := pinnedListener(t)
	calls := 0
	p := testProxy(t, allowChecker("127.0.0.1"))
	p.resolve = func(context.Context, string) ([]netip.Addr, error) {
		calls++
		if calls == 1 {
			return []netip.Addr{netip.MustParseAddr(host)}, nil
		}
		// The name now resolves somewhere else: the classic rebind.
		return []netip.Addr{netip.MustParseAddr("10.9.9.9")}, nil
	}
	ctx := context.Background()

	if _, err := p.dialVerified(ctx, "tcp", "rebind.test:"+port); err != nil {
		t.Fatalf("dialVerified(first resolve) = %v, want a connection", err)
	}
	if _, err := p.dialVerified(ctx, "tcp", "rebind.test:"+port); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("dialVerified(rebound) = %v, want ErrNotAllowed", err)
	}
}

func TestProxyRejectsUnpinnedHostname(t *testing.T) {
	p := testProxy(t, allowChecker("10.0.0.0/8"))
	p.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, err := p.dialVerified(context.Background(), "tcp", "evil.example:443"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("dialVerified(unpinned host) = %v, want ErrNotAllowed", err)
	}
}

func TestProxyHTTPForwardOnlyPinned(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "pinned payload")
	}))
	defer target.Close()

	proxy := testProxy(t, allowChecker("127.0.0.1"))
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	defer func() { _ = proxy.Close() }()

	client := proxyClient(t, proxy.URL())
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Get(pinned) = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "pinned payload" {
		t.Errorf("pinned response = %d %q, want 200 %q", resp.StatusCode, body, "pinned payload")
	}
}

func TestProxyHTTPForwardRefusesUnpinned(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secret")
	}))
	defer target.Close()

	proxy := testProxy(t, allowChecker("10.0.0.0/8"))
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	defer func() { _ = proxy.Close() }()

	resp, err := proxyClient(t, proxy.URL()).Get(target.URL)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unpinned response = %d, want 403", resp.StatusCode)
	}
}

// proxyClient builds a client that routes every request through proxyURL.
func proxyClient(t *testing.T, proxyURL string) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
}
