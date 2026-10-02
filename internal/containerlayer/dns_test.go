package containerlayer

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func testDNSServer(t *testing.T) *DNSServer {
	t.Helper()
	server, err := NewDNSServer(DNSServerOptions{
		Addr: "127.0.0.1:0",
		Pins: []NamePin{
			{Name: "app.acme.example", Addrs: []netip.Addr{
				netip.MustParseAddr("192.0.2.44"),
				netip.MustParseAddr("2001:db8::44"),
			}},
			{Name: "acme.example", Wildcard: true, Addrs: []netip.Addr{
				netip.MustParseAddr("198.51.100.7"),
			}},
		},
	})
	if err != nil {
		t.Fatalf("NewDNSServer() = %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	t.Cleanup(func() { _ = server.Stop() })
	return server
}

// lookupName asks the running resolver, as a container would.
func lookupName(t *testing.T, serverAddr, name string) ([]net.IPAddr, error) {
	t.Helper()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, serverAddr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return r.LookupIPAddr(ctx, name)
}

func TestDNSLookupAnswersOnlyPinnedNames(t *testing.T) {
	server := testDNSServer(t)

	if addrs, ok := server.Lookup("app.acme.example"); !ok || len(addrs) != 2 {
		t.Errorf("Lookup(pinned) = %v/%v, want both pinned addresses", addrs, ok)
	}
	if addrs, ok := server.Lookup("APP.ACME.EXAMPLE."); !ok || len(addrs) != 2 {
		t.Errorf("Lookup(pinned, normalized) = %v/%v, want both pinned addresses", addrs, ok)
	}
	if addrs, ok := server.Lookup("db.acme.example"); !ok || len(addrs) != 1 || addrs[0].String() != "198.51.100.7" {
		t.Errorf("Lookup(wildcard) = %v/%v, want the wildcard pin", addrs, ok)
	}
	if addrs, ok := server.Lookup("acme.example"); ok {
		t.Errorf("Lookup(zone apex) = %v, want the wildcard not to cover the apex", addrs)
	}
	if addrs, ok := server.Lookup("evil.example"); ok {
		t.Errorf("Lookup(unpinned) = %v, want no answer", addrs)
	}
}

func TestDNSAnswersPinnedNamesOverTheWire(t *testing.T) {
	server := testDNSServer(t)
	addr := server.Addr()

	got, err := lookupName(t, addr, "app.acme.example")
	if err != nil {
		t.Fatalf("LookupIPAddr(pinned) = %v", err)
	}
	if !containsIP(got, "192.0.2.44") || !containsIP(got, "2001:db8::44") {
		t.Errorf("pinned answer = %v, want both the A and AAAA pins", got)
	}

	wild, err := lookupName(t, addr, "db.acme.example")
	if err != nil {
		t.Fatalf("LookupIPAddr(wildcard) = %v", err)
	}
	if !containsIP(wild, "198.51.100.7") {
		t.Errorf("wildcard answer = %v, want the wildcard pin", wild)
	}

	// Unpinned names must not resolve: the resolver is authoritative, so
	// there is nothing to rebind to.
	if _, err := lookupName(t, addr, "evil.example"); err == nil {
		t.Error("LookupIPAddr(unpinned) = nil error, want NXDOMAIN")
	} else if !strings.Contains(strings.ToLower(err.Error()), "no such host") {
		t.Errorf("unpinned error = %v, want a no-such-host failure", err)
	}
}

func TestDNSUnusableAddressIsRejected(t *testing.T) {
	if _, err := NewDNSServer(DNSServerOptions{Addr: "  "}); err == nil {
		t.Error("NewDNSServer(no address) = nil error, want a refusal")
	}
}

// containsIP reports whether a resolved address list contains ip.
func containsIP(addrs []net.IPAddr, ip string) bool {
	want := net.ParseIP(ip)
	for _, a := range addrs {
		if a.IP.Equal(want) {
			return true
		}
	}
	return false
}
