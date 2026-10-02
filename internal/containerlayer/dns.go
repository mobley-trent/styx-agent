package containerlayer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsTTL is the TTL the resolver stamps on its answers. Pins are fixed for the
// session's lifetime, so the value only keeps clients from re-querying
// constantly.
const dnsTTL = 60

// dnsReadTimeout bounds a TCP client's read.
const dnsReadTimeout = 5 * time.Second

// NamePin is one authorized hostname and the addresses it is pinned to. The
// harness resolver answers exactly these names and nothing else.
type NamePin struct {
	// Name is the hostname (or, for a wildcard, the base it covers).
	Name string
	// Wildcard is true when the entry was declared as `*.name`: any name
	// strictly below Name resolves to Addrs.
	Wildcard bool
	// Addrs are the pinned addresses.
	Addrs []netip.Addr
}

// DNSServer is the harness's authoritative resolver for the session container
// (§5.2). The container is told to use it, and it answers only the
// engagement's pinned names: a query for a pinned name returns exactly the
// addresses it resolved to at load, and any other name is NXDOMAIN. Because
// the harness never forwards the query, a rebind has nothing to lie about.
type DNSServer struct {
	addr string

	exact     map[string][]netip.Addr
	wildcards []NamePin

	mu     sync.Mutex
	udp    *net.UDPConn
	tcp    net.Listener
	closed bool
	wg     sync.WaitGroup
}

// DNSServerOptions configures a DNSServer.
type DNSServerOptions struct {
	// Addr is the listen address, "ip:port". A zero port binds an ephemeral
	// port (for tests).
	Addr string
	// Pins is the authorized name-to-address set.
	Pins []NamePin
}

// NewDNSServer builds a resolver. It does not listen until Start.
func NewDNSServer(opts DNSServerOptions) (*DNSServer, error) {
	if strings.TrimSpace(opts.Addr) == "" {
		return nil, errors.New("containerlayer: dns server needs a listen address")
	}
	s := &DNSServer{addr: opts.Addr, exact: make(map[string][]netip.Addr)}
	for _, pin := range opts.Pins {
		name := normalizeDNSName(pin.Name)
		if name == "" || len(pin.Addrs) == 0 {
			continue
		}
		addrs := dedupeAddrs(pin.Addrs)
		if len(addrs) == 0 {
			continue
		}
		if pin.Wildcard {
			s.wildcards = append(s.wildcards, NamePin{Name: name, Wildcard: true, Addrs: addrs})
			continue
		}
		s.exact[name] = addrs
	}
	return s, nil
}

// Start binds UDP and TCP and begins answering. Both transports bind the same
// port; a zero port in the configured address is resolved by the TCP listener
// and reused for UDP.
func (s *DNSServer) Start() error {
	tcp, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("containerlayer: dns listen tcp %s: %w", s.addr, err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		return fmt.Errorf("containerlayer: dns resolve %s: %w", tcp.Addr(), err)
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = tcp.Close()
		return fmt.Errorf("containerlayer: dns listen udp %s: %w", udpAddr, err)
	}

	s.mu.Lock()
	s.tcp, s.udp = tcp, udp
	s.mu.Unlock()

	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.serveUDP(udp) }()
	go func() { defer s.wg.Done(); s.serveTCP(tcp) }()
	return nil
}

// Addr is the bound address (host:port), empty before Start.
func (s *DNSServer) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcp == nil {
		return ""
	}
	return s.tcp.Addr().String()
}

// Lookup resolves a name against the pinned set. It reports false for any name
// the engagement did not authorize.
func (s *DNSServer) Lookup(name string) ([]netip.Addr, bool) {
	n := normalizeDNSName(name)
	if n == "" {
		return nil, false
	}
	if addrs, ok := s.exact[n]; ok {
		return append([]netip.Addr(nil), addrs...), true
	}
	for _, w := range s.wildcards {
		if matchWildcardName(w.Name, n) {
			return append([]netip.Addr(nil), w.Addrs...), true
		}
	}
	return nil, false
}

// Stop closes both listeners and is idempotent.
func (s *DNSServer) Stop() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	udp, tcp := s.udp, s.tcp
	s.mu.Unlock()

	var errs []error
	if udp != nil {
		if err := udp.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if tcp != nil {
		if err := tcp.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	s.wg.Wait()
	return errors.Join(errs...)
}

// serveUDP answers datagrams until the socket closes.
func (s *DNSServer) serveUDP(conn *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		resp := s.answer(query)
		if resp == nil {
			continue
		}
		_, _ = conn.WriteToUDP(resp, remote)
	}
}

// serveTCP answers length-prefixed requests until the listener closes.
func (s *DNSServer) serveTCP(ln net.Listener) {
	// Handled inline: DNS over TCP is rare and answering one query is quick,
	// and it keeps connection goroutines out of Stop's wait group.
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		s.handleTCP(conn)
		_ = conn.Close()
	}
}

// handleTCP reads one length-prefixed query and writes one answer.
func (s *DNSServer) handleTCP(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(dnsReadTimeout))
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	size := int(binary.BigEndian.Uint16(lenBuf[:]))
	if size == 0 || size > 65535 {
		return
	}
	query := make([]byte, size)
	if _, err := io.ReadFull(conn, query); err != nil {
		return
	}
	resp := s.answer(query)
	if resp == nil {
		return
	}
	out := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
	copy(out[2:], resp)
	_, _ = conn.Write(out)
}

// answer builds a response for one query, or nil when the input is not a
// single standard query we can answer.
func (s *DNSServer) answer(query []byte) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil
	}
	if hdr.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}

	addrs, ok := s.Lookup(q.Name.String())
	rcode := dnsmessage.RCodeSuccess
	if !ok {
		rcode = dnsmessage.RCodeNameError
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               hdr.ID,
		Response:         true,
		Authoritative:    true,
		RecursionDesired: hdr.RecursionDesired,
		RCode:            rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil
	}
	if err := b.Question(q); err != nil {
		return nil
	}
	if answers := filterAnswers(addrs, q.Type); len(answers) > 0 {
		if err := b.StartAnswers(); err != nil {
			return nil
		}
		rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: dnsTTL}
		for _, ip := range answers {
			rh.Type = q.Type
			switch q.Type {
			case dnsmessage.TypeA:
				if err := b.AResource(rh, dnsmessage.AResource{A: ip.As4()}); err != nil {
					return nil
				}
			case dnsmessage.TypeAAAA:
				if err := b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: ip.As16()}); err != nil {
					return nil
				}
			}
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// filterAnswers keeps the pinned addresses of the queried family.
func filterAnswers(addrs []netip.Addr, t dnsmessage.Type) []netip.Addr {
	var out []netip.Addr
	for _, ip := range addrs {
		switch t {
		case dnsmessage.TypeA:
			if ip.Is4() {
				out = append(out, ip)
			}
		case dnsmessage.TypeAAAA:
			if ip.Is6() && !ip.Is4In6() {
				out = append(out, ip)
			}
		}
	}
	return out
}

// normalizeDNSName lowercases a name, drops a trailing root dot, and trims
// surrounding whitespace.
func normalizeDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// matchWildcardName reports whether a normalized name is strictly below a
// normalized base — the same rule the engagement scope applies.
func matchWildcardName(base, name string) bool {
	if base == "" || name == base {
		return false
	}
	return strings.HasSuffix(name, "."+base)
}

// dedupeAddrs unmaps, deduplicates, and sorts a pin set.
func dedupeAddrs(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, ip := range addrs {
		out = append(out, ip.Unmap())
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}
