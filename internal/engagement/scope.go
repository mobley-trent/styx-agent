package engagement

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/policy"
)

// Scope is the engagement file's authorization pool after load: IP literals,
// CIDRs, and hostnames (or wildcard domains) pinned to the addresses they
// resolved to at load (§7.1, §7.2). It is immutable and safe for concurrent
// use, and it is the concrete implementation the policy engine consumes
// through its Scope interface — one definition of "in scope" for the whole
// harness.
type Scope struct {
	entries []entry
}

// Scope is what the policy engine's Scope seam expects (§6.2).
var _ policy.Scope = (*Scope)(nil)

// entryKind is how a pool entry was declared.
type entryKind int

const (
	// entryIP is an IP literal (10.0.0.1).
	entryIP entryKind = iota
	// entryCIDR is a CIDR block (10.0.0.0/24).
	entryCIDR
	// entryHost is a hostname pinned to its load-time addresses.
	entryHost
	// entryWildcard is a `*.example.com` pattern pinned to the expansion
	// set the wildcard name resolved to at load.
	entryWildcard
)

// entry is one authorization-pool entry.
type entry struct {
	raw  string       // exactly as declared, for diagnostics
	kind entryKind    //
	ip   netip.Addr   // entryIP
	cidr netip.Prefix // entryCIDR
	name string       // entryHost / entryWildcard: normalized hostname
	pins []netip.Addr // entryHost / entryWildcard: load-time DNS pins
}

// needsResolve reports whether the entry must be pinned through the resolver.
func (e entry) needsResolve() bool {
	return e.kind == entryHost || e.kind == entryWildcard
}

// InScope reports whether a concrete destination is authorized by the pool
// (§7.1: "in scope iff the target matches any pool entry — IP literal,
// containing CIDR, or pinned hostname/IP").
//
// dest is what a network call actually intends to touch: an IP literal, a
// hostname, or either with a port ("10.0.0.1:443", "[2001:db8::1]:443"). The
// port never affects membership. An IP destination matches the literal and
// CIDR entries and the pin set of every hostname/wildcard entry — that is the
// DNS-rebinding check, since the caller re-resolves before asking (§7.2). A
// hostname destination matches a declared hostname exactly or a wildcard
// pattern; `*.example.com` matches names below example.com, never the bare
// domain.
func (s *Scope) InScope(dest string) bool {
	host := stripPort(dest)
	if host == "" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return s.contains(ip.Unmap())
	}

	name := normalizeName(host)
	if name == "" {
		return false
	}
	for _, e := range s.entries {
		switch e.kind {
		case entryHost:
			if e.name == name {
				return true
			}
		case entryWildcard:
			if matchWildcard(e.name, name) {
				return true
			}
		}
	}
	return false
}

// contains reports whether an IP belongs to the pool: an equal literal, an
// enclosing CIDR, or a hostname/wildcard entry's pinned addresses.
func (s *Scope) contains(ip netip.Addr) bool {
	for _, e := range s.entries {
		switch e.kind {
		case entryIP:
			if e.ip == ip {
				return true
			}
		case entryCIDR:
			if e.cidr.Contains(ip) {
				return true
			}
		case entryHost, entryWildcard:
			if slices.Contains(e.pins, ip) {
				return true
			}
		}
	}
	return false
}

// HostPins is one hostname authorization with the addresses it was pinned to
// at load. It is the name-to-address mapping the harness's authoritative
// resolver answers from (§5.2): a query for the name returns exactly these
// addresses, and a name absent from this set does not resolve at all.
type HostPins struct {
	// Name is the normalized hostname; for a wildcard entry it is the base
	// the pattern covers (excluding the leading `*.`).
	Name string
	// Wildcard is true when the entry was declared as `*.name`: any name
	// strictly below it resolves to Addrs.
	Wildcard bool
	// Addrs are the addresses the name resolved to once, at load.
	Addrs []netip.Addr
}

// HostPins returns the pool's hostname and wildcard entries with their
// load-time pins, in declaration order. IP and CIDR entries carry no name and
// are not included.
func (s *Scope) HostPins() []HostPins {
	var out []HostPins
	for _, e := range s.entries {
		switch e.kind {
		case entryHost:
			out = append(out, HostPins{Name: e.name, Addrs: append([]netip.Addr(nil), e.pins...)})
		case entryWildcard:
			out = append(out, HostPins{
				Name:     strings.TrimPrefix(e.name, "*."),
				Wildcard: true,
				Addrs:    append([]netip.Addr(nil), e.pins...),
			})
		}
	}
	return out
}

// Pins returns every concrete IP the pool authorizes — literals plus the
// load-time expansions of hostnames and wildcards — deduplicated and sorted.
// The container egress layer programs from this set (§5.2).
func (s *Scope) Pins() []netip.Addr {
	var pins []netip.Addr
	for _, e := range s.entries {
		switch e.kind {
		case entryIP:
			pins = append(pins, e.ip)
		case entryHost, entryWildcard:
			pins = append(pins, e.pins...)
		}
	}
	sortAddrs(pins)
	return slices.Compact(pins)
}

// Prefixes returns the pool's CIDR blocks, in declaration order. Together
// with Pins it is the complete authorization pool the egress layer programs.
func (s *Scope) Prefixes() []netip.Prefix {
	var prefixes []netip.Prefix
	for _, e := range s.entries {
		if e.kind == entryCIDR {
			prefixes = append(prefixes, e.cidr)
		}
	}
	return prefixes
}

// stripPort removes a port from a destination, tolerating bare IP literals
// and bracketed IPv6 forms ("[2001:db8::1]" and "[2001:db8::1]:443").
func stripPort(dest string) string {
	d := strings.TrimSpace(dest)
	if host, _, err := net.SplitHostPort(d); err == nil {
		return host
	}
	if inner, ok := strings.CutPrefix(d, "["); ok {
		if inner, ok := strings.CutSuffix(inner, "]"); ok {
			return inner
		}
	}
	return d
}

// normalizeName lowercases a hostname and drops a trailing root dot, so
// `App.ACME.Example.` and `app.acme.example` are one name.
func normalizeName(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// matchWildcard reports whether a normalized name is covered by a normalized
// `*.base` pattern: any name strictly below base. The bare base is not
// covered — `*.acme.example` authorizes subdomains, not the zone apex.
func matchWildcard(pattern, name string) bool {
	base, ok := strings.CutPrefix(pattern, "*.")
	if !ok || name == base {
		return false
	}
	return strings.HasSuffix(name, "."+base)
}

// sortAddrs sorts addresses into a canonical order (Load's pin sets are
// printed in tests and compared downstream).
func sortAddrs(addrs []netip.Addr) {
	slices.SortFunc(addrs, netip.Addr.Compare)
}
