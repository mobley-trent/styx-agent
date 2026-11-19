package engagement

import (
	"net/netip"
	"slices"
)

// Target is one destination a changed declaration made usable: the host the
// document declared and the addresses it resolved to when it declared it.
type Target struct {
	// Host is the declared server's hostname or IP literal.
	Host string
	// Addrs are the addresses the declaration resolved to.
	Addrs []netip.Addr
}

// Narrow returns the engagement narrowed to the destinations a diff declared
// (docs/api-spec-targets.md §5.3, docs/headless-ci.md §11.2): the intersection
// of the declared targets with the engagement's own pool. A target the pool
// does not authorize contributes nothing, and a pool entry no target names is
// dropped — the result can only ever be smaller than the pool, never larger,
// and never contains a destination the file did not authorize.
//
// A declared name stays a name, whatever pool entry authorized it: whether the
// pool names it, covers it with a wildcard, or merely contains the addresses it
// resolved to, the narrowed pool keeps the name with exactly those addresses as
// its pins. That is what lets the session's authoritative resolver answer a
// request by name at all — a narrowed pool of bare addresses would leave the
// container unable to resolve the declared host — and it authorizes nothing
// new, because every pin is an address the pool already contained and no other
// address joins it. A name whose addresses are not all authorized is refused
// whole, exactly as the loader refuses it (answer-binding).
//
// The caller decides what an empty result means: a diff scope treats it as the
// successful no-op, never as a run with full scope.
func (e *Engagement) Narrow(targets []Target) *Engagement {
	if e == nil {
		return nil
	}
	entries, declared := e.scope.narrow(targets)
	out := *e
	out.scope = &Scope{entries: entries}
	out.targets = declared
	return &out
}

// Empty reports whether the pool authorizes nothing at all. A narrowed
// engagement can be empty; an engagement file cannot, because the gate refuses
// one with no targets.
func (s *Scope) Empty() bool { return s == nil || len(s.entries) == 0 }

// narrow intersects the declared targets with the pool's entries, returning the
// kept entries and the effective target list the audit and the prompt report.
func (s *Scope) narrow(targets []Target) ([]entry, []string) {
	var entries []entry
	var declared []string
	seenEntry := map[string]bool{}
	seenTarget := map[string]bool{}

	addEntry := func(key string, e entry) {
		if seenEntry[key] {
			return
		}
		seenEntry[key] = true
		entries = append(entries, e)
	}
	addTarget := func(name string) {
		if seenTarget[name] {
			return
		}
		seenTarget[name] = true
		declared = append(declared, name)
	}

	for _, target := range targets {
		host := normalizeName(target.Host)
		if host == "" {
			continue
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			ip = ip.Unmap()
			if !s.contains(ip) {
				continue
			}
			addEntry("ip:"+ip.String(), entry{raw: ip.String(), kind: entryIP, ip: ip})
			addTarget(ip.String())
			continue
		}
		pins := pinnedAddrs(target.Addrs)
		if len(pins) == 0 || !s.authorizesAll(pins) {
			continue
		}
		// Keep the name, with the addresses the declaration resolved to, so the
		// session resolver answers it and the egress pins stay the declared
		// ones. The name itself joins nothing: these are pool addresses.
		addEntry("name:"+host, entry{raw: host, kind: entryHost, name: host, pins: pins})
		addTarget(host)
	}
	return entries, declared
}

// pinnedAddrs renders a declaration's addresses as a stable pin set.
func pinnedAddrs(addrs []netip.Addr) []netip.Addr {
	pins := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		pins = append(pins, addr.Unmap())
	}
	sortAddrs(pins)
	return slices.Compact(pins)
}

// authorizesAll reports whether the pool contains every address, which is the
// declaration's prerequisite: a name resolving partly outside the pool is
// refused whole, never narrowed to the in-scope half (§3.1).
func (s *Scope) authorizesAll(addrs []netip.Addr) bool {
	for _, addr := range addrs {
		if !s.contains(addr) {
			return false
		}
	}
	return true
}
