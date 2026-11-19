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
// A declared name the pool authorizes by name keeps its name, so the session's
// authoritative resolver still answers it and the container's egress pins land
// on the declared addresses; a name authorized only by address narrows to those
// addresses. The caller decides what an empty result means: a diff scope treats
// it as the successful no-op, never as a run with full scope.
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
		if s.nameAuthorized(host) {
			pins := slices.Clone(target.Addrs)
			sortAddrs(pins)
			pins = slices.Compact(pins)
			addEntry("name:"+host, entry{raw: host, kind: entryHost, name: host, pins: pins})
			addTarget(host)
			continue
		}
		for _, addr := range target.Addrs {
			addr = addr.Unmap()
			if !s.contains(addr) {
				continue
			}
			addEntry("ip:"+addr.String(), entry{raw: addr.String(), kind: entryIP, ip: addr})
			addTarget(addr.String())
		}
	}
	return entries, declared
}

// nameAuthorized reports whether the pool authorizes a hostname by name: an
// exact hostname entry, or a wildcard covering it.
func (s *Scope) nameAuthorized(name string) bool {
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
