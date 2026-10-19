package parsers

import (
	"net/netip"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// index resolves the natural keys a parse will touch to the ids engagement
// state already holds for those records.
//
// A parse cannot know the id of a record it did not write itself: a model may
// have recorded the same service through `state_update`, or another parser may
// have found it first. Writing an op that references its own minted id would
// dangle, and the whole batch would be refused (§5's atomicity is what makes a
// dangling reference fatal rather than partial). The pre-parse read closes that
// gap: every reference the batch makes resolves to whatever id the record
// already has, and only a record no one has recorded yet is written under the
// parse's minted id.
//
// The index mirrors the store's natural keys (§3 of docs/engagement-state.md):
// a host by its address, a service by its host and port, a credential by type
// and principal and secret, a finding by title and affected refs, a segment by
// label. A host is keyed under every address it carries and its hostname, so a
// reference by any alias finds one record.
type index struct {
	// ids maps a natural key to the id the store holds for it.
	ids map[string]string
	// primary maps a host id to the address key it is keyed under: the first
	// address it was recorded with, which is its natural key.
	primary map[string]string
	// credentials, services, and hosts map an id to the ref naming it, so a
	// record referred to by another record's id can be keyed the same way the
	// parsers key it.
	credentials map[string]ref
	services    map[string]ref
}

// newIndex indexes a snapshot's records by natural key.
func newIndex(snap engagementstate.Snapshot) *index {
	ix := &index{
		ids:         map[string]string{},
		primary:     map[string]string{},
		credentials: map[string]ref{},
		services:    map[string]ref{},
	}

	// Hosts first: every other key is expressed through a host's address.
	for _, e := range snap.Entities {
		if e.Kind != engagementstate.KindHost || len(e.Addresses) == 0 {
			continue
		}
		ix.primary[e.ID] = normalizeKey(e.Addresses[0])
		for _, addr := range e.Addresses {
			ix.ids[hostRef(addr).key()] = e.ID
		}
		if e.Hostname != "" {
			ix.ids[hostRef(e.Hostname).key()] = e.ID
		}
	}
	// The host a reference names: its recorded primary address when the
	// snapshot holds it, else the reference itself (a host this parse is about
	// to write).
	hostKey := func(id string) string {
		if key, ok := ix.primary[id]; ok {
			return key
		}
		return normalizeKey(id)
	}

	for _, e := range snap.Entities {
		switch e.Kind {
		case engagementstate.KindSegment:
			ix.ids[segmentRef(e.Label).key()] = e.ID
		case engagementstate.KindService:
			r := serviceRef(hostKey(e.Host), e.Port, e.Proto)
			ix.ids[r.key()] = e.ID
			ix.services[e.ID] = r
		case engagementstate.KindCredential:
			r := credentialRef(e.Type, e.Principal, e.Secret)
			ix.ids[r.key()] = e.ID
			ix.credentials[e.ID] = r
		}
	}

	for _, e := range snap.Entities {
		if e.Kind != engagementstate.KindAccess {
			continue
		}
		r := accessRef(ix.principalRef(e.Principal), ix.targetRef(e.Target, hostKey))
		ix.ids[r.key()] = e.ID
	}

	for _, f := range snap.Findings {
		affected := make([]ref, 0, len(f.Affected))
		for _, a := range f.Affected {
			affected = append(affected, ix.targetRef(a, hostKey))
		}
		ix.ids[findingRef(f.Title, affected...).key()] = f.ID
	}
	return ix
}

// principalRef names an access principal: a credential by its natural key, or a
// bare account name.
func (ix *index) principalRef(principal string) ref {
	if r, ok := ix.credentials[principal]; ok {
		return r
	}
	return ref{kind: refAccount, value: principal}
}

// targetRef names an access or finding target: a host by its address, a service
// by its host and port.
func (ix *index) targetRef(id string, hostKey func(string) string) ref {
	if r, ok := ix.services[id]; ok {
		return r
	}
	return hostRef(hostKey(id))
}

// recorded returns the id the store already holds for a ref.
func (ix *index) recorded(r ref) (string, bool) {
	id, ok := ix.ids[r.key()]
	return id, ok
}

// id is the id a parse writes a ref's record under: the one the store already
// holds, or the parse's minted one.
func (ix *index) id(r ref) string {
	if id, ok := ix.recorded(r); ok {
		return id
	}
	return mintedID(r)
}

// ref renders a ref as the store-facing reference an op carries. A host is
// named by its recorded id, or by its address when the store does not hold it
// yet — the store resolves an address to the host that records it, including
// one this batch writes. Every other kind must be named by id: the store has no
// other way to resolve a service, credential, access, finding, or segment.
func (ix *index) ref(r ref) string {
	switch r.kind {
	case refAccount:
		return r.value
	case refHost:
		if id, ok := ix.recorded(r); ok {
			return id
		}
		return r.value
	default:
		return ix.id(r)
	}
}

// normalizeKey canonicalizes a reference for keying: an IP literal in its
// unmapped form, or a lowercased name without a trailing root dot. It matches
// how engagementstate compares addresses, so a key built here and one built
// from a stored record agree.
func normalizeKey(raw string) string {
	s := strings.TrimSpace(raw)
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}
