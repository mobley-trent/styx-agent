package engagement

import (
	"net/netip"
	"testing"
)

// TestNarrowIntersectsWithThePool covers docs/api-spec-targets.md §5.3: a
// diff's declared hosts can only remove targets from the pool.
func TestNarrowIntersectsWithThePool(t *testing.T) {
	eng, err := gate(t, baseFile)
	if err != nil {
		t.Fatalf("gate() = %v", err)
	}

	narrowed := eng.Narrow([]Target{{Host: "192.0.2.44"}})
	if got, want := narrowed.Targets(), []string{"192.0.2.44"}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if !narrowed.Scope().InScope("192.0.2.44") {
		t.Error("the declared target is no longer in scope")
	}
	if narrowed.Scope().InScope("10.0.0.9") {
		t.Error("a pool entry the change did not declare stayed in scope")
	}
	if narrowed.Scope().Empty() {
		t.Error("a narrowed pool with one target reports empty")
	}

	// A declared address inside a CIDR narrows to that address, not the block.
	inside := eng.Narrow([]Target{{Host: "10.0.0.9"}})
	if inside.Scope().InScope("10.0.0.10") {
		t.Error("a narrowed CIDR kept addresses the change did not declare")
	}
}

// TestNarrowKeepsAnAuthorizedName covers the resolver half: a declared name the
// pool authorizes by name stays a name, so the container's authoritative
// resolver still answers it.
func TestNarrowKeepsAnAuthorizedName(t *testing.T) {
	eng, err := gate(t, validFixture)
	if err != nil {
		t.Fatalf("gate() = %v", err)
	}
	addrs := []netip.Addr{netip.MustParseAddr("192.0.2.45")}
	narrowed := eng.Narrow([]Target{{Host: "app.acme.example", Addrs: addrs}})

	if !narrowed.Scope().InScope("app.acme.example") {
		t.Error("the declared name is not in scope by name")
	}
	if narrowed.Scope().InScope("192.0.2.44") {
		t.Error("a pinned address the change did not declare stayed in scope")
	}
	pins := narrowed.Scope().HostPins()
	if len(pins) != 1 || pins[0].Name != "app.acme.example" {
		t.Fatalf("host pins = %+v, want the declared name", pins)
	}
	if len(pins[0].Addrs) != 1 || pins[0].Addrs[0].String() != "192.0.2.45" {
		t.Errorf("pins = %v, want the declared addresses", pins[0].Addrs)
	}
}

// TestNarrowNeverAddsAnUnauthorizedTarget is the refusal side: a declaration the
// pool does not authorize contributes nothing.
func TestNarrowNeverAddsAnUnauthorizedTarget(t *testing.T) {
	eng, err := gate(t, baseFile)
	if err != nil {
		t.Fatalf("gate() = %v", err)
	}
	narrowed := eng.Narrow([]Target{
		{Host: "198.51.100.7"},
		{Host: "not-in-scope.example", Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}},
	})
	if !narrowed.Scope().Empty() {
		t.Fatalf("targets = %v, want none: an unauthorized declaration added one", narrowed.Targets())
	}
	if narrowed.Scope().InScope("198.51.100.7") {
		t.Error("an unauthorized target became reachable")
	}
}

// TestNarrowKeepsADeclaredNameInsideACIDR is the reachability half of §5.3: a
// spec's declared name authorized by a CIDR must stay a name in the narrowed
// pool, or the session resolver never answers it and every request by name
// fails. The pins are exactly the addresses the pool already contained.
func TestNarrowKeepsADeclaredNameInsideACIDR(t *testing.T) {
	eng, err := gate(t, baseFile)
	if err != nil {
		t.Fatalf("gate() = %v", err)
	}
	declared := []netip.Addr{netip.MustParseAddr("10.0.0.9")}
	narrowed := eng.Narrow([]Target{{Host: "api.acme.example", Addrs: declared}})

	if !narrowed.Scope().InScope("api.acme.example") {
		t.Fatal("the declared name is not reachable by name in the narrowed pool")
	}
	pins := narrowed.Scope().HostPins()
	if len(pins) != 1 || pins[0].Name != "api.acme.example" || pins[0].Wildcard {
		t.Fatalf("host pins = %+v, want the declared name", pins)
	}
	if len(pins[0].Addrs) != 1 || pins[0].Addrs[0].String() != "10.0.0.9" {
		t.Errorf("pins = %v, want the declared address", pins[0].Addrs)
	}
	if got := narrowed.Scope().Pins(); len(got) != 1 || got[0].String() != "10.0.0.9" {
		t.Errorf("egress pins = %v, want the declared address alone", got)
	}
	if got := narrowed.Targets(); len(got) != 1 || got[0] != "api.acme.example" {
		t.Errorf("targets = %v, want the declared name", got)
	}
	// Keeping the name adds no authorization: the rest of the CIDR stays out.
	if narrowed.Scope().InScope("10.0.0.10") {
		t.Error("an undeclared address inside the CIDR became reachable")
	}
}

// TestNarrowRefusesANamePartlyOutsideThePool is answer-binding: a name is taken
// whole or not at all, exactly as the loader refuses it.
func TestNarrowRefusesANamePartlyOutsideThePool(t *testing.T) {
	eng, err := gate(t, baseFile)
	if err != nil {
		t.Fatalf("gate() = %v", err)
	}
	narrowed := eng.Narrow([]Target{{
		Host:  "api.acme.example",
		Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("203.0.113.9")},
	}})
	if !narrowed.Scope().Empty() {
		t.Fatalf("targets = %v, want none: a partly out-of-scope name was narrowed", narrowed.Targets())
	}
	if narrowed.Scope().InScope("api.acme.example") {
		t.Error("a partly out-of-scope name became reachable")
	}
}
