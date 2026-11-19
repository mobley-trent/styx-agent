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
