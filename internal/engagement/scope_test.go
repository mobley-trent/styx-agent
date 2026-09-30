package engagement

import (
	"net/netip"
	"testing"
)

// scopeFixture exercises every entry kind, including an IPv6 literal.
const scopeFixture = `apiVersion: styx.engagement/v1
name: acme-q4-redteam
targets:
  - 192.0.2.44
  - 10.0.0.0/24
  - app.acme.example
  - "*.acme.example"
  - 2001:db8::1
roe:
  exploit_allowed: true
  destructive_forbidden: true
`

// TestScopeMatch is the scope-membership acceptance: IP literal, containing
// CIDR, pinned hostname — with the negative cases proven out of scope,
// including the rebinding-shaped ones (a pin set is a closed set of
// addresses; a look-alike name or an unpublished address is not authorized).
func TestScopeMatch(t *testing.T) {
	eng, err := gate(t, scopeFixture)
	if err != nil {
		t.Fatalf("Parse() error = %v, want a valid engagement", err)
	}
	scope := eng.Scope()

	tests := []struct {
		name string
		dest string
		want bool
	}{
		{name: "ip literal", dest: "192.0.2.44", want: true},
		{name: "address inside cidr", dest: "10.0.0.1", want: true},
		{name: "cidr network address", dest: "10.0.0.0", want: true},
		{name: "cidr broadcast address", dest: "10.0.0.255", want: true},
		{name: "pinned hostname address", dest: "192.0.2.45", want: true},
		{name: "wildcard pinned address", dest: "198.51.100.7", want: true},
		{name: "ipv6 literal", dest: "2001:db8::1", want: true},
		{name: "ipv4-mapped ipv6 of a pin", dest: "::ffff:192.0.2.44", want: true},
		{name: "port is irrelevant", dest: "192.0.2.44:443", want: true},
		{name: "bracketed ipv6 with port", dest: "[2001:db8::1]:8443", want: true},
		{name: "declared hostname", dest: "app.acme.example", want: true},
		{name: "hostname case and root dot normalized", dest: "APP.ACME.EXAMPLE.", want: true},
		{name: "wildcard subdomain", dest: "db.acme.example", want: true},
		{name: "wildcard spans labels", dest: "a.b.acme.example", want: true},

		{name: "unpublished address", dest: "203.0.113.9", want: false},
		{name: "address just outside cidr", dest: "10.0.1.1", want: false},
		{name: "address next to a pin", dest: "192.0.2.46", want: false},
		{name: "wildcard expansion is a closed set", dest: "198.51.100.8", want: false},
		{name: "ipv6 neighbour", dest: "2001:db8::2", want: false},
		{name: "wildcard does not cover the zone apex", dest: "acme.example", want: false},
		{name: "look-alike domain", dest: "notacme.example", want: false},
		{name: "suffix spoof", dest: "app.acme.example.attacker.test", want: false},
		{name: "undeclared subdomain of another zone", dest: "db.other.example", want: false},
		{name: "empty destination", dest: "", want: false},
		{name: "url is not a destination", dest: "https://app.acme.example", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scope.InScope(tt.dest); got != tt.want {
				t.Errorf("InScope(%q) = %v, want %v", tt.dest, got, tt.want)
			}
		})
	}
}

// TestScopesAreSeparate confirms each parsed engagement owns its own pins:
// one file's hostnames never widen another's scope.
func TestScopesAreSeparate(t *testing.T) {
	wild, err := gate(t, scopeFixture)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	plain, err := gate(t, baseFile)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if !wild.Scope().InScope("198.51.100.7") {
		t.Error("the wildcard engagement lost its own pin")
	}
	if plain.Scope().InScope("198.51.100.7") {
		t.Error("a scope authorized another engagement's wildcard pin")
	}
	if !plain.Scope().InScope("192.0.2.44") {
		t.Error("the plain engagement lost its own pin")
	}
}

// TestScopeAccessorsReturnCopies confirms the accessors hand out copies: a
// caller mutating the returned slices cannot widen or narrow the engagement.
func TestScopeAccessorsReturnCopies(t *testing.T) {
	eng, err := gate(t, scopeFixture)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	pins := eng.Scope().Pins()
	for i := range pins {
		pins[i] = netip.MustParseAddr("203.0.113.9")
	}
	prefixes := eng.Scope().Prefixes()
	for i := range prefixes {
		prefixes[i] = netip.MustParsePrefix("0.0.0.0/0")
	}

	if eng.Scope().InScope("203.0.113.9") {
		t.Error("mutating a returned pin slice widened the scope")
	}
	if !eng.Scope().InScope("10.0.0.9") {
		t.Error("mutating a returned prefix slice dropped authorization")
	}
}
