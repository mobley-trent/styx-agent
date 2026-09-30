package engagement

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/policy"
)

// TestParseRefuseToStart is the gate's core acceptance: malformed YAML,
// unresolvable targets, unknown ROE flags, and stale expiry each produce a
// clear error and no partial scope. Every case must also assert the refusal's
// kind (the wrapped sentinel) and that nothing at all came back.
func TestParseRefuseToStart(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr error
		wantMsg string // a substring the operator must see
	}{
		{
			name:    "empty file",
			src:     "",
			wantErr: ErrParse,
			wantMsg: "empty",
		},
		{
			name:    "malformed yaml",
			src:     "apiVersion: [styx.engagement/v1\nname: acme\n",
			wantErr: ErrParse,
		},
		{
			name:    "unknown top-level key",
			src:     replaceLine(baseFile, "  destructive_forbidden: true", "  destructive_forbidden: true\nscope: 0.0.0.0/0"),
			wantErr: ErrParse,
			wantMsg: "scope",
		},
		{
			name:    "missing apiVersion",
			src:     without(baseFile, "apiVersion: styx.engagement/v1"),
			wantErr: ErrParse,
			wantMsg: "apiVersion",
		},
		{
			name:    "unsupported apiVersion",
			src:     replaceLine(baseFile, "apiVersion: styx.engagement/v1", "apiVersion: styx.engagement/v2"),
			wantErr: ErrParse,
			wantMsg: "styx.engagement/v2",
		},
		{
			name:    "missing name",
			src:     without(baseFile, "name: acme-q4-redteam"),
			wantErr: ErrParse,
			wantMsg: "name",
		},
		{
			name:    "unknown roe flag",
			src:     replaceLine(baseFile, "  destructive_forbidden: true", "  destructive_forbidden: true\n  persistence_allowed: true"),
			wantErr: ErrParse,
			wantMsg: "persistence_allowed",
		},
		{
			name:    "roe block absent",
			src:     "apiVersion: styx.engagement/v1\nname: acme\ntargets:\n  - 192.0.2.44\n",
			wantErr: ErrROE,
			wantMsg: "exploit_allowed",
		},
		{
			name:    "roe flag absent",
			src:     without(baseFile, "  destructive_forbidden: true"),
			wantErr: ErrROE,
			wantMsg: "destructive_forbidden",
		},
		{
			name:    "roe flag not a boolean",
			src:     replaceLine(baseFile, "  exploit_allowed: true", "  exploit_allowed: maybe"),
			wantErr: ErrParse,
			wantMsg: "into bool",
		},
		{
			name:    "no targets",
			src:     without(baseFile, "targets:\n  - 10.0.0.0/24\n  - 192.0.2.44\n  - app.acme.example"),
			wantErr: ErrTarget,
			wantMsg: "at least one",
		},
		{
			name:    "empty target",
			src:     replaceLine(baseFile, "  - 192.0.2.44", "  - \"  \""),
			wantErr: ErrTarget,
			wantMsg: "empty",
		},
		{
			name:    "malformed cidr",
			src:     replaceLine(baseFile, "  - 10.0.0.0/24", "  - 10.0.0.0/33"),
			wantErr: ErrTarget,
			wantMsg: "10.0.0.0/33",
		},
		{
			name:    "scoped ipv6 address",
			src:     replaceLine(baseFile, "  - 192.0.2.44", "  - fe80::1%eth0"),
			wantErr: ErrTarget,
			wantMsg: "scoped IPv6",
		},
		{
			name:    "url is not a target",
			src:     replaceLine(baseFile, "  - app.acme.example", "  - https://app.acme.example"),
			wantErr: ErrTarget,
			wantMsg: "https://app.acme.example",
		},
		{
			name:    "bare wildcard",
			src:     replaceLine(baseFile, "  - app.acme.example", "  - \"*\""),
			wantErr: ErrTarget,
			wantMsg: "wildcard",
		},
		{
			name:    "misplaced wildcard",
			src:     replaceLine(baseFile, "  - app.acme.example", "  - \"*acme.example\""),
			wantErr: ErrTarget,
			wantMsg: "wildcard",
		},
		{
			name:    "unresolvable target",
			src:     replaceLine(baseFile, "  - app.acme.example", "  - gone.acme.example"),
			wantErr: ErrTarget,
			wantMsg: "gone.acme.example",
		},
		{
			name:    "wildcard cannot be pinned",
			src:     replaceLine(baseFile, "  - app.acme.example", "  - \"*.broken.example\""),
			wantErr: ErrTarget,
			wantMsg: "*.broken.example",
		},
		{
			name:    "expiry not rfc 3339",
			src:     replaceLine(baseFile, "expires: 2026-10-15T23:59:59Z", "expires: 2026-10-15"),
			wantErr: ErrParse,
			wantMsg: "expires",
		},
		{
			name:    "stale expiry",
			src:     replaceLine(baseFile, "expires: 2026-10-15T23:59:59Z", "expires: 2026-09-01T00:00:00Z"),
			wantErr: ErrStale,
			wantMsg: "2026-09-01T00:00:00Z",
		},
		{
			name:    "time window start not hh mm",
			src:     replaceLine(baseFile, "  destructive_forbidden: true", "  destructive_forbidden: true\n  time_window:\n    start: 8am\n    end: \"18:00\""),
			wantErr: ErrROE,
			wantMsg: "8am",
		},
		{
			name:    "time window end not hh mm",
			src:     replaceLine(baseFile, "  destructive_forbidden: true", "  destructive_forbidden: true\n  time_window:\n    start: \"08:00\"\n    end: \"25:00\""),
			wantErr: ErrROE,
			wantMsg: "25:00",
		},
		{
			name:    "unknown timezone",
			src:     replaceLine(baseFile, "  destructive_forbidden: true", "  destructive_forbidden: true\n  time_window:\n    start: \"08:00\"\n    end: \"18:00\"\n    tz: Mars/Olympus"),
			wantErr: ErrROE,
			wantMsg: "Mars/Olympus",
		},
		{
			name:    "more than one yaml document",
			src:     baseFile + "---\nname: second\n",
			wantErr: ErrParse,
			wantMsg: "more than one",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng, err := gate(t, tt.src)
			if err == nil {
				t.Fatalf("Parse() = %+v, want refusal", eng)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Parse() error = %v, want it to wrap %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Parse() error = %q, want it to mention %q", err, tt.wantMsg)
			}
			if eng != nil {
				t.Errorf("refused file returned a partial engagement: %+v", eng)
			}
		})
	}
}

// TestParseCollectsEveryProblem checks the gate reports all of a file's
// defects at once rather than one per attempt — the operator fixes the file
// once.
func TestParseCollectsEveryProblem(t *testing.T) {
	src := "apiVersion: styx.engagement/v1\ntargets:\n  - 10.0.0.0/33\n  - gone.acme.example\nroe:\n  exploit_allowed: true\n"
	_, err := gate(t, src)
	if err == nil {
		t.Fatal("Parse() = nil error, want refusal")
	}
	for _, want := range []error{ErrParse, ErrTarget, ErrROE} {
		if !errors.Is(err, want) {
			t.Errorf("error %v does not wrap %v", err, want)
		}
	}
	for _, msg := range []string{"name", "10.0.0.0/33", "gone.acme.example", "destructive_forbidden"} {
		if !strings.Contains(err.Error(), msg) {
			t.Errorf("error = %q, want it to mention %q", err, msg)
		}
	}
}

// TestParseValidFile asserts the accepted shape: the pool is preserved
// verbatim, ROE maps onto the policy engine's limits, and expiry is reported.
func TestParseValidFile(t *testing.T) {
	eng, err := gate(t, validFixture)
	if err != nil {
		t.Fatalf("Parse() error = %v, want a valid engagement", err)
	}

	if got, want := eng.Name(), "acme-q4-redteam"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
	if got, want := eng.Operator(), "eddy"; got != want {
		t.Errorf("Operator() = %q, want %q", got, want)
	}
	wantTargets := []string{"10.0.0.0/24", "192.0.2.44", "app.acme.example", "*.acme.example"}
	if got := eng.Targets(); !reflect.DeepEqual(got, wantTargets) {
		t.Errorf("Targets() = %v, want %v", got, wantTargets)
	}

	expires, ok := eng.Expires()
	if !ok {
		t.Fatal("Expires() = no expiry, want the declared one")
	}
	if want := time.Date(2026, 10, 15, 23, 59, 59, 0, time.UTC); !expires.Equal(want) {
		t.Errorf("Expires() = %s, want %s", expires, want)
	}

	wantROE := &policy.ROE{
		ExploitAllowed:       true,
		DestructiveForbidden: true,
		TimeWindow:           &policy.TimeWindow{Start: "08:00", End: "18:00", TZ: "America/New_York"},
	}
	if got := eng.ROE(); !reflect.DeepEqual(got, wantROE) {
		t.Errorf("ROE() = %+v, want %+v", got, wantROE)
	}
}

// TestParseEvergreenWithoutExpiry pins the documented "absent = evergreen"
// rule.
func TestParseEvergreenWithoutExpiry(t *testing.T) {
	eng, err := gate(t, without(baseFile, "expires: 2026-10-15T23:59:59Z"))
	if err != nil {
		t.Fatalf("Parse() error = %v, want a valid engagement", err)
	}
	if _, ok := eng.Expires(); ok {
		t.Error("Expires() reported an expiry, want none")
	}
}

// TestParsePinsHostnamesAtLoad is the DNS-pinning acceptance: hostnames and
// wildcards resolve once, at load, and their addresses become the immutable
// pin set.
func TestParsePinsHostnamesAtLoad(t *testing.T) {
	eng, err := gate(t, scopeFixture)
	if err != nil {
		t.Fatalf("Parse() error = %v, want a valid engagement", err)
	}

	// The scope is the policy engine's Scope seam — one definition of
	// in-scope for the whole harness (§2).
	var scope policy.Scope = eng.Scope()
	for _, addr := range []string{"10.0.0.1", "192.0.2.44", "192.0.2.45", "198.51.100.7"} {
		if !scope.InScope(addr) {
			t.Errorf("InScope(%q) = false, want true (pinned at load)", addr)
		}
	}
	if scope.InScope("198.51.100.8") {
		t.Error("InScope(198.51.100.8) = true, want false (never pinned)")
	}

	// Pins are deduplicated and sorted: 10.0.0.0/24 contributes no address,
	// 192.0.2.44 is both a literal and a hostname pin.
	var want []netip.Addr
	for _, p := range []string{"192.0.2.44", "192.0.2.45", "198.51.100.7", "2001:db8::1"} {
		want = append(want, netip.MustParseAddr(p))
	}
	if got := eng.Scope().Pins(); !reflect.DeepEqual(got, want) {
		t.Errorf("Pins() = %v, want %v", got, want)
	}
	if got := eng.Scope().Prefixes(); len(got) != 1 || got[0].String() != "10.0.0.0/24" {
		t.Errorf("Prefixes() = %v, want [10.0.0.0/24]", got)
	}
}

// TestLoadReadsAndRefusesOnDisk covers the file path: a valid file on disk
// loads; a missing one is an error, never a silent safe-mode fallback.
func TestLoadReadsAndRefusesOnDisk(t *testing.T) {
	ctx := context.Background()
	eng, err := Load(ctx, "../testdata/engagement/acme-q4-redteam.yaml",
		WithResolver(testResolver), WithClock(fixedClock(t, pinClock)))
	if err != nil {
		t.Fatalf("Load(fixture) error = %v, want a valid engagement", err)
	}
	if eng.Name() != "acme-q4-redteam" {
		t.Errorf("Load(fixture).Name() = %q, want acme-q4-redteam", eng.Name())
	}
	if eng.ROE() == nil || !eng.ROE().ExploitAllowed {
		t.Errorf("Load(fixture).ROE() = %+v, want the declared flags", eng.ROE())
	}

	if _, err := Load(ctx, "../testdata/engagement/missing.yaml"); err == nil {
		t.Error("Load(missing file) = nil error, want a read failure")
	}
}

// TestParseRejectsUnknownResolverOutput guards the resolver seam's contract:
// a resolver that answers with something that is not an address refuses the
// file instead of pinning a bogus value.
func TestParseRejectsUnknownResolverOutput(t *testing.T) {
	bad := fakeResolver{records: map[string][]string{"app.acme.example": {"not-an-ip"}}}
	_, err := Parse(context.Background(), []byte(baseFile), WithResolver(bad), WithClock(fixedClock(t, pinClock)))
	if !errors.Is(err, ErrTarget) {
		t.Fatalf("Parse() error = %v, want it to wrap %v", err, ErrTarget)
	}
}
