package engagement

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// pinClock is the instant the loader's expiry check is tested against.
const pinClock = "2026-09-30T12:00:00Z"

// testResolver is the DNS seam's deterministic double: a static name →
// addresses table, plus names that refuse to resolve.
var testResolver = fakeResolver{
	records: map[string][]string{
		"app.acme.example": {"192.0.2.44", "192.0.2.45", "192.0.2.44"},
		"*.acme.example":   {"192.0.2.44", "198.51.100.7"},
	},
	fail: map[string]error{
		"gone.acme.example": &net.DNSError{Err: "no such host", Name: "gone.acme.example", IsNotFound: true},
		"*.broken.example":  errors.New("resolver refuses wildcard queries"),
	},
}

// fakeResolver resolves only the names it was given; anything else is
// "no such host", like a live resolver.
type fakeResolver struct {
	records map[string][]string
	fail    map[string]error
}

// LookupHost is the Resolver seam's test double.
func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if err, ok := f.fail[host]; ok {
		return nil, err
	}
	addrs, ok := f.records[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, nil
}

// fixedClock pins the loader's clock to an RFC 3339 instant.
func fixedClock(t *testing.T, at string) func() time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, at)
	if err != nil {
		t.Fatalf("bad test clock %q: %v", at, err)
	}
	return func() time.Time { return parsed }
}

// gate runs the whole gate — validation plus pinning — against the test
// resolver and the pinned clock.
func gate(t *testing.T, src string) (*Engagement, error) {
	t.Helper()
	return Parse(context.Background(), []byte(src),
		WithResolver(testResolver), WithClock(fixedClock(t, pinClock)))
}

// baseFile is a minimal, well-formed engagement file; table cases state only
// what they change about it.
const baseFile = `apiVersion: styx.engagement/v1
name: acme-q4-redteam
operator: eddy
expires: 2026-10-15T23:59:59Z
targets:
  - 10.0.0.0/24
  - 192.0.2.44
  - app.acme.example
roe:
  exploit_allowed: true
  destructive_forbidden: true
`

// validFixture is the full accepted shape: CIDR, IP literal, hostname, and
// wildcard targets, an expiry, and a time window.
const validFixture = `apiVersion: styx.engagement/v1
name: acme-q4-redteam
operator: eddy
expires: 2026-10-15T23:59:59Z
targets:
  - 10.0.0.0/24
  - 192.0.2.44
  - app.acme.example
  - "*.acme.example"
roe:
  exploit_allowed: true
  destructive_forbidden: true
  time_window:
    start: "08:00"
    end: "18:00"
    tz: America/New_York
`

// without drops one line from a source file.
func without(src, line string) string {
	return strings.Replace(src, line+"\n", "", 1)
}

// replaceLine swaps one line (or fragment) in a source file.
func replaceLine(src, old, replacement string) string {
	return strings.Replace(src, old, replacement, 1)
}
