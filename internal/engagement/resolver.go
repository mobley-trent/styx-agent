package engagement

import (
	"context"
	"net"
)

// Resolver resolves a hostname to its addresses. It is the only seam through
// which the engagement gate can touch DNS, which keeps the gate's tests
// hermetic and deterministic: production pins through the host resolver, tests
// pin through a static table.
type Resolver interface {
	// LookupHost returns the addresses a hostname resolves to. An error or an
	// empty result refuses the engagement file to start (§7.2: "every target
	// must resolve").
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// DefaultResolver pins hostnames through the host's resolver.
var DefaultResolver Resolver = hostResolver{}

// hostResolver is the production Resolver: net.DefaultResolver, unmodified.
type hostResolver struct{}

// LookupHost delegates to the host resolver, returning the addresses as
// strings (the Resolver contract) rather than net.IPs.
func (hostResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}
