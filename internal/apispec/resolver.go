package apispec

import (
	"context"
	"net"
)

// netLookupHost is the production resolver body: the host resolver, unmodified.
// It is a seam so a load's DNS touches exactly one place and tests stay
// offline.
func netLookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}
