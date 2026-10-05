package app

import (
	"context"
	"errors"
	"sync"

	"github.com/mobley-trent/styx-agent/internal/model"
)

// errNoAPIKey marks a turn the deferred provider refused because the credential
// is absent. The status bar names this state from the sentinel rather than by
// parsing message text.
var errNoAPIKey = errors.New("provider credential is not set")

// lazyModelClient defers provider resolution to the first model turn (§1 "fail
// on demand"). Startup never refuses for a missing API key or an unreachable
// provider; those failures surface at their point of use as a recoverable turn
// error, and the harness reports the degraded state in the status bar.
//
// A successful resolution is cached; a failed one is not, so a later turn
// retries and a transient outage or a corrected provider recovers without a
// restart. It is wiring, not policy: it decides nothing about what may run, it
// only moves the provider's construction to where the provider is needed.
type lazyModelClient struct {
	// resolve builds the concrete client, or returns the reason it cannot. It
	// runs under the client's lock, at most once per successful build, again
	// after each failure.
	resolve func(context.Context) (model.ModelClient, error)

	mu     sync.Mutex
	client model.ModelClient
	// status is the status bar's degraded-provider marker: empty when the
	// provider is healthy or untried, or the reason a build last failed.
	status string
}

var _ model.ModelClient = (*lazyModelClient)(nil)

// newLazyModelClient wraps a deferred provider build. initialStatus is the
// degraded marker already known before any turn — a missing credential, for
// instance — and is empty when no problem is known.
func newLazyModelClient(resolve func(context.Context) (model.ModelClient, error), initialStatus string) *lazyModelClient {
	return &lazyModelClient{resolve: resolve, status: initialStatus}
}

// StreamTurn builds the provider on first use, then delegates. A failed build
// is returned as the turn error and is not cached: the next turn retries.
func (c *lazyModelClient) StreamTurn(ctx context.Context, req model.ModelRequest) (<-chan model.StreamEvent, error) {
	client, err := c.ensure(ctx)
	if err != nil {
		return nil, err
	}
	return client.StreamTurn(ctx, req)
}

// ensure returns the resolved provider, building it on first use.
func (c *lazyModelClient) ensure(ctx context.Context) (model.ModelClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	client, err := c.resolve(ctx)
	if err != nil {
		c.status = providerStatus(err)
		return nil, err
	}
	c.client = client
	c.status = ""
	return client, nil
}

// ProviderStatus is the status bar's degraded-provider readout: empty when the
// provider is healthy or has not been tried, or a short marker once a build has
// failed.
func (c *lazyModelClient) ProviderStatus() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// providerStatus maps a deferred-build error onto the status bar's marker.
func providerStatus(err error) string {
	if errors.Is(err, errNoAPIKey) {
		return "no api key"
	}
	return "provider unavailable"
}
