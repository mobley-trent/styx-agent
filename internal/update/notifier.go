package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Fetch defaults. The notifier is a background courtesy, never a startup
// dependency: a slow or unreachable endpoint must not delay the harness.
const (
	// DefaultTimeout bounds the single releases fetch.
	DefaultTimeout = 5 * time.Second
	// DefaultMaxBytes caps the fetched release document.
	DefaultMaxBytes = 64 << 10
	// userAgent identifies styx to the releases endpoint.
	userAgent = "styx-update-notifier"
)

// Fetcher is the single-request seam the notifier fetches through. It is the
// only thing tests replace, so no test talks to the network.
type Fetcher interface {
	// Fetch performs one GET and returns the response body.
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// HTTPFetcher is the default Fetcher. It reads at most DefaultMaxBytes so a
// misbehaving endpoint cannot balloon the harness.
type HTTPFetcher struct {
	// Client is the HTTP client; nil means a client bounded by DefaultTimeout.
	Client *http.Client
	// MaxBytes caps the body; zero means DefaultMaxBytes.
	MaxBytes int64
}

// Fetch performs the GET.
func (f HTTPFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}
	maxBytes := f.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: releases endpoint returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, err
	}
	return body, nil
}

// Notifier performs the single releases-latest fetch the harness is allowed
// (§12.3). It is safe for concurrent use and fetches at most once per process:
// later Check calls return the first result without touching the network.
type Notifier struct {
	current string
	fetcher Fetcher

	once sync.Once
	rel  Release
	new  bool
	err  error
}

// NewNotifier builds a notifier for the running version. A nil fetcher uses
// the default HTTP fetcher.
func NewNotifier(current string, fetcher Fetcher) *Notifier {
	if fetcher == nil {
		fetcher = HTTPFetcher{}
	}
	return &Notifier{current: current, fetcher: fetcher}
}

// Check fetches the latest release and reports whether a strictly newer stable
// version exists. Only the first call fetches; later calls replay its result.
func (n *Notifier) Check(ctx context.Context) (Release, bool, error) {
	n.once.Do(func() {
		body, err := n.fetcher.Fetch(ctx, ReleasesURL)
		if err != nil {
			n.err = err
			return
		}
		var rel Release
		if err := json.Unmarshal(body, &rel); err != nil {
			n.err = fmt.Errorf("update: decode releases endpoint: %w", err)
			return
		}
		n.rel = rel
		n.new = NewerAvailable(n.current, rel)
	})
	return n.rel, n.new, n.err
}

// Gate decides whether the update notifier may run at all (§12.3): it is off
// when the operator opts out (config or env), off for source builds, and off
// while engagement mode is active.
type Gate struct {
	// ConfigEnabled is the config's update_notifier value (default true).
	ConfigEnabled bool
	// SourceBuild is true for an unstamped (go build / go install) binary.
	SourceBuild bool
	// Engagement is true while engagement mode is active.
	Engagement bool
	// Env reads an environment variable; nil means os.Getenv.
	Env func(string) string
}

// Active reports whether the notifier is permitted to make its single fetch.
func (g Gate) Active() bool {
	if !g.ConfigEnabled || g.SourceBuild || g.Engagement {
		return false
	}
	env := g.Env
	if env == nil {
		env = os.Getenv
	}
	return !truthy(env(NoNotifierEnv))
}

// truthy interprets the opt-out env var: an unset, empty, or "false"-like
// value leaves the notifier on; anything else opts out.
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// Report is the `styx update` output: current version, latest release, the
// detected install source, and the exact upgrade command for it (§12.3).
func Report(current string, rel Release, src Source) string {
	latest := rel.Version
	if latest == "" {
		latest = "unknown"
	}
	url := rel.URL
	if url == "" {
		url = ReleasesPage
	}
	var b strings.Builder
	fmt.Fprintf(&b, "current: %s\n", displayVersion(current))
	fmt.Fprintf(&b, "latest:  %s\n", displayVersion(latest))
	fmt.Fprintf(&b, "source:  %s\n", src.Label())
	b.WriteString("upgrade: " + UpgradeCommand(src))
	// An empty release means the endpoint was unreachable: say nothing about
	// being up to date, or the failed check would read as a success.
	if rel.Version == "" {
		return b.String()
	}
	if !NewerAvailable(current, rel) {
		b.WriteString("\n\nalready up to date")
		return b.String()
	}
	b.WriteString("\n\n" + url)
	return b.String()
}

// displayVersion normalizes an empty version for display.
func displayVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "dev"
	}
	return v
}
