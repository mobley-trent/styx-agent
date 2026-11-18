package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/mobley-trent/styx-agent/internal/agent"
	"github.com/mobley-trent/styx-agent/internal/browser"
	"github.com/mobley-trent/styx-agent/internal/containerlayer"
	"github.com/mobley-trent/styx-agent/internal/engagement"
)

// This file is the harness's half of the browser's wiring
// (docs/browser-and-proxy.md §3): it hands the agent a driver whose only egress
// path is the session proxy and whose profile is scoped to the engagement. The
// driver owns the process and CDP; the app owns when it starts and when it is
// torn down.

// browserAdapter adapts internal/browser's values to the agent's seam, so the
// tool package never imports the driver.
type browserAdapter struct{ driver *browser.Manager }

// Navigate implements agent.Browser.
func (a browserAdapter) Navigate(ctx context.Context, rawURL string) (agent.BrowserPage, error) {
	state, err := a.driver.Navigate(ctx, rawURL)
	return agent.BrowserPage{URL: state.URL, Title: state.Title}, err
}

// Read implements agent.Browser.
func (a browserAdapter) Read(ctx context.Context, handle string, maxChars int) (string, error) {
	return a.driver.Read(ctx, handle, maxChars)
}

// Click implements agent.Browser.
func (a browserAdapter) Click(ctx context.Context, handle string) (agent.BrowserPage, error) {
	state, err := a.driver.Click(ctx, handle)
	return agent.BrowserPage{URL: state.URL, Title: state.Title}, err
}

// Type implements agent.Browser.
func (a browserAdapter) Type(ctx context.Context, handle, text string, submit bool) (agent.BrowserPage, error) {
	state, err := a.driver.TypeText(ctx, handle, text, submit)
	return agent.BrowserPage{URL: state.URL, Title: state.Title}, err
}

// Screenshot implements agent.Browser.
func (a browserAdapter) Screenshot(ctx context.Context, fullPage bool) (agent.BrowserArtifact, error) {
	artifact, err := a.driver.Screenshot(ctx, fullPage)
	return browserArtifact(artifact), err
}

// Download implements agent.Browser.
func (a browserAdapter) Download(ctx context.Context, handle string) (agent.BrowserArtifact, error) {
	artifact, err := a.driver.Download(ctx, handle)
	return browserArtifact(artifact), err
}

// browserArtifact converts a driver artifact into the agent-facing shape.
func browserArtifact(artifact browser.Artifact) agent.BrowserArtifact {
	return agent.BrowserArtifact{
		Path:        artifact.Path,
		Filename:    artifact.Filename,
		ContentType: artifact.ContentType,
		Bytes:       artifact.Bytes,
		URL:         artifact.URL,
		Title:       artifact.Title,
		Width:       artifact.Width,
		Height:      artifact.Height,
	}
}

// browserTools builds the session's six browser tools and the driver behind
// them. The driver is created in both modes and starts lazily on the first
// browser call (§7). Its proxy resolver starts the session container, because
// the browser dials the harness proxy and nothing else: a session with no
// container — tests, or a host that cannot run one — has no proxy, and the
// tool refuses with a named error instead of opening a direct path (§3.1).
func (h *Harness) browserTools(container *containerlayer.Manager, eng *engagement.Engagement) ([]agent.Tool, *browser.Manager) {
	opts := browser.Options{
		ProjectDir: h.WorkDir,
		Session:    h.SessionID(),
		Now:        h.now,
		ProxyURL: func(ctx context.Context) (string, error) {
			if container == nil {
				return "", errors.New("browser: this session has no egress proxy; the browser dials only the harness proxy")
			}
			if _, err := container.Start(ctx); err != nil {
				return "", fmt.Errorf("browser: start the session egress proxy: %w", err)
			}
			return container.ProxyURL(), nil
		},
	}
	if eng != nil {
		// Engagement browsing keeps its profile per engagement (§5) and pins
		// the engagement CA's SPKI on the browser's command line, so exactly
		// one process trusts exactly one CA (§4.4).
		opts.Engagement = eng.Name()
		opts.CASPKI = func(context.Context) (string, error) {
			ca, err := containerlayer.OpenCA(containerlayer.CAOptions{
				ProjectDir: h.WorkDir,
				Engagement: eng.Name(),
				Now:        h.now,
			})
			if err != nil {
				return "", err
			}
			return ca.SPKIHash()
		}
	}
	driver := browser.New(opts)
	return agent.BrowserTools(browserAdapter{driver: driver}), driver
}

// browserText is the status bar's host-browser indicator (§3.1, §9.1): the bar
// says `browser: host` while a browser is running, so a host process rendering
// hostile page content is never implied to be anything else.
func (h *Harness) browserText() string {
	h.mu.Lock()
	driver := h.browserDriver
	h.mu.Unlock()
	if driver == nil || !driver.Running() {
		return ""
	}
	return "browser: host"
}
