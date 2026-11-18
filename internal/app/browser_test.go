package app

import (
	"context"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/agent"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
)

// TestBrowserToolsRegistered proves the six browser tools join every session's
// registry in both modes. Their gating is the rule table's job, and safe mode's
// floor is a prompt (§6); the browser itself stays a declared prerequisite, not
// a startup requirement.
func TestBrowserToolsRegistered(t *testing.T) {
	h, err := Build(context.Background(), buildOptions(t, t.TempDir(), fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	names := map[string]bool{}
	for _, name := range h.Tools.Names() {
		names[name] = true
	}
	for _, want := range agent.BrowserToolNames() {
		if !names[want] {
			t.Errorf("registry is missing the %q browser tool", want)
		}
	}

	if got := h.Engine.Decide(policy.Call{Tool: "browser_read"}).Verdict; got != policy.VerdictPrompt {
		t.Errorf("safe-mode browser_read verdict = %q, want prompt", got)
	}
	if got := h.Status(false).Browser; got != "" {
		t.Errorf("status bar says %q before any browser call, want nothing", got)
	}
}
