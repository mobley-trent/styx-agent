package app

import (
	"context"
	"errors"
	"strings"
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

// TestBrowserNavigateIsScopeCheckedAtTheGate proves the browser's target source
// reaches the policy gate end to end (docs/browser-and-proxy.md §3.2, §3.3,
// §6): the registered tool derives the URL's host, engagement scope widens the
// in-scope navigate, and an out-of-scope host still prompts.
func TestBrowserNavigateIsScopeCheckedAtTheGate(t *testing.T) {
	opts := buildOptions(t, t.TempDir(), fakemodel.New())
	opts.Engagement = engagementFixture
	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	tool, ok := h.Tools.Lookup("browser_navigate")
	if !ok {
		t.Fatal("registry has no browser_navigate")
	}
	decide := func(rawURL string) policy.VerdictResult {
		t.Helper()
		targets := tool.Targets(map[string]any{"url": rawURL})
		if len(targets) != 1 {
			t.Fatalf("Targets(%q) = %v, want the URL's host", rawURL, targets)
		}
		return h.Engine.Decide(policy.Call{Tool: "browser_navigate", ScopeTargets: targets})
	}

	if got := decide("http://192.0.2.44/login"); got.Verdict != policy.VerdictAllow || got.Reason != policy.ReasonInScope {
		t.Errorf("in-scope navigate = %v/%s, want allow/in-scope", got.Verdict, got.Reason)
	}
	if got := decide("http://203.0.113.9/login"); got.Verdict != policy.VerdictPrompt || got.Reason != policy.ReasonOutOfScope {
		t.Errorf("out-of-scope navigate = %v/%s, want prompt/out-of-scope", got.Verdict, got.Reason)
	}
}

// TestHeadlessBrowserPromptIsDeniedNoOperator pins the headless half of the
// browser's gating (§6): a prompt has no operator to answer it, so a
// non-interactive run denies it as no-operator and never launches the browser.
func TestHeadlessBrowserPromptIsDeniedNoOperator(t *testing.T) {
	dir := t.TempDir()
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "browser_navigate", `{"url":"http://192.0.2.44/"}`)),
		fakemodel.Text("no browser available"),
	))
	var out, errOut strings.Builder

	err := Run(context.Background(), headlessOptions(t, dir, fake, "browse the target", &out, &errOut))
	var notClean *NotClean
	if !errors.As(err, &notClean) {
		t.Fatalf("Run() = %v, want *NotClean", err)
	}
	if notClean.Denied != 1 {
		t.Errorf("denied = %d, want 1", notClean.Denied)
	}
	if !strings.Contains(errOut.String(), "! deny browser_navigate (no operator: not permitted non-interactively)") {
		t.Errorf("stderr does not report the no-operator denial:\n%s", errOut.String())
	}
	if strings.Contains(errOut.String(), "browser_navigate: no browser driver") {
		t.Errorf("the denied call reached the browser driver:\n%s", errOut.String())
	}
}
