package app

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/diffscope"
	"github.com/mobley-trent/styx-agent/internal/engagement"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
)

const diffEngagement = `apiVersion: styx.engagement/v1
name: diff-scope
operator: eddy
targets:
  - 192.0.2.44
  - 10.0.0.0/24
roe:
  exploit_allowed: false
  destructive_forbidden: true
`

// scopeResult is the computation a diff-scoped test injects, so the wiring is
// tested without a repository.
func scopeResult(targets []engagement.Target, changed ...string) diffscope.Result {
	return diffscope.Result{
		Base:       "main",
		BaseCommit: "0123456789abcdef0123456789abcdef01234567",
		Documents:  []string{"api/openapi.yaml"},
		Targets:    targets,
		Changed:    changed,
	}
}

// TestHeadlessDiffScopeEmptyIsACleanNoOp covers §11.2: a change that maps to no
// authorized target exits 0 with one line, the normal summary, and no turn
// spent. Functionality no test would miss: a scope flag must never claim a
// narrowing the run cannot keep.
func TestHeadlessDiffScopeEmptyIsACleanNoOp(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "engagement.yaml", diffEngagement)
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("a turn ran anyway")))
	var out, errOut strings.Builder

	opts := headlessOptions(t, dir, fake, "scan the API", &out, &errOut)
	opts.Engagement = filepath.Join(dir, "engagement.yaml")
	opts.ScopeMode = ScopeModeDiff
	opts.DiffBase = "main"
	opts.DiffScope = func(context.Context, diffscope.Options) (diffscope.Result, error) {
		return scopeResult(nil), nil
	}

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() = %v, want a clean no-op", err)
	}
	if got := strings.TrimSpace(out.String()); got != "" {
		t.Errorf("stdout = %q, want no answer from a run that scanned nothing", got)
	}
	transcript := errOut.String()
	for _, want := range []string{
		"diff scope (base 0123456789ab)",
		"styx: diff scope: no authorized target matched the change",
		"styx: done — 0 turns",
		"styx: denied 0 prompts",
	} {
		if !strings.Contains(transcript, want) {
			t.Errorf("stderr does not contain %q:\n%s", want, transcript)
		}
	}
}

// TestHeadlessDiffScopeNarrowsAndCarriesContext covers §5.3: the change narrows
// the pool to its declared host, the changed operation reaches the prompt as
// context that authorizes nothing, and the audit records the effective pool.
func TestHeadlessDiffScopeNarrowsAndCarriesContext(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "engagement.yaml", diffEngagement)
	engPath := filepath.Join(dir, "engagement.yaml")
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("scanned")))
	var out, errOut strings.Builder

	scope := func(context.Context, diffscope.Options) (diffscope.Result, error) {
		return scopeResult([]engagement.Target{{Host: "192.0.2.44"}}, "POST /users/{id}"), nil
	}
	opts := headlessOptions(t, dir, fake, "scan the change", &out, &errOut)
	opts.Engagement = engPath
	opts.ScopeMode = ScopeModeDiff
	opts.DiffBase = "main"
	opts.DiffScope = scope

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	if h.Mode == "" || h.Engagement == nil {
		t.Fatal("Build() did not activate the engagement")
	}
	if got := h.Engagement.Targets(); len(got) != 1 || got[0] != "192.0.2.44" {
		t.Errorf("effective pool = %v, want only the declared host", got)
	}
	if h.Engagement.Scope().InScope("10.0.0.9") {
		t.Error("an undeclared pool entry stayed in scope")
	}
	if !h.Engagement.Scope().InScope("192.0.2.44") {
		t.Error("the declared host is not in scope")
	}
	for _, want := range []string{"- 192.0.2.44", "changed: POST /users/{id}", "Operations the diff changed"} {
		if !strings.Contains(h.Prompt, want) {
			t.Errorf("prompt does not contain %q:\n%s", want, h.Prompt)
		}
	}
	if strings.Contains(h.Prompt, "- 10.0.0.0/24") {
		t.Errorf("prompt still advertises the un-narrowed pool:\n%s", h.Prompt)
	}
	_ = h.Close()

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if !strings.Contains(errOut.String(), "styx: diff scope: base 0123456789ab · targets 192.0.2.44") {
		t.Errorf("stderr does not report the narrowing:\n%s", errOut.String())
	}

	var row *audit.Record
	for _, rec := range readAuditRecords(t, dir) {
		if rec.Tool == "diff_scope" && rec.Params["base"] == "main" {
			found := rec
			row = &found
		}
	}
	if row == nil {
		t.Fatal("no diff_scope audit row")
	}
	targets, ok := row.Params["targets"].([]any)
	if !ok || len(targets) != 1 || targets[0] != "192.0.2.44" {
		t.Errorf("audit targets = %v, want [192.0.2.44]", row.Params["targets"])
	}
	if row.Params["base_commit"] != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("audit base commit = %v", row.Params["base_commit"])
	}
	if row.Mode != audit.ModeEngagement || row.Verdict != audit.VerdictAllow {
		t.Errorf("audit row = %s/%s, want allow in engagement mode", row.Verdict, row.Mode)
	}
}

// TestDiffScopeRefusalStopsTheRun keeps a scope flag an assurance: a change the
// harness cannot read refuses the run instead of falling back to full scope.
func TestDiffScopeRefusalStopsTheRun(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "engagement.yaml", diffEngagement)
	var out, errOut strings.Builder

	opts := headlessOptions(t, dir, fakemodel.New(), "scan", &out, &errOut)
	opts.Engagement = filepath.Join(dir, "engagement.yaml")
	opts.ScopeMode = ScopeModeDiff
	opts.DiffBase = "nope"
	opts.DiffScope = func(context.Context, diffscope.Options) (diffscope.Result, error) {
		return diffscope.Result{}, errors.New(`diff scope: base "nope": not a valid object name`)
	}

	if _, err := Build(context.Background(), opts); err == nil {
		t.Fatal("Build() = nil, want a refusal")
	} else if !strings.Contains(err.Error(), "refusing to start") || !strings.Contains(err.Error(), `base "nope"`) {
		t.Errorf("error = %v, want the base refusal named", err)
	}
}

// TestScopeOptionUsageErrors pins the flag combination the CLI also refuses
// (docs/headless-ci.md §11.2): each is a usage error, never a silently ignored
// flag.
func TestScopeOptionUsageErrors(t *testing.T) {
	allowed := Options{NonInteractive: true, Engagement: "engagement.yaml", ScopeMode: ScopeModeDiff, DiffBase: "main"}
	if err := checkScopeOptions(allowed); err != nil {
		t.Fatalf("checkScopeOptions() = %v, want nil", err)
	}

	tests := []struct {
		name string
		opts Options
	}{
		{"mode without -n", Options{Engagement: "e.yaml", ScopeMode: ScopeModeDiff, DiffBase: "main"}},
		{"mode without an engagement", Options{NonInteractive: true, ScopeMode: ScopeModeDiff, DiffBase: "main"}},
		{"mode without a base", Options{NonInteractive: true, Engagement: "e.yaml", ScopeMode: ScopeModeDiff}},
		{"unknown mode", allowed},
		{"base without mode", Options{NonInteractive: true, Engagement: "e.yaml", DiffBase: "main"}},
		{"base without -n", Options{Engagement: "e.yaml", DiffBase: "main"}},
	}
	tests[3].opts.ScopeMode = "full"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkScopeOptions(tt.opts)
			if err == nil {
				t.Fatal("checkScopeOptions() = nil, want a usage error")
			}
			if !IsUsageError(err) {
				t.Errorf("error = %v, want a usage error", err)
			}
		})
	}
}
