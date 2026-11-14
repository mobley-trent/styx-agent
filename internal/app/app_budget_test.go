package app

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/agent"
	"github.com/mobley-trent/styx-agent/internal/findingsexport"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// budgetTurn is one model turn at a known dollar cost: at deepseek-flash's
// published peak rates, 1,000,000 prompt tokens bill $0.30 at peak and half
// that off-peak, which is where the harness's pinned test clock sits.
func budgetTurn(promptTokens int, calls ...model.ToolCall) fakemodel.Turn {
	return fakemodel.Turn{
		ToolCalls: calls,
		Usage:     &model.Usage{PromptTokens: promptTokens},
	}
}

// A model with no configured rate has no price to bill, so a budgeted run
// refuses to start with the model and the three keys named, and the refusal is
// a broken run (exit 1) rather than a usage error (docs/budget-cap.md §2.1).
func TestBudgetRefusesUnpricedModel(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"), `model: local-llama
models:
  - id: local-llama
    context_window: 8192
`)
	var out, errOut strings.Builder
	opts := headlessOptions(t, dir, fakemodel.New(fakemodel.WithTurns(fakemodel.Text("hi"))), "work", &out, &errOut)
	opts.MaxBudget = 0.50

	_, err := Build(context.Background(), opts)
	if err == nil {
		t.Fatal("Build() = nil, want the unpriced-model refusal")
	}
	for _, want := range []string{`"local-llama"`, "input_per_million", "output_per_million", "cache_hit_per_million"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal = %q, want it to name %s", err.Error(), want)
		}
	}
	var usage UsageError
	if errors.As(err, &usage) {
		t.Errorf("refusal = %v, want a broken run (1), not a usage error (2)", err)
	}

	// The same unpriced model runs fine when no cap was asked for: the refusal
	// belongs to the budget, not to the model.
	opts.MaxBudget = 0
	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() without a cap = %v, want the unpriced model to run unbudgeted", err)
	}
	_ = h.Close()
}

// A budget stop is a broken run: exit 1 through the generic error path, the
// gate never consulted, the export still written, and the stop line carrying
// the overshoot (docs/budget-cap.md §7).
func TestHeadlessBudgetStopIsBrokenAndWritesExport(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "ok\n")
	outDir := filepath.Join(dir, "reports")
	fake := fakemodel.New(fakemodel.WithTurns(
		budgetTurn(1_000_000, fakemodel.Call("call-1", "read_file", `{"path":"a.txt"}`)),
		fakemodel.Text("never asked"),
	))
	var out, errOut strings.Builder

	opts := headlessOptions(t, dir, fake, "scan", &out, &errOut)
	opts.MaxBudget = 0.01
	opts.OutDir = outDir
	// A gate that would fail this run if it were consulted: no findings reach
	// it, but the point is that a budget stop never asks.
	opts.FailOn = "info"

	err := Run(context.Background(), opts)
	var exhausted *agent.ErrBudgetExhausted
	if !errors.As(err, &exhausted) {
		t.Fatalf("Run() = %v, want *agent.ErrBudgetExhausted", err)
	}
	if _, ok := VerdictCode(err); ok {
		t.Errorf("VerdictCode() reported a verdict for a broken run")
	}
	if fake.Calls() != 1 {
		t.Errorf("model turns = %d, want the next call refused", fake.Calls())
	}

	transcript := errOut.String()
	for _, want := range []string{
		"styx: budget cap $0.0100",
		"! budget exhausted: $0.1500 of $0.0100 after 1 model turn",
		"styx: done — 1 turn",
		"styx: usage 1,000,000 tokens · $0.1500 of $0.0100",
	} {
		if !strings.Contains(transcript, want) {
			t.Errorf("stderr does not contain %q:\n%s", want, transcript)
		}
	}
	if strings.Contains(transcript, "gate failed") {
		t.Errorf("the gate was consulted on a budget stop:\n%s", transcript)
	}

	// A scan that ran out of money still observed what it observed.
	if _, err := os.Stat(filepath.Join(outDir, findingsexport.JSONName)); err != nil {
		t.Errorf("the findings export was not written on a budget stop: %v", err)
	}
}

// The measurement reaches the session log and the model's context: a half
// warning is tail-appended before the crossing turn, and the spend curve is
// reconstructable from the JSONL (docs/budget-cap.md §5, §9).
func TestBudgetWarningReachesModelAndSessionLog(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "ok\n")
	// 400k prompt tokens cost $0.06 off-peak: 60% of a $0.10 cap, then 120%
	// after the second turn.
	fake := fakemodel.New(fakemodel.WithTurns(
		budgetTurn(400_000, fakemodel.Call("call-1", "read_file", `{"path":"a.txt"}`)),
		budgetTurn(400_000, fakemodel.Call("call-2", "read_file", `{"path":"a.txt"}`)),
		fakemodel.Text("never asked"),
	))
	var out, errOut strings.Builder
	opts := headlessOptions(t, dir, fake, "scan", &out, &errOut)
	opts.MaxBudget = 0.10

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	_, runErr := h.SubmitResult(context.Background(), "scan")
	var exhausted *agent.ErrBudgetExhausted
	if !errors.As(runErr, &exhausted) {
		t.Fatalf("SubmitResult() = %v, want *agent.ErrBudgetExhausted", runErr)
	}
	if exhausted.Turns != 2 {
		t.Errorf("turns = %d, want 2", exhausted.Turns)
	}
	if math.Abs(exhausted.Spent-0.12) > 1e-9 || exhausted.Cap != 0.10 {
		t.Errorf("stop = %+v, want $0.12 of $0.10", exhausted)
	}

	// The model was told, as transcript content: the request after the 60%
	// seam carries the note.
	requests := fake.Requests()
	if len(requests) != 2 {
		t.Fatalf("model turns = %d, want 2", len(requests))
	}
	var noted bool
	for _, m := range requests[1].Messages {
		if strings.HasPrefix(m.Content, "[budget]") && strings.Contains(m.Content, "half the budget is spent") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("the model never saw the half-budget note: %+v", requests[1].Messages)
	}

	// The session log carries both levels, so the spend curve survives the run.
	events, err := h.sessions.Replay(dir, h.SessionID())
	if err != nil {
		t.Fatalf("Replay() = %v", err)
	}
	var levels []string
	for _, ev := range events {
		if ev.Kind == sessions.KindBudget {
			levels = append(levels, ev.Level)
			if ev.Cap != 0.10 || ev.Spent <= 0 {
				t.Errorf("budget event = %+v, want the measured spend and cap", ev)
			}
		}
	}
	if strings.Join(levels, ",") != "half,exhausted" {
		t.Errorf("persisted budget levels = %v, want half then exhausted", levels)
	}
}
