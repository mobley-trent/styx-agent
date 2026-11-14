package agent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/budget"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// scriptedBudget is a BudgetReader whose measurement a test controls: the
// spend is read fresh at every seam, exactly as the app's accumulator is.
type scriptedBudget struct {
	spend func() (spent, ceiling float64)
}

func (b scriptedBudget) Spend() (float64, float64) { return b.spend() }

// perTurnBudget bills a fixed amount for every model turn the fake completed,
// so a test reads spend against turn count instead of scripting the reader.
func perTurnBudget(fake *fakemodel.Fake, perTurn, ceiling float64) scriptedBudget {
	return scriptedBudget{spend: func() (float64, float64) {
		return perTurn * float64(fake.Calls()), ceiling
	}}
}

// permissiveEngine allows the tests' counting tool outright, so a call reaches
// its handler with no operator attached.
func permissiveEngine(t *testing.T, tool string) *policy.Engine {
	t.Helper()
	return mustEngine(t, policy.ModeSafe, policy.WithProjectRules([]policy.Rule{
		{Tool: tool, Action: policy.VerdictAllow, Source: "project"},
	}))
}

// The crossing turn completes, its tool calls run, and the next model call is
// refused — post-hoc accounting, so the stop reports the overshoot rather than
// hiding the soft edge (docs/budget-cap.md §4, §7).
func TestBudgetRefusesNextModelCallAfterCrossing(t *testing.T) {
	var ran int
	tool := testTool("noop", func(context.Context, map[string]any) (string, error) {
		ran++
		return "ok", nil
	})
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.Turn{
			ToolCalls: []model.ToolCall{fakemodel.Call("call-1", "noop", `{}`)},
			Usage:     &model.Usage{PromptTokens: 10},
		},
		fakemodel.Turn{
			ToolCalls: []model.ToolCall{fakemodel.Call("call-2", "noop", `{}`)},
			Usage:     &model.Usage{PromptTokens: 10},
		},
		fakemodel.Text("never asked"),
	))
	events := &collector{}
	const capUSD = 0.10

	loop := NewLoop(
		fake,
		mustRegistry(t, tool),
		permissiveEngine(t, "noop"),
		audit.NewWriter(&bytes.Buffer{}),
		testSystemPrompt,
		WithEmitter(events.emit),
		WithBudget(perTurnBudget(fake, 0.06, capUSD)),
	)

	result, err := loop.Run(context.Background(), nil, "work")
	var exhausted *ErrBudgetExhausted
	if !errors.As(err, &exhausted) {
		t.Fatalf("Run() = %v, want *ErrBudgetExhausted", err)
	}
	if exhausted.Cap != capUSD || exhausted.Turns != 2 {
		t.Errorf("stop = %+v, want the $0.10 cap crossed after 2 turns", exhausted)
	}
	if exhausted.Spent <= exhausted.Cap {
		t.Errorf("Spent = %v, want the overshoot carried above the cap", exhausted.Spent)
	}
	if got, want := err.Error(), "budget exhausted: $0.1200 of $0.1000 after 2 model turns"; got != want {
		t.Errorf("stop line = %q, want %q", got, want)
	}
	if result.Turns != 2 {
		t.Errorf("Turns = %d, want 2", result.Turns)
	}

	// The crossing turn is turn 2: its model call happened, and so did its tool
	// call. The third model call never did.
	if got := fake.Calls(); got != 2 {
		t.Errorf("model turns = %d, want 2", got)
	}
	if ran != 2 {
		t.Errorf("tool runs = %d, want both turns' calls to run", ran)
	}

	// The run reported the crossing to the session: a half warning at 60%, then
	// the exhausted level, then the `! ` error line.
	levels := make([]string, 0, 2)
	for _, ev := range events.byKind(sessions.KindBudget) {
		levels = append(levels, ev.Level)
	}
	if strings.Join(levels, ",") != "half,exhausted" {
		t.Errorf("budget events = %v, want half then exhausted", levels)
	}
	failures := events.byKind(sessions.KindError)
	if len(failures) != 1 || !strings.Contains(failures[0].Failure, "budget exhausted:") {
		t.Errorf("error events = %+v, want the budget stop line", failures)
	}

	// The model saw the half warning as transcript content, not as a prompt
	// change: the request that followed the seam still leads with the
	// byte-stable system prompt.
	requests := fake.Requests()
	if len(requests) != 2 {
		t.Fatalf("recorded requests = %d, want 2", len(requests))
	}
	if requests[1].Messages[0].Content != testSystemPrompt {
		t.Errorf("second request does not lead with the system prompt")
	}
	if !hasBudgetNote(requests[1].Messages, budgetNote(budget.LevelHalf, budget.Spend{Spent: 0.06, Cap: capUSD})) {
		t.Errorf("second request carries no half-budget note: %+v", requests[1].Messages)
	}
}

// A level is announced once per run, and re-appended at the next seam when a
// compaction has evicted the note (docs/budget-cap.md §5).
func TestBudgetNoteAnnouncedOnceAndReappended(t *testing.T) {
	events := &collector{}
	spend := scriptedBudget{spend: func() (float64, float64) { return 0.085, 0.10 }}
	loop := NewLoop(
		nil,
		mustRegistry(t, testTool("noop", func(context.Context, map[string]any) (string, error) { return "", nil })),
		mustEngine(t, policy.ModeSafe),
		nil,
		testSystemPrompt,
		WithEmitter(events.emit),
		WithBudget(spend),
	)
	messages := []model.Message{{Role: model.RoleSystem, Content: testSystemPrompt}}

	messages, err := loop.checkBudget(messages, 2)
	if err != nil {
		t.Fatalf("checkBudget() = %v", err)
	}
	if len(messages) != 2 {
		t.Fatalf("messages = %d, want the note tail-appended", len(messages))
	}
	note := messages[len(messages)-1]
	if note.Role != model.RoleSystem || !strings.HasPrefix(note.Content, budgetNotePrefix) {
		t.Fatalf("note = %+v, want a harness-authored system note", note)
	}
	if !strings.Contains(note.Content, "finish the current line of work") {
		t.Errorf("85%% of the cap did not carry the wrap-up advice: %q", note.Content)
	}
	if !strings.Contains(note.Content, "85%") || !strings.Contains(note.Content, "$0.0850") || !strings.Contains(note.Content, "$0.1000") {
		t.Errorf("note does not state the measurement: %q", note.Content)
	}
	if got := len(events.byKind(sessions.KindBudget)); got != 1 {
		t.Errorf("budget events = %d, want 1", got)
	}

	// The same seam again announces nothing new.
	again, err := loop.checkBudget(messages, 3)
	if err != nil {
		t.Fatalf("checkBudget() = %v", err)
	}
	if len(again) != len(messages) {
		t.Errorf("messages = %d, want the note announced once", len(again))
	}
	if got := len(events.byKind(sessions.KindBudget)); got != 1 {
		t.Errorf("budget events = %d, want still 1", got)
	}

	// A compaction that evicted the note gets it back at the next seam: a model
	// that lost the note also lost the instruction to wrap up.
	evicted := messages[:len(messages)-1]
	reappended, err := loop.checkBudget(evicted, 4)
	if err != nil {
		t.Fatalf("checkBudget() = %v", err)
	}
	if len(reappended) != len(evicted)+1 {
		t.Fatalf("messages = %d, want the note re-appended", len(reappended))
	}
	if got := len(events.byKind(sessions.KindBudget)); got != 2 {
		t.Errorf("budget events = %d, want the re-append recorded", got)
	}
}

// Half and wrap-up are distinct instructions (docs/budget-cap.md §5).
func TestBudgetNoteAdvice(t *testing.T) {
	half := budgetNote(budget.LevelHalf, budget.Spend{Spent: 0.05, Cap: 0.10})
	if !strings.Contains(half, "half the budget is spent") {
		t.Errorf("half note = %q, want the narrow-the-work instruction", half)
	}
	if strings.Contains(half, "stop at the ceiling") {
		t.Errorf("half note = %q, want no wrap-up instruction", half)
	}
	wrap := budgetNote(budget.LevelWrapUp, budget.Spend{Spent: 0.08, Cap: 0.10})
	if !strings.Contains(wrap, "stop at the ceiling") {
		t.Errorf("wrap-up note = %q, want the wrap-up instruction", wrap)
	}
}

// A completed turn with no usage is a turn the cap cannot price, so a budgeted
// run ends with the unmeasured refusal (docs/budget-cap.md §6). The turn's tool
// calls still run, and the refusal is on the session bus for the `! ` line.
func TestBudgetedRunStopsOnUnpricedTurn(t *testing.T) {
	var ran int
	tool := testTool("noop", func(context.Context, map[string]any) (string, error) {
		ran++
		return "ok", nil
	})
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.Turn{
			ToolCalls: []model.ToolCall{fakemodel.Call("call-1", "noop", `{}`)},
			// Usage nil: the provider omitted it.
		},
		fakemodel.Text("never asked"),
	))
	events := &collector{}

	loop := NewLoop(
		fake,
		mustRegistry(t, tool),
		permissiveEngine(t, "noop"),
		audit.NewWriter(&bytes.Buffer{}),
		testSystemPrompt,
		WithEmitter(events.emit),
		WithBudget(scriptedBudget{spend: func() (float64, float64) { return 0, 1 }}),
	)

	_, err := loop.Run(context.Background(), nil, "work")
	if !errors.Is(err, ErrUnpricedTurn) {
		t.Fatalf("Run() = %v, want ErrUnpricedTurn", err)
	}
	if got, want := ErrUnpricedTurn.Error(), "budget cannot be enforced: the provider reported no usage"; got != want {
		t.Errorf("refusal = %q, want %q", got, want)
	}
	if got := fake.Calls(); got != 1 {
		t.Errorf("model turns = %d, want the run to end after the unpriced turn", got)
	}
	if ran != 1 {
		t.Errorf("tool runs = %d, want the unpriced turn's call to run", ran)
	}
	failures := events.byKind(sessions.KindError)
	if len(failures) != 1 || !strings.Contains(failures[0].Failure, "cannot be enforced") {
		t.Errorf("error events = %+v, want the unmeasured refusal", failures)
	}
}

// An unbudgeted run is untouched: an unpriced turn does not end it and no
// budget event is emitted (docs/budget-cap.md §6, §8).
func TestUnbudgetedRunIgnoresMissingUsage(t *testing.T) {
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.Turn{ToolCalls: []model.ToolCall{fakemodel.Call("call-1", "noop", `{}`)}},
		fakemodel.Text("done"),
	))
	events := &collector{}

	loop := NewLoop(
		fake,
		mustRegistry(t, testTool("noop", func(context.Context, map[string]any) (string, error) { return "ok", nil })),
		permissiveEngine(t, "noop"),
		audit.NewWriter(&bytes.Buffer{}),
		testSystemPrompt,
		WithEmitter(events.emit),
	)

	result, err := loop.Run(context.Background(), nil, "work")
	if err != nil {
		t.Fatalf("Run() = %v, want an unbudgeted run to ignore missing usage", err)
	}
	if result.Answer != "done" || result.Turns != 2 {
		t.Errorf("result = %+v, want the normal two-turn run", result)
	}
	if got := len(events.byKind(sessions.KindBudget)); got != 0 {
		t.Errorf("budget events = %d, want none without a cap", got)
	}
}

// A cap of zero is not a ceiling: the reader enforces nothing.
func TestZeroCapNeverStops(t *testing.T) {
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Turn{
		Text:  []string{"done"},
		Usage: &model.Usage{PromptTokens: 10},
	}))
	loop := NewLoop(
		fake,
		mustRegistry(t, testTool("noop", func(context.Context, map[string]any) (string, error) { return "", nil })),
		mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&bytes.Buffer{}),
		testSystemPrompt,
		WithEmitter((&collector{}).emit),
		WithBudget(scriptedBudget{spend: func() (float64, float64) { return 5, 0 }}),
	)
	if _, err := loop.Run(context.Background(), nil, "work"); err != nil {
		t.Fatalf("Run() = %v, want a zero cap to enforce nothing", err)
	}
}
