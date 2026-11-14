package subagent

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/agent"
	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
)

// spentBudget bills $0.05 for every model turn the fake completed against a
// $0.05 ceiling, so the nested run is priced out after its first turn.
type spentBudget struct{ fake *fakemodel.Fake }

func (b spentBudget) Spend() (float64, float64) { return 0.05 * float64(b.fake.Calls()), 0.05 }

// A subagent run inherits the session's loop options, so its own between-turns
// seam refuses its next model call at the same ceiling and the stop reaches the
// root as a failed delegation rather than a failed run
// (docs/budget-cap.md §4).
func TestRunnerInheritsBudgetAndReturnsItsStop(t *testing.T) {
	reg := fullRegistry(t, nil)
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.Turn{
			ToolCalls: []model.ToolCall{fakemodel.Call("call-1", "read_file", `{"path":"a.txt"}`)},
			Usage:     &model.Usage{PromptTokens: 10},
		},
		fakemodel.Text("never asked"),
	))
	runner := New(Config{
		Client:   fake,
		Registry: reg,
		Engine:   safeEngine(t),
		Audit:    audit.NewWriter(&bytes.Buffer{}),
		Options:  []agent.LoopOption{agent.WithBudget(spentBudget{fake: fake})},
	})

	_, err := runner.Dispatch(context.Background(), agent.DispatchRequest{Role: "coder", Task: "work"})
	if err == nil {
		t.Fatal("Dispatch() = nil, want the budget stop to end the nested run")
	}
	if !strings.Contains(err.Error(), "budget exhausted") {
		t.Errorf("Dispatch() = %v, want the budget stop named", err)
	}
	if got := fake.Calls(); got != 1 {
		t.Errorf("model turns = %d, want the nested run's next call refused", got)
	}
}
