package subagent

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/agent"
	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

const testSchema = `{"type":"object","additionalProperties":true}`

// countingTool is a minimal tool with a per-call counter.
func countingTool(name string, ran *int32) agent.Tool {
	return agent.Tool{
		Name:        name,
		Description: name,
		Parameters:  json.RawMessage(testSchema),
		Handler: func(context.Context, map[string]any) (string, error) {
			if ran != nil {
				atomic.AddInt32(ran, 1)
			}
			return "ok", nil
		},
	}
}

// fullRegistry carries every built-in tool name any preset allowlist names,
// plus the delegation tool so nesting can be proven structural.
func fullRegistry(t *testing.T, ran map[string]*int32) *agent.Registry {
	t.Helper()
	names := []string{
		"read_file", "write_file", "edit_file", "glob", "grep",
		"bash", "code_exec", "web_fetch", "ssh_logs",
		agent.DispatchSubagentToolName,
	}
	tools := make([]agent.Tool, 0, len(names))
	for _, name := range names {
		tools = append(tools, countingTool(name, ran[name]))
	}
	reg, err := agent.NewRegistry(tools...)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func engagementEngine(t *testing.T) *policy.Engine {
	t.Helper()
	engine, err := policy.NewEngine(policy.ModeEngagement)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func safeEngine(t *testing.T, opts ...policy.Option) *policy.Engine {
	t.Helper()
	engine, err := policy.NewEngine(policy.ModeSafe, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestRunnerBoundedAtTurnLimit(t *testing.T) {
	reg := fullRegistry(t, nil)
	fake := fakemodel.New(
		fakemodel.WithRepeatLast(true),
		fakemodel.WithTurns(fakemodel.ToolCalls(fakemodel.Call("c1", "read_file", `{"path":"main.go"}`))),
	)
	runner := New(Config{
		Client:   fake,
		Registry: reg,
		Engine:   safeEngine(t),
		Audit:    audit.NewWriter(&bytes.Buffer{}),
	})

	if _, err := runner.Dispatch(context.Background(), agent.DispatchRequest{Role: "coder", Task: "loop forever"}); err == nil {
		t.Fatal("Dispatch() = nil error, want the run to hit its turn bound")
	}
	if got := fake.Calls(); got != DefaultMaxTurns {
		t.Errorf("subagent model calls = %d, want the bound %d", got, DefaultMaxTurns)
	}
}

func TestRunnerToolCallsPassThePolicyEngine(t *testing.T) {
	var ran int32
	reg := fullRegistry(t, map[string]*int32{"read_file": &ran})
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "read_file", `{"path":"main.go"}`)),
		fakemodel.Text("blocked"),
	))
	var auditBuf bytes.Buffer
	engine := safeEngine(t, policy.WithProjectRules([]policy.Rule{
		{Tool: "read_file", Action: policy.VerdictDeny, Source: "project"},
	}))
	runner := New(Config{
		Client:   fake,
		Registry: reg,
		Engine:   engine,
		Audit:    audit.NewWriter(&auditBuf),
	})

	if _, err := runner.Dispatch(context.Background(), agent.DispatchRequest{Role: "coder", Task: "read it"}); err != nil {
		t.Fatalf("Dispatch() = %v, want nil", err)
	}
	if atomic.LoadInt32(&ran) != 0 {
		t.Error("the subagent tool ran despite the policy deny")
	}
	if !strings.Contains(auditBuf.String(), `"verdict":"hard-deny"`) {
		t.Errorf("audit trail = %s, want the denial recorded", auditBuf.String())
	}
	if !strings.Contains(auditBuf.String(), `"subagent":"coder"`) {
		t.Errorf("audit trail = %s, want the call attributed to the coder subagent", auditBuf.String())
	}
}

func TestRunnerRejectsNestingStructurally(t *testing.T) {
	reg := fullRegistry(t, nil)
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.Text("done"),
	))
	runner := New(Config{
		Client:   fake,
		Registry: reg,
		Engine:   safeEngine(t),
		Audit:    audit.NewWriter(&bytes.Buffer{}),
	})

	if _, err := runner.Dispatch(context.Background(), agent.DispatchRequest{Role: "coder", Task: "work"}); err != nil {
		t.Fatalf("Dispatch() = %v, want nil", err)
	}
	reqs := fake.Requests()
	if len(reqs) == 0 {
		t.Fatal("the subagent made no model request")
	}
	for _, tool := range reqs[0].Tools {
		if tool.Name == agent.DispatchSubagentToolName {
			t.Fatalf("the subagent received %s; nesting must be structurally impossible", agent.DispatchSubagentToolName)
		}
	}
}

func TestRunnerExploitDevIsEngagementGated(t *testing.T) {
	reg := fullRegistry(t, nil)
	fake := fakemodel.New()
	runner := New(Config{
		Client:   fake,
		Registry: reg,
		Engine:   safeEngine(t),
		Audit:    audit.NewWriter(&bytes.Buffer{}),
	})

	_, err := runner.Dispatch(context.Background(), agent.DispatchRequest{Role: "exploit-dev", Task: "exploit"})
	if err == nil {
		t.Fatal("Dispatch(exploit-dev in safe mode) = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "engagement-gated") {
		t.Errorf("error = %v, want it to name the engagement gate", err)
	}
	if fake.Calls() != 0 {
		t.Errorf("model calls = %d, want the gated run to never start", fake.Calls())
	}
}

func TestRunnerExploitDevHonorsROE(t *testing.T) {
	reg := fullRegistry(t, nil)

	forbidden := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("done")))
	blocked := New(Config{
		Client:         forbidden,
		Registry:       reg,
		Engine:         engagementEngine(t),
		Audit:          audit.NewWriter(&bytes.Buffer{}),
		ExploitAllowed: func() bool { return false },
	})
	if _, err := blocked.Dispatch(context.Background(), agent.DispatchRequest{Role: "exploit-dev", Task: "exploit"}); err == nil {
		t.Fatal("Dispatch(exploit_allowed=false) = nil error, want a refusal")
	}
	if forbidden.Calls() != 0 {
		t.Errorf("model calls = %d, want the refused run to never start", forbidden.Calls())
	}

	allowed := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("done")))
	runner := New(Config{
		Client:         allowed,
		Registry:       reg,
		Engine:         engagementEngine(t),
		Audit:          audit.NewWriter(&bytes.Buffer{}),
		ExploitAllowed: func() bool { return true },
	})
	if _, err := runner.Dispatch(context.Background(), agent.DispatchRequest{Role: "exploit-dev", Task: "exploit"}); err != nil {
		t.Fatalf("Dispatch(exploit_allowed=true) = %v, want nil", err)
	}
	if allowed.Calls() == 0 {
		t.Error("the allowed exploit-dev run never reached the model")
	}
}

func TestRunnerEmitsLifecycleEvents(t *testing.T) {
	reg := fullRegistry(t, nil)
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("the report")))
	var events []sessions.Event
	runner := New(Config{
		Client:   fake,
		Registry: reg,
		Engine:   safeEngine(t),
		Audit:    audit.NewWriter(&bytes.Buffer{}),
		Emit:     func(ev sessions.Event) { events = append(events, ev) },
	})

	report, err := runner.Dispatch(context.Background(), agent.DispatchRequest{Role: "coder", Task: "do it"})
	if err != nil {
		t.Fatalf("Dispatch() = %v, want nil", err)
	}
	if report != "the report" {
		t.Errorf("report = %q, want the run's final answer", report)
	}
	var starts, reports int
	var startRun, reportRun string
	for _, ev := range events {
		if ev.Kind != sessions.KindSubagent || ev.Subagent != "coder" {
			continue
		}
		if ev.RunID == "" {
			t.Error("lifecycle event carries no run id")
		}
		switch ev.Detail {
		case DetailStart:
			starts++
			startRun = ev.RunID
			if ev.Text != "do it" {
				t.Errorf("start event text = %q, want the task", ev.Text)
			}
		case DetailReport:
			reports++
			reportRun = ev.RunID
			if ev.Text != "the report" {
				t.Errorf("report event text = %q, want the report", ev.Text)
			}
		}
	}
	if starts != 1 || reports != 1 {
		t.Errorf("lifecycle events = %d start / %d report, want one each", starts, reports)
	}
	if startRun == "" || startRun != reportRun {
		t.Errorf("run ids = start %q / report %q, want the same non-empty id", startRun, reportRun)
	}
}

func TestRunnerRunIDsAreUnique(t *testing.T) {
	reg := fullRegistry(t, nil)
	fake := fakemodel.New(fakemodel.WithRepeatLast(true), fakemodel.WithTurns(fakemodel.Text("done")))
	var runs []string
	runner := New(Config{
		Client:   fake,
		Registry: reg,
		Engine:   safeEngine(t),
		Audit:    audit.NewWriter(&bytes.Buffer{}),
		Emit: func(ev sessions.Event) {
			if ev.Kind == sessions.KindSubagent && ev.Detail == DetailStart {
				runs = append(runs, ev.RunID)
			}
		},
	})
	for i := 0; i < 3; i++ {
		if _, err := runner.Dispatch(context.Background(), agent.DispatchRequest{Role: "coder", Task: "work"}); err != nil {
			t.Fatalf("Dispatch() = %v, want nil", err)
		}
	}
	seen := map[string]bool{}
	for _, id := range runs {
		if id == "" || seen[id] {
			t.Errorf("run id %q is empty or repeated", id)
		}
		seen[id] = true
	}
}

func TestRunnerUnknownRole(t *testing.T) {
	runner := New(Config{
		Client:   fakemodel.New(),
		Registry: fullRegistry(t, nil),
		Engine:   safeEngine(t),
	})
	if _, err := runner.Dispatch(context.Background(), agent.DispatchRequest{Role: "nope", Task: "x"}); err == nil {
		t.Fatal("Dispatch(unknown role) = nil error, want an error")
	}
}
