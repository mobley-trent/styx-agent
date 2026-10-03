package agent

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// recordingDispatcher captures the dispatch request.
type recordingDispatcher struct {
	got    DispatchRequest
	report string
	err    error
}

func (d *recordingDispatcher) Dispatch(_ context.Context, req DispatchRequest) (string, error) {
	d.got = req
	return d.report, d.err
}

func TestDispatchSubagentToolDelegates(t *testing.T) {
	d := &recordingDispatcher{report: "the report"}
	tool := DispatchSubagentTool(d)
	if tool.Name != DispatchSubagentToolName {
		t.Fatalf("tool name = %q, want %q", tool.Name, DispatchSubagentToolName)
	}

	got, err := tool.Handler(context.Background(), map[string]any{"role": "coder", "task": "do it"})
	if err != nil {
		t.Fatalf("Handler() = %v, want nil", err)
	}
	if got != "the report" {
		t.Errorf("result = %q, want the dispatcher's report", got)
	}
	if d.got.Role != "coder" || d.got.Task != "do it" {
		t.Errorf("dispatch request = %+v, want coder/do it", d.got)
	}
}

func TestDispatchSubagentToolWithoutDispatcher(t *testing.T) {
	tool := DispatchSubagentTool(nil)
	if _, err := tool.Handler(context.Background(), map[string]any{"role": "coder", "task": "x"}); err == nil {
		t.Fatal("Handler(no dispatcher) = nil error, want an error")
	}
}

func TestRegistrySubset(t *testing.T) {
	ok := func(context.Context, map[string]any) (string, error) { return "ok", nil }
	reg := mustRegistry(t, testTool("a", ok), testTool("b", ok), testTool("c", ok))
	sub, err := reg.Subset("c", "a")
	if err != nil {
		t.Fatalf("Subset() = %v, want nil", err)
	}
	if names := sub.Names(); len(names) != 2 || names[0] != "c" || names[1] != "a" {
		t.Errorf("subset names = %v, want the requested order [c a]", names)
	}
	if _, err := reg.Subset("missing"); err == nil {
		t.Error("Subset(unknown) = nil error, want an error")
	}
}

// capturingPrompter records the request and denies.
type capturingPrompter struct{ got PromptRequest }

func (p *capturingPrompter) Prompt(_ context.Context, req PromptRequest) (Decision, error) {
	p.got = req
	return DecisionDeny, nil
}

func TestLoopAttributesSubagentActivity(t *testing.T) {
	ran := errors.New("the tool must not run")
	tool := testTool("risky", func(context.Context, map[string]any) (string, error) { return "", ran })
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "risky", `{}`)),
		fakemodel.Text("done"),
	))
	prompter := &capturingPrompter{}
	var auditBuf bytes.Buffer
	events := &collector{}

	loop := NewLoop(fake, mustRegistry(t, tool), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&auditBuf), testSystemPrompt,
		WithSubagent("recon"), WithPrompter(prompter), WithEmitter(events.emit))

	if _, err := loop.Run(context.Background(), nil, "scan"); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}

	if prompter.got.Subagent != "recon" {
		t.Errorf("prompt subagent = %q, want recon", prompter.got.Subagent)
	}
	for _, ev := range events.events {
		if ev.Kind == sessions.KindToolCall && ev.Subagent != "recon" {
			t.Errorf("tool_call event subagent = %q, want recon", ev.Subagent)
		}
	}
	records := auditRecords(t, &auditBuf)
	if len(records) != 1 || records[0].Subagent != "recon" {
		t.Errorf("audit records = %+v, want one attributed to recon", records)
	}
}
