package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

func TestDispatchSubagentEndToEnd(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"),
		"permissions:\n  rules:\n    - tool: dispatch_subagent\n      action: allow\n")

	fake := fakemodel.New(fakemodel.WithTurns(
		// Main loop: dispatch the coder role.
		fakemodel.ToolCalls(fakemodel.Call("d1", "dispatch_subagent", `{"role":"coder","task":"fix the build"}`)),
		// Coder run: an isolated context that just reports.
		fakemodel.Text("the coder report"),
		// Main loop: finish.
		fakemodel.Text("all done"),
	))

	h, err := Build(context.Background(), buildOptions(t, dir, fake))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if _, ok := h.Tools.Lookup("dispatch_subagent"); !ok {
		t.Fatal("the session registry has no dispatch_subagent tool")
	}

	if err := h.Submit(context.Background(), "delegate the fix"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}

	// The dispatch tool result is the subagent's report.
	var dispatchResult string
	for _, m := range h.Messages() {
		if m.Role == model.RoleTool && m.ToolCallID == "d1" {
			dispatchResult = m.Content
		}
	}
	if dispatchResult != "the coder report" {
		t.Errorf("dispatch tool result = %q, want the subagent report", dispatchResult)
	}

	// The coder run streamed its own system prompt and reduced tool set.
	requests := fake.Requests()
	if len(requests) < 2 {
		t.Fatalf("model requests = %d, want the main call and the subagent call", len(requests))
	}
	subReq := requests[1]
	if !strings.Contains(subReq.Messages[0].Content, "Role: coder") {
		t.Errorf("subagent system prompt = %q, want the coder role", subReq.Messages[0].Content)
	}
	for _, tool := range subReq.Tools {
		if tool.Name == "dispatch_subagent" {
			t.Error("the coder run received dispatch_subagent; nesting must be impossible")
		}
	}

	// The run is persisted in the session JSONL with attribution.
	events, err := h.sessions.Replay(dir, h.SessionID())
	if err != nil {
		t.Fatalf("Replay() = %v, want nil", err)
	}
	var starts, reports int
	for _, ev := range events {
		if ev.Kind != sessions.KindSubagent || ev.Subagent != "coder" {
			continue
		}
		switch ev.Detail {
		case "start":
			starts++
		case "report":
			reports++
			if ev.Text != "the coder report" {
				t.Errorf("persisted report = %q, want the subagent report", ev.Text)
			}
		}
	}
	if starts != 1 || reports != 1 {
		t.Errorf("persisted subagent events = %d start / %d report, want one each", starts, reports)
	}
}
