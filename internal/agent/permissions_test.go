package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// scriptedPrompter records every permission request and answers with decide.
type scriptedPrompter struct {
	mu     sync.Mutex
	seen   []PromptRequest
	decide func(PromptRequest) Decision
}

func (p *scriptedPrompter) Prompt(_ context.Context, req PromptRequest) (Decision, error) {
	p.mu.Lock()
	p.seen = append(p.seen, req)
	p.mu.Unlock()
	if p.decide != nil {
		return p.decide(req), nil
	}
	return DecisionAllowOnce, nil
}

func (p *scriptedPrompter) requests() []PromptRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]PromptRequest(nil), p.seen...)
}

// scriptedReviewer records every diff and answers with decide.
type scriptedReviewer struct {
	mu     sync.Mutex
	seen   []DiffRequest
	decide func(DiffRequest) DiffDecision
}

func (r *scriptedReviewer) Review(_ context.Context, req DiffRequest) (DiffDecision, error) {
	r.mu.Lock()
	r.seen = append(r.seen, req)
	r.mu.Unlock()
	if r.decide != nil {
		return r.decide(req), nil
	}
	return DiffAccept, nil
}

func (r *scriptedReviewer) requests() []DiffRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]DiffRequest(nil), r.seen...)
}

// fixedPlanApprover answers every plan with one verdict.
type fixedPlanApprover struct{ approve bool }

func (a fixedPlanApprover) Approve(context.Context, Plan) (bool, error) { return a.approve, nil }

// readWorkspace reads a file this test created, keeping gosec quiet.
func readWorkspace(t *testing.T, path string) string {
	t.Helper()
	//nolint:gosec // a test-only read of a path the test itself built.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func callWrite(path, content string) model.ToolCall {
	args, _ := json.Marshal(map[string]any{"path": path, "content": content})
	return fakemodel.Call("call-"+path, "write_file", string(args))
}

func callPlan(t *testing.T, summary string, steps ...sessions.PlanStep) model.ToolCall {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"summary": summary, "steps": steps})
	if err != nil {
		t.Fatal(err)
	}
	return fakemodel.Call("call-plan", PlanToolName, string(raw))
}

func TestLoopWritePromptsRendersDiffAndApplies(t *testing.T) {
	dir := workspace(t, map[string]string{"a.txt": "one\ntwo\n"})
	prompter := &scriptedPrompter{}
	reviewer := &scriptedReviewer{}
	events := &collector{}
	var auditBuf bytes.Buffer

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(callWrite("a.txt", "one\nTWO\n")),
		fakemodel.Text("done"),
	))
	loop := NewLoop(fake, mustRegistry(t, WriteFileTool(dir)), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&auditBuf), testSystemPrompt,
		WithPrompter(prompter), WithDiffReviewer(reviewer), WithEmitter(events.emit))

	if _, err := loop.Run(context.Background(), nil, "edit a.txt"); err != nil {
		t.Fatalf("Run() = %v", err)
	}

	// The write-class verdict in safe mode is a prompt, resolved allow-once.
	records := auditRecords(t, &auditBuf)
	if len(records) != 1 || records[0].Verdict != audit.VerdictAllowOnce {
		t.Fatalf("audit records = %+v, want one allow-once for the write", records)
	}
	if got := prompter.requests(); len(got) != 1 || got[0].Tool != "write_file" {
		t.Fatalf("permission prompts = %+v, want one for write_file", got)
	}

	// The diff was rendered on the bus and reviewed before the write.
	diffs := events.byKind(sessions.KindDiff)
	if len(diffs) != 1 || diffs[0].Path != "a.txt" || diffs[0].Diff == nil || diffs[0].Diff.Empty() {
		t.Fatalf("diff events = %+v, want one non-empty diff for a.txt", diffs)
	}
	if got := reviewer.requests(); len(got) != 1 || got[0].Diff.Path != "a.txt" {
		t.Fatalf("diff reviews = %+v, want one for a.txt", got)
	}

	onDisk := readWorkspace(t, filepath.Join(dir, "a.txt"))
	if string(onDisk) != "one\nTWO\n" {
		t.Errorf("file = %q, want the accepted change applied", onDisk)
	}
}

func TestLoopWriteDeniedByPromptIsNotApplied(t *testing.T) {
	dir := workspace(t, map[string]string{"a.txt": "one\n"})
	prompter := &scriptedPrompter{decide: func(PromptRequest) Decision { return DecisionDeny }}
	reviewer := &scriptedReviewer{}
	events := &collector{}
	var auditBuf bytes.Buffer

	loop := NewLoop(
		fakemodel.New(fakemodel.WithTurns(
			fakemodel.ToolCalls(callWrite("a.txt", "changed\n")),
			fakemodel.Text("done"),
		)),
		mustRegistry(t, WriteFileTool(dir)), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&auditBuf), testSystemPrompt,
		WithPrompter(prompter), WithDiffReviewer(reviewer), WithEmitter(events.emit))

	if _, err := loop.Run(context.Background(), nil, "edit a.txt"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if got := events.byKind(sessions.KindDiff); len(got) != 0 {
		t.Errorf("diff events = %+v, want none for a denied write", got)
	}
	if got := reviewer.requests(); len(got) != 0 {
		t.Errorf("diff reviews = %+v, want none for a denied write", got)
	}
	onDisk := readWorkspace(t, filepath.Join(dir, "a.txt"))
	if string(onDisk) != "one\n" {
		t.Errorf("file = %q, want it untouched", onDisk)
	}
}

func TestLoopWriteRejectedDiffIsNotApplied(t *testing.T) {
	dir := workspace(t, map[string]string{"a.txt": "one\n"})
	reviewer := &scriptedReviewer{decide: func(DiffRequest) DiffDecision { return DiffReject }}
	events := &collector{}
	var auditBuf bytes.Buffer

	loop := NewLoop(
		fakemodel.New(fakemodel.WithTurns(
			fakemodel.ToolCalls(callWrite("a.txt", "changed\n")),
			fakemodel.Text("done"),
		)),
		mustRegistry(t, WriteFileTool(dir)), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&auditBuf), testSystemPrompt,
		WithPrompter(&scriptedPrompter{}), WithDiffReviewer(reviewer), WithEmitter(events.emit))

	if _, err := loop.Run(context.Background(), nil, "edit a.txt"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if got := events.byKind(sessions.KindDiff); len(got) != 1 {
		t.Errorf("diff events = %+v, want the rejected diff still rendered", got)
	}
	onDisk := readWorkspace(t, filepath.Join(dir, "a.txt"))
	if string(onDisk) != "one\n" {
		t.Errorf("file = %q, want the rejected change not applied", onDisk)
	}
	results := events.byKind(sessions.KindToolResult)
	if len(results) != 1 || !strings.Contains(results[0].Result, "rejected") {
		t.Errorf("tool results = %+v, want a rejection message", results)
	}
}

func TestLoopAcceptRestOfTurnSkipsLaterReviews(t *testing.T) {
	dir := workspace(t, map[string]string{"a.txt": "1\n", "b.txt": "2\n"})
	reviewer := &scriptedReviewer{decide: func(DiffRequest) DiffDecision { return DiffAcceptRest }}
	events := &collector{}

	loop := NewLoop(
		fakemodel.New(fakemodel.WithTurns(
			fakemodel.ToolCalls(callWrite("a.txt", "one\n"), callWrite("b.txt", "two\n")),
			fakemodel.Text("done"),
		)),
		mustRegistry(t, WriteFileTool(dir)), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&bytes.Buffer{}), testSystemPrompt,
		WithPrompter(&scriptedPrompter{}), WithDiffReviewer(reviewer), WithEmitter(events.emit))

	if _, err := loop.Run(context.Background(), nil, "edit both"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if got := len(reviewer.requests()); got != 1 {
		t.Errorf("diff reviews = %d, want 1 (the second diff rides the accept-rest)", got)
	}
	if got := len(events.byKind(sessions.KindDiff)); got != 2 {
		t.Errorf("diff events = %d, want 2 (both diffs rendered)", got)
	}
	for _, f := range []string{"a.txt", "b.txt"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s was not written under accept-rest: %v", f, err)
		}
	}
}

func TestLoopAllowSessionIsSessionScoped(t *testing.T) {
	dir := workspace(t, map[string]string{"a.txt": "one\n", "b.txt": "two\n"})
	prompter := &scriptedPrompter{decide: func(PromptRequest) Decision { return DecisionAllowSession }}

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(callWrite("a.txt", "ONE\n")), fakemodel.Text("done"),
		fakemodel.ToolCalls(callWrite("a.txt", "ONE\n")), fakemodel.Text("done"),
		fakemodel.ToolCalls(callWrite("b.txt", "TWO\n")), fakemodel.Text("done"),
	))
	loop := NewLoop(fake, mustRegistry(t, WriteFileTool(dir)), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&bytes.Buffer{}), testSystemPrompt, WithPrompter(prompter))

	for i := 0; i < 3; i++ {
		if _, err := loop.Run(context.Background(), nil, "edit"); err != nil {
			t.Fatalf("Run(%d) = %v", i, err)
		}
	}

	// The repeated identical call was remembered for the session; the
	// different call still prompted.
	seen := prompter.requests()
	if len(seen) != 2 {
		t.Fatalf("permission prompts = %d, want 2 (allow-session remembered a.txt)", len(seen))
	}
	if seen[0].Params["path"] != "a.txt" || seen[1].Params["path"] != "b.txt" {
		t.Errorf("prompted paths = %v/%v, want a.txt then b.txt", seen[0].Params["path"], seen[1].Params["path"])
	}

	// Session-scoped only: a fresh loop (a new session) prompts again.
	fresh := &scriptedPrompter{}
	freshLoop := NewLoop(
		fakemodel.New(fakemodel.WithTurns(fakemodel.ToolCalls(callWrite("a.txt", "AGAIN\n")), fakemodel.Text("done"))),
		mustRegistry(t, WriteFileTool(dir)), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&bytes.Buffer{}), testSystemPrompt, WithPrompter(fresh))
	if _, err := freshLoop.Run(context.Background(), nil, "edit"); err != nil {
		t.Fatalf("fresh Run() = %v", err)
	}
	if got := len(fresh.requests()); got != 1 {
		t.Errorf("fresh session prompts = %d, want 1 (session scope does not leak)", got)
	}
}

func TestLoopPlanPreAuthorizesListedActionsOnly(t *testing.T) {
	dir := workspace(t, map[string]string{"a.txt": "old\n", "b.txt": "old\n"})
	prompter := &scriptedPrompter{decide: func(PromptRequest) Decision { return DecisionDeny }}
	reviewer := &scriptedReviewer{}
	events := &collector{}
	var auditBuf bytes.Buffer

	plan := callPlan(t, "write a.txt", sessions.PlanStep{Tool: "write_file", Params: map[string]any{"path": "a.txt"}})
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(plan),
		fakemodel.ToolCalls(callWrite("a.txt", "A\n"), callWrite("b.txt", "B\n")),
		fakemodel.Text("done"),
	))
	loop := NewLoop(fake, mustRegistry(t, ProposePlanTool(), WriteFileTool(dir)), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&auditBuf), testSystemPrompt,
		WithPrompter(prompter), WithDiffReviewer(reviewer),
		WithPlanApprover(fixedPlanApprover{approve: true}), WithEmitter(events.emit))

	if _, err := loop.Run(context.Background(), nil, "refactor"); err != nil {
		t.Fatalf("Run() = %v", err)
	}

	// The plan block rendered with its step.
	plans := events.byKind(sessions.KindPlan)
	if len(plans) != 1 || len(plans[0].Steps) != 1 || plans[0].Steps[0].Tool != "write_file" {
		t.Fatalf("plan events = %+v, want one plan with the write step", plans)
	}

	// Only the unlisted action prompted; the listed one ran under allow-plan.
	seen := prompter.requests()
	if len(seen) != 1 || seen[0].Params["path"] != "b.txt" {
		t.Fatalf("permission prompts = %+v, want exactly the unlisted b.txt", seen)
	}

	verdicts := map[string]audit.Verdict{}
	for _, rec := range auditRecords(t, &auditBuf) {
		if rec.Tool != "write_file" {
			continue
		}
		path, _ := rec.Params["path"].(string)
		verdicts[path] = rec.Verdict
	}
	if verdicts["a.txt"] != audit.VerdictAllowPlan {
		t.Errorf("a.txt verdict = %q, want allow-plan", verdicts["a.txt"])
	}
	if verdicts["b.txt"] != audit.VerdictDeny {
		t.Errorf("b.txt verdict = %q, want deny", verdicts["b.txt"])
	}

	if got := readWorkspace(t, filepath.Join(dir, "a.txt")); got != "A\n" {
		t.Errorf("a.txt = %q, want the listed write applied", got)
	}
	if got := readWorkspace(t, filepath.Join(dir, "b.txt")); got != "old\n" {
		t.Errorf("b.txt = %q, want the unlisted write denied", got)
	}
}

func TestLoopPlanApprovalDoesNotBypassDenyRule(t *testing.T) {
	dir := workspace(t, map[string]string{"a.txt": "old\n"})
	prompter := &scriptedPrompter{}
	events := &collector{}
	var auditBuf bytes.Buffer

	plan := callPlan(t, "write a.txt", sessions.PlanStep{Tool: "write_file", Params: map[string]any{"path": "a.txt"}})
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(plan),
		fakemodel.ToolCalls(callWrite("a.txt", "A\n")),
		fakemodel.Text("done"),
	))
	engine := mustEngine(t, policy.ModeSafe, policy.WithProjectRules([]policy.Rule{
		{Tool: "write_file", ParamPtr: "path", Action: policy.VerdictDeny, Source: "project"},
	}))
	loop := NewLoop(fake, mustRegistry(t, ProposePlanTool(), WriteFileTool(dir)), engine,
		audit.NewWriter(&auditBuf), testSystemPrompt,
		WithPrompter(prompter), WithPlanApprover(fixedPlanApprover{approve: true}), WithEmitter(events.emit))

	if _, err := loop.Run(context.Background(), nil, "refactor"); err != nil {
		t.Fatalf("Run() = %v", err)
	}

	var writes []audit.Record
	for _, rec := range auditRecords(t, &auditBuf) {
		if rec.Tool == "write_file" {
			writes = append(writes, rec)
		}
	}
	if len(writes) != 1 || writes[0].Verdict != audit.VerdictHardDeny {
		t.Fatalf("write audit records = %+v, want a single hard-deny for the denied write", writes)
	}
	// The deny never reaches a prompt, plan approval notwithstanding.
	if got := len(prompter.requests()); got != 0 {
		t.Errorf("permission prompts = %d, want 0 for a hard deny", got)
	}
	if got := readWorkspace(t, filepath.Join(dir, "a.txt")); got != "old\n" {
		t.Errorf("a.txt = %q, want it untouched by a denied write", got)
	}
}

func TestLoopPlanRejectedLeavesPromptsInPlace(t *testing.T) {
	dir := workspace(t, map[string]string{"a.txt": "old\n"})
	prompter := &scriptedPrompter{}
	plan := callPlan(t, "write a.txt", sessions.PlanStep{Tool: "write_file"})
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(plan),
		fakemodel.ToolCalls(callWrite("a.txt", "A\n")),
		fakemodel.Text("done"),
	))
	loop := NewLoop(fake, mustRegistry(t, ProposePlanTool(), WriteFileTool(dir)), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&bytes.Buffer{}), testSystemPrompt,
		WithPrompter(prompter), WithPlanApprover(fixedPlanApprover{approve: false}))

	if _, err := loop.Run(context.Background(), nil, "refactor"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if got := len(prompter.requests()); got != 1 {
		t.Errorf("permission prompts = %d, want 1 when the plan was rejected", got)
	}
}
