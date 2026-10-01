package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/model/repair"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

const (
	testSystemPrompt = "SYSTEM PROMPT\n"
	anySchema        = `{"type":"object","properties":{},"additionalProperties":true}`
)

// collector is an event-bus sink that records every event.
type collector struct {
	mu     sync.Mutex
	events []sessions.Event
}

func (c *collector) emit(ev sessions.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *collector) byKind(k sessions.Kind) []sessions.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []sessions.Event
	for _, ev := range c.events {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

// auditRecords decodes what a writer captured.
func auditRecords(t *testing.T, buf *bytes.Buffer) []audit.Record {
	t.Helper()
	var records []audit.Record
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec audit.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}

// testTool is a minimal tool with a counting handler.
func testTool(name string, handler Handler) Tool {
	return Tool{Name: name, Description: name, Parameters: json.RawMessage(anySchema), Handler: handler}
}

// workspace writes files into a temp directory and returns its path.
func workspace(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mustRegistry(t *testing.T, tools ...Tool) *Registry {
	t.Helper()
	reg, err := NewRegistry(tools...)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func mustEngine(t *testing.T, mode policy.Mode, opts ...policy.Option) *policy.Engine {
	t.Helper()
	engine, err := policy.NewEngine(mode, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestLoopReadsFileAndAnswers(t *testing.T) {
	dir := workspace(t, map[string]string{"main.go": "package main\n"})
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "read_file", `{"path":"main.go"}`)),
		fakemodel.Text("It prints usage."),
	))

	var auditBuf bytes.Buffer
	auditWriter := audit.NewWriter(&auditBuf)
	events := &collector{}

	loop := NewLoop(
		fake,
		mustRegistry(t, ReadFileTool(dir)),
		mustEngine(t, policy.ModeSafe),
		auditWriter,
		testSystemPrompt,
		WithEmitter(events.emit),
	)

	result, err := loop.Run(context.Background(), nil, "what does main.go do?")
	if err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
	if result.Answer != "It prints usage." {
		t.Errorf("Answer = %q, want %q", result.Answer, "It prints usage.")
	}
	if result.Turns != 2 {
		t.Errorf("Turns = %d, want 2", result.Turns)
	}

	// System-prompt assembly: every request leads with the byte-stable
	// prefix, and the tool descriptors ride along.
	requests := fake.Requests()
	if len(requests) != 2 {
		t.Fatalf("model turns = %d, want 2", len(requests))
	}
	for i, req := range requests {
		if req.Messages[0].Role != model.RoleSystem || req.Messages[0].Content != testSystemPrompt {
			t.Errorf("request %d does not lead with the system prompt: %+v", i, req.Messages[0])
		}
		if len(req.Tools) != 1 || req.Tools[0].Name != "read_file" {
			t.Errorf("request %d tools = %+v, want read_file", i, req.Tools)
		}
	}

	// Tool dispatch through the full normative order: the result came back to
	// the model as a tool message.
	second := requests[1].Messages
	last := second[len(second)-1]
	if last.Role != model.RoleTool || last.ToolCallID != "call-1" || last.Content != "package main\n" {
		t.Errorf("tool result message = %+v, want the file contents", last)
	}

	// One audit entry, allow, with the verbatim params.
	records := auditRecords(t, &auditBuf)
	if len(records) != 1 {
		t.Fatalf("audit records = %d, want 1", len(records))
	}
	if records[0].Tool != "read_file" || records[0].Verdict != audit.VerdictAllow {
		t.Errorf("audit record = %+v, want read_file/allow", records[0])
	}
	if got := records[0].Params["path"]; got != "main.go" {
		t.Errorf("audit params path = %v, want main.go", got)
	}
	if records[0].Mode != audit.ModeSafe {
		t.Errorf("audit mode = %q, want safe", records[0].Mode)
	}

	// The session event bus saw the call and its result.
	calls := events.byKind(sessions.KindToolCall)
	results := events.byKind(sessions.KindToolResult)
	if len(calls) != 1 || calls[0].Verdict != string(audit.VerdictAllow) {
		t.Errorf("tool_call events = %+v, want one allow", calls)
	}
	if len(results) != 1 || results[0].Result != "package main\n" {
		t.Errorf("tool_result events = %+v, want the file contents", results)
	}
	if deltas := events.byKind(sessions.KindTextDelta); len(deltas) != 1 {
		t.Errorf("text deltas = %d, want 1", len(deltas))
	}
}

func TestLoopFailsClosedWhenAuditWriteFails(t *testing.T) {
	var ran int32
	tool := testTool("read_file", func(context.Context, map[string]any) (string, error) {
		atomic.AddInt32(&ran, 1)
		return "should not run", nil
	})
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "read_file", `{"path":"main.go"}`)),
		fakemodel.Text("understood"),
	))

	loop := NewLoop(fake, mustRegistry(t, tool), mustEngine(t, policy.ModeSafe), failingAudit{}, testSystemPrompt)

	_, err := loop.Run(context.Background(), nil, "read it")
	if err != nil {
		t.Fatalf("Run() = %v, want nil (the failure is a denied call, not a loop error)", err)
	}
	if atomic.LoadInt32(&ran) != 0 {
		t.Error("the tool ran despite the audit write failing: fail-closed is broken")
	}

	requests := fake.Requests()
	if len(requests) < 2 {
		t.Fatalf("model turns = %d, want 2", len(requests))
	}
	messages := requests[1].Messages
	last := messages[len(messages)-1]
	if last.Role != model.RoleTool || !strings.Contains(last.Content, "audit") {
		t.Errorf("tool result = %+v, want a fail-closed denial mentioning the audit trail", last)
	}
}

func TestLoopTurnCapEnforced(t *testing.T) {
	dir := workspace(t, map[string]string{"main.go": "package main\n"})
	fake := fakemodel.New(
		fakemodel.WithRepeatLast(true),
		fakemodel.WithTurns(fakemodel.ToolCalls(fakemodel.Call("call-1", "read_file", `{"path":"main.go"}`))),
	)
	loop := NewLoop(fake, mustRegistry(t, ReadFileTool(dir)), mustEngine(t, policy.ModeSafe), audit.NewWriter(&bytes.Buffer{}), testSystemPrompt)

	result, err := loop.Run(context.Background(), nil, "loop forever")
	if !errors.Is(err, ErrTurnCap) {
		t.Fatalf("Run() = %v, want ErrTurnCap", err)
	}
	if result.Turns != DefaultMaxTurns {
		t.Errorf("Turns = %d, want %d", result.Turns, DefaultMaxTurns)
	}
	if got := fake.Calls(); got != DefaultMaxTurns {
		t.Errorf("model calls = %d, want %d", got, DefaultMaxTurns)
	}
	if DefaultMaxTurns != 200 {
		t.Errorf("DefaultMaxTurns = %d, want the spec's 200", DefaultMaxTurns)
	}
}

func TestLoopParallelDispatchCap(t *testing.T) {
	var inFlight, peak int32
	tool := testTool("spin", func(context.Context, map[string]any) (string, error) {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			peakNow := atomic.LoadInt32(&peak)
			if cur <= peakNow || atomic.CompareAndSwapInt32(&peak, peakNow, cur) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		return "ok", nil
	})

	const calls = 12
	var turn fakemodel.Turn
	for i := 0; i < calls; i++ {
		turn.ToolCalls = append(turn.ToolCalls, fakemodel.Call(fmt.Sprintf("call-%d", i), "spin", `{}`))
	}
	fake := fakemodel.New(fakemodel.WithTurns(turn, fakemodel.Text("done")))
	engine := mustEngine(t, policy.ModeSafe, policy.WithProjectRules([]policy.Rule{
		{Tool: "spin", Action: policy.VerdictAllow, Source: "project"},
	}))
	loop := NewLoop(fake, mustRegistry(t, tool), engine, audit.NewWriter(&bytes.Buffer{}), testSystemPrompt)

	if _, err := loop.Run(context.Background(), nil, "go"); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
	if got := atomic.LoadInt32(&peak); got > DefaultMaxParallel {
		t.Errorf("peak concurrency = %d, want at most %d", got, DefaultMaxParallel)
	}
	if got := atomic.LoadInt32(&peak); got < 2 {
		t.Errorf("peak concurrency = %d, want the dispatch cap to actually parallelize", got)
	}
	if DefaultMaxParallel != 8 {
		t.Errorf("DefaultMaxParallel = %d, want the spec's 8", DefaultMaxParallel)
	}
}

func TestLoopHardDenyIsNotExecuted(t *testing.T) {
	dir := workspace(t, map[string]string{"main.go": "package main\n"})
	var ran int32
	tool := ReadFileTool(dir)
	inner := tool.Handler
	tool.Handler = func(ctx context.Context, args map[string]any) (string, error) {
		atomic.AddInt32(&ran, 1)
		return inner(ctx, args)
	}

	var auditBuf bytes.Buffer
	engine := mustEngine(t, policy.ModeSafe, policy.WithProjectRules([]policy.Rule{
		{Tool: "read_file", Action: policy.VerdictDeny, Source: "project"},
	}))
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "read_file", `{"path":"main.go"}`)),
		fakemodel.Text("cannot read it"),
	))
	loop := NewLoop(fake, mustRegistry(t, tool), engine, audit.NewWriter(&auditBuf), testSystemPrompt)

	if _, err := loop.Run(context.Background(), nil, "read it"); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
	if atomic.LoadInt32(&ran) != 0 {
		t.Error("a hard-denied tool executed")
	}
	records := auditRecords(t, &auditBuf)
	if len(records) != 1 || records[0].Verdict != audit.VerdictHardDeny {
		t.Fatalf("audit records = %+v, want one hard-deny", records)
	}
	messages := fake.Requests()[1].Messages
	last := messages[len(messages)-1]
	if !strings.Contains(last.Content, "denied") {
		t.Errorf("tool result = %q, want a denial explanation", last.Content)
	}
}

// oncePrompter answers every prompt with one fixed decision.
type oncePrompter struct{ decision Decision }

func (p oncePrompter) Prompt(context.Context, PromptRequest) (Decision, error) {
	return p.decision, nil
}

func TestLoopPromptVerdictResolved(t *testing.T) {
	for _, tc := range []struct {
		name        string
		decision    Decision
		wantVerdict audit.Verdict
		wantRan     bool
	}{
		{name: "allow once", decision: DecisionAllowOnce, wantVerdict: audit.VerdictAllowOnce, wantRan: true},
		{name: "allow session", decision: DecisionAllowSession, wantVerdict: audit.VerdictAllowSession, wantRan: true},
		{name: "deny", decision: DecisionDeny, wantVerdict: audit.VerdictDeny, wantRan: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ran int32
			tool := testTool("risky", func(context.Context, map[string]any) (string, error) {
				atomic.AddInt32(&ran, 1)
				return "did it", nil
			})
			fake := fakemodel.New(fakemodel.WithTurns(
				fakemodel.ToolCalls(fakemodel.Call("call-1", "risky", `{}`)),
				fakemodel.Text("ok"),
			))
			var auditBuf bytes.Buffer
			loop := NewLoop(fake, mustRegistry(t, tool), mustEngine(t, policy.ModeSafe),
				audit.NewWriter(&auditBuf), testSystemPrompt,
				WithPrompter(oncePrompter{decision: tc.decision}))

			if _, err := loop.Run(context.Background(), nil, "go"); err != nil {
				t.Fatalf("Run() = %v, want nil", err)
			}
			if got := atomic.LoadInt32(&ran) == 1; got != tc.wantRan {
				t.Errorf("tool ran = %v, want %v", got, tc.wantRan)
			}
			records := auditRecords(t, &auditBuf)
			if len(records) != 1 || records[0].Verdict != tc.wantVerdict {
				t.Fatalf("audit records = %+v, want one %s", records, tc.wantVerdict)
			}
		})
	}
}

func TestLoopRepairBudgetAbortsTurn(t *testing.T) {
	dir := workspace(t, map[string]string{"main.go": "package main\n"})
	bad := fakemodel.ToolCalls(fakemodel.Call("call-1", "read_file", `{"nope":true}`))
	fake := fakemodel.New(fakemodel.WithTurns(bad, bad, bad, bad))
	loop := NewLoop(fake, mustRegistry(t, ReadFileTool(dir)), mustEngine(t, policy.ModeSafe), audit.NewWriter(&bytes.Buffer{}), testSystemPrompt)

	result, err := loop.Run(context.Background(), nil, "read it")
	if !errors.Is(err, repair.ErrTurnAborted) {
		t.Fatalf("Run() = %v, want ErrTurnAborted", err)
	}
	// Two repairs are fed back, the third call aborts the run.
	if got := fake.Calls(); got != DefaultMaxRepairs+1 {
		t.Errorf("model calls = %d, want %d", got, DefaultMaxRepairs+1)
	}
	// The aborting call still gets a result, so the conversation never keeps
	// an assistant turn whose tool calls went unanswered.
	messages := result.Messages
	if len(messages) == 0 {
		t.Fatal("the aborted turn produced no messages")
	}
	last := messages[len(messages)-1]
	if last.Role != model.RoleTool || !strings.Contains(last.Content, "not executed") {
		t.Errorf("aborting call result = %+v, want a tool message explaining the abort", last)
	}
	answered := make(map[string]bool)
	for _, m := range messages {
		if m.Role == model.RoleTool {
			answered[m.ToolCallID] = true
		}
	}
	for _, m := range messages {
		for _, call := range m.ToolCalls {
			if !answered[call.ID] {
				t.Errorf("tool call %s was left unanswered", call.ID)
			}
		}
	}
}

func TestLoopAbortResolvesUnexecutedCalls(t *testing.T) {
	dir := workspace(t, map[string]string{"main.go": "package main\n"})
	bad := fakemodel.ToolCalls(fakemodel.Call("bad", "read_file", `{"nope":true}`))
	fake := fakemodel.New(fakemodel.WithTurns(
		bad,
		bad,
		fakemodel.ToolCalls(
			fakemodel.Call("good", "read_file", `{"path":"main.go"}`),
			fakemodel.Call("bad", "read_file", `{"nope":true}`),
		),
	))
	loop := NewLoop(fake, mustRegistry(t, ReadFileTool(dir)), mustEngine(t, policy.ModeSafe), audit.NewWriter(&bytes.Buffer{}), testSystemPrompt)

	result, err := loop.Run(context.Background(), nil, "read it")
	if !errors.Is(err, repair.ErrTurnAborted) {
		t.Fatalf("Run() = %v, want ErrTurnAborted", err)
	}

	answered := make(map[string]string)
	for _, m := range result.Messages {
		if m.Role == model.RoleTool {
			answered[m.ToolCallID] = m.Content
		}
	}
	for _, id := range []string{"good", "bad"} {
		if answered[id] == "" {
			t.Errorf("tool call %q has no result: %+v", id, result.Messages)
		}
	}
	if !strings.Contains(answered["good"], "aborted") {
		t.Errorf("unexecuted call result = %q, want it to explain the abort", answered["good"])
	}
}

func TestLoopRepairFeedbackReachesTheModel(t *testing.T) {
	dir := workspace(t, map[string]string{"main.go": "package main\n"})
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "read_file", `{"nope":true}`)),
		fakemodel.Text("sorry"),
	))
	loop := NewLoop(fake, mustRegistry(t, ReadFileTool(dir)), mustEngine(t, policy.ModeSafe), audit.NewWriter(&bytes.Buffer{}), testSystemPrompt)

	if _, err := loop.Run(context.Background(), nil, "read it"); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
	messages := fake.Requests()[1].Messages
	last := messages[len(messages)-1]
	if last.Role != model.RoleTool || !strings.Contains(last.Content, "invalid arguments") {
		t.Errorf("repair feedback = %+v, want a structured validation error", last)
	}
}

func TestLoopTruncatesToolOutput(t *testing.T) {
	long := strings.Repeat("x", 5000)
	dir := workspace(t, map[string]string{"big.txt": long})
	var result *Result
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "read_file", `{"path":"big.txt"}`)),
		fakemodel.Text("done"),
	))
	events := &collector{}
	loop := NewLoop(fake, mustRegistry(t, ReadFileTool(dir)), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&bytes.Buffer{}), testSystemPrompt,
		WithMaxToolOutput(100), WithEmitter(events.emit))

	got, err := loop.Run(context.Background(), nil, "read it")
	if err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
	result = &got
	if len(result.Messages) == 0 {
		t.Fatal("no messages returned")
	}

	results := events.byKind(sessions.KindToolResult)
	if len(results) != 1 {
		t.Fatalf("tool results = %d, want 1", len(results))
	}
	if !results[0].Truncated {
		t.Error("the result was not flagged truncated")
	}
	if !strings.Contains(results[0].Result, "truncated") {
		t.Errorf("truncated result lacks a marker: %q", results[0].Result)
	}
	if len(results[0].Result) > 200 {
		t.Errorf("truncated result is %d bytes, want it near the 100-byte cap", len(results[0].Result))
	}
	// The model sees exactly what the session recorded.
	messages := fake.Requests()[1].Messages
	last := messages[len(messages)-1]
	if last.Content != results[0].Result {
		t.Errorf("model saw a different result than the session bus recorded")
	}
}

// failingAudit is the fail-closed writer: every append fails.
type failingAudit struct{}

func (failingAudit) Append(audit.Record) error { return errors.New("disk on fire") }

func TestTruncateOutputKeepsFirstLine(t *testing.T) {
	body := "first line summary\nsecond line that is quite long and will be cut\nthird"
	got, truncated := truncateOutput(body, 30)
	if !truncated {
		t.Fatal("truncateOutput did not report truncation")
	}
	if !strings.HasPrefix(got, "first line summary\n") {
		t.Errorf("truncated output = %q, want the first line preserved", got)
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("truncated output = %q, want a marker", got)
	}
	if short, cut := truncateOutput("short", 30); cut || short != "short" {
		t.Errorf("truncateOutput(short) = %q/%v, want it untouched", short, cut)
	}

	// A single long line still gets its marker on its own line.
	single, _ := truncateOutput(strings.Repeat("y", 400), 50)
	if !strings.Contains(single, "\n[agent: output truncated") {
		t.Errorf("single-line truncation = %q, want the marker on a new line", single)
	}
}

func TestConversationRebuildsTurns(t *testing.T) {
	events := []sessions.Event{
		{Kind: sessions.KindUser, Text: "what is in main.go?"},
		{Kind: sessions.KindAssistant, Text: "reading", Calls: []sessions.ToolCallRef{
			{ID: "call-1", Name: "read_file", Arguments: `{"path":"main.go"}`},
		}},
		{Kind: sessions.KindToolResult, CallID: "call-1", Tool: "read_file", Result: "package main\n"},
		{Kind: sessions.KindAssistant, Text: "It is a hello-world program."},
	}
	messages := Conversation(events)
	if len(messages) != 4 {
		t.Fatalf("messages = %d, want 4", len(messages))
	}
	if messages[1].Role != model.RoleAssistant || len(messages[1].ToolCalls) != 1 || messages[1].ToolCalls[0].ID != "call-1" {
		t.Errorf("assistant turn = %+v, want its tool call replayed", messages[1])
	}
	if messages[2].Role != model.RoleTool || messages[2].ToolCallID != "call-1" || messages[2].Content != "package main\n" {
		t.Errorf("tool turn = %+v, want the result paired by ID", messages[2])
	}
	if messages[3].Content != "It is a hello-world program." {
		t.Errorf("final answer = %q", messages[3].Content)
	}
}

func TestConversationDropsDanglingToolCall(t *testing.T) {
	events := []sessions.Event{
		{Kind: sessions.KindUser, Text: "go"},
		{Kind: sessions.KindAssistant, Calls: []sessions.ToolCallRef{{ID: "call-1", Name: "read_file"}}},
		// No tool result: the session was interrupted mid-turn.
	}
	messages := Conversation(events)
	if len(messages) != 1 || messages[0].Role != model.RoleUser {
		t.Fatalf("messages = %+v, want the dangling assistant turn dropped", messages)
	}
}

func TestConversationKeepsFailureResults(t *testing.T) {
	events := []sessions.Event{
		{Kind: sessions.KindUser, Text: "go"},
		{Kind: sessions.KindAssistant, Calls: []sessions.ToolCallRef{{ID: "call-1", Name: "read_file"}}},
		{Kind: sessions.KindToolResult, CallID: "call-1", Failure: "invalid arguments for tool \"read_file\":"},
	}
	messages := Conversation(events)
	if len(messages) != 3 {
		t.Fatalf("messages = %d, want 3", len(messages))
	}
	if messages[2].Content != "invalid arguments for tool \"read_file\":" {
		t.Errorf("tool message = %q, want the failure text", messages[2].Content)
	}
}
