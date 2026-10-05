package agent

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// compactionSystemPrompt stands in for a prompt carrying engagement context
// and ROE state: the protected bytes that must survive compaction untouched.
const compactionSystemPrompt = "SYSTEM PROMPT\n# Engagement\ntargets: 10.0.0.0/24\nroe: exploit_allowed=false\n"

func TestLoopAutoCompactsBetweenTurns(t *testing.T) {
	// A previous turn left a huge tool result in history; the run's own turn
	// is small. The boundary before the first model call is where compaction
	// fires, so the model never receives the over-threshold context.
	big := strings.Repeat("noise line\n", 3000)
	history := []model.Message{
		{Role: model.RoleUser, Content: "list files"},
		{Role: model.RoleAssistant, ToolCalls: []model.ToolCall{{ID: "h1", Name: "bash", Arguments: "{}"}}},
		{Role: model.RoleTool, ToolCallID: "h1", Content: big},
	}

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(
			fakemodel.Call("c1", "probe", "{}"),
			fakemodel.Call("c2", "probe", "{}"),
		),
		fakemodel.Text("done"),
	))

	events := &collector{}
	probe := testTool("probe", func(context.Context, map[string]any) (string, error) {
		return "ok", nil
	})

	var auditBuf bytes.Buffer
	compactor := NewCompactor(CompactionSettings{
		Mode: CompactionAuto, Threshold: 0.85, KeepTurns: 1, ContextWindow: 1000,
	}, nil, nil)
	loop := NewLoop(fake, mustRegistry(t, probe), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&auditBuf), compactionSystemPrompt,
		WithCompactor(compactor), WithEmitter(events.emit))

	result, err := loop.Run(context.Background(), history, "do more")
	if err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}

	compactions := events.byKind(sessions.KindCompaction)
	if len(compactions) != 1 {
		t.Fatalf("compaction events = %d, want exactly 1", len(compactions))
	}
	if compactions[0].Turn != 1 {
		t.Errorf("compaction turn = %d, want the boundary before turn 1", compactions[0].Turn)
	}
	// No mid-turn firing: the compaction event precedes the turn's first tool
	// result, so it was not interleaved with dispatch.
	ordered := events.snapshot()
	firstCompaction := indexOfKind(ordered, sessions.KindCompaction)
	firstResult := indexOfKind(ordered, sessions.KindToolResult)
	if firstCompaction < 0 || firstResult < 0 || firstCompaction > firstResult {
		t.Errorf("compaction event at %d does not precede the first tool result at %d", firstCompaction, firstResult)
	}

	requests := fake.Requests()
	if len(requests) != 2 {
		t.Fatalf("model requests = %d, want 2", len(requests))
	}
	// The very first request already sees the compacted history: the old tool
	// result's body was evicted to its first line.
	got := toolContent(requests[0].Messages, "h1")
	if !strings.Contains(got, evictionMarker) {
		t.Errorf("first request did not see the evicted tool result:\n%q", got)
	}
	if len(got) >= len(big) {
		t.Errorf("evicted tool result is %d bytes, want far less than %d", len(got), len(big))
	}

	// Cache economics: the system prompt is byte-identical across the boundary.
	for i, req := range requests {
		if req.Messages[0].Role != model.RoleSystem || req.Messages[0].Content != compactionSystemPrompt {
			t.Errorf("request %d does not lead with the byte-stable system prompt: %q", i, req.Messages[0].Content)
		}
	}
	// The engagement context/ROE bytes never appear in the compacted transcript
	// (they live only in the system prompt), and the transcript no longer holds
	// the full big result.
	for _, m := range result.Messages {
		if strings.Contains(m.Content, "roe: exploit_allowed") {
			t.Error("the system prompt leaked into the returned conversation")
		}
	}

	// Audit is untouched by compaction: only the two probe calls are recorded.
	records := auditRecords(t, &auditBuf)
	if len(records) != 2 {
		t.Errorf("audit records = %d, want the 2 probe calls only", len(records))
	}
}

// snapshot returns a copy of the recorded events in order.
func (c *collector) snapshot() []sessions.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]sessions.Event(nil), c.events...)
}

// indexOfKind returns the index of the first event of a kind, or -1.
func indexOfKind(events []sessions.Event, kind sessions.Kind) int {
	for i, ev := range events {
		if ev.Kind == kind {
			return i
		}
	}
	return -1
}

func TestLoopSummarizesOldestSegmentWhenEvictionInsufficient(t *testing.T) {
	var history []model.Message
	for i := 0; i < 6; i++ {
		history = append(history, model.Message{Role: model.RoleUser, Content: strings.Repeat("u", 600)})
		history = append(history, model.Message{Role: model.RoleAssistant, Content: strings.Repeat("a", 600)})
	}

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "probe", "{}")),
		fakemodel.Text("done"),
	))
	sum := &recordingSummarizer{summary: "condensed earlier work"}
	compactor := NewCompactor(CompactionSettings{
		Mode: CompactionAuto, Threshold: 0.85, KeepTurns: 1, ContextWindow: 1000,
	}, sum, nil)
	events := &collector{}
	loop := NewLoop(fake, mustRegistry(t, testTool("probe", func(context.Context, map[string]any) (string, error) {
		return "ok", nil
	})), mustEngine(t, policy.ModeSafe), audit.NewWriter(&bytes.Buffer{}), compactionSystemPrompt,
		WithCompactor(compactor), WithEmitter(events.emit))

	if _, err := loop.Run(context.Background(), history, "keep going"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if len(sum.instructions) != 1 {
		t.Fatalf("summarizer calls = %d, want 1", len(sum.instructions))
	}
	requests := fake.Requests()
	if len(requests) != 2 {
		t.Fatalf("model requests = %d, want 2", len(requests))
	}
	first := requests[0].Messages
	if first[0].Content != compactionSystemPrompt {
		t.Errorf("system prompt changed across summarization: %q", first[0].Content)
	}
	if first[1].Role != model.RoleSystem || !strings.HasPrefix(first[1].Content, summaryPrefix) {
		t.Errorf("first request does not carry the compaction summary: %+v", first[1])
	}
	if !strings.Contains(first[1].Content, "condensed earlier work") {
		t.Errorf("summary content = %q, want the summarizer output", first[1].Content)
	}
}

// toolContent returns the content of the tool message answering id.
func toolContent(messages []model.Message, id string) string {
	for _, m := range messages {
		if m.Role == model.RoleTool && m.ToolCallID == id {
			return m.Content
		}
	}
	return ""
}
