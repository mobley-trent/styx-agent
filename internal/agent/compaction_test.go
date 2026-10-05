package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/model"
)

// recordingSummarizer records every summarization ask and returns a fixed
// summary.
type recordingSummarizer struct {
	instructions []string
	summary      string
	err          error
}

func (r *recordingSummarizer) Summarize(_ context.Context, instruction string, _ []model.Message) (string, error) {
	r.instructions = append(r.instructions, instruction)
	return r.summary, r.err
}

// scriptedCounter reports a fixed token count, so threshold and hysteresis can
// be driven exactly.
type scriptedCounter struct{ tokens int }

func (s *scriptedCounter) Count([]model.Message) int { return s.tokens }

func userMsg(s string) model.Message { return model.Message{Role: model.RoleUser, Content: s} }
func assistantMsg(s string) model.Message {
	return model.Message{Role: model.RoleAssistant, Content: s}
}
func toolMsg(id, s string) model.Message {
	return model.Message{Role: model.RoleTool, ToolCallID: id, Content: s}
}

func TestSplitKeepKeepsRecentUserTurnsVerbatim(t *testing.T) {
	messages := []model.Message{
		userMsg("one"), assistantMsg("a"),
		userMsg("two"), assistantMsg("b"),
		userMsg("three"), assistantMsg("c"),
	}
	eligible, kept := splitKeep(messages, 2)
	if len(kept) != 4 {
		t.Fatalf("kept %d messages, want the last two turns (4 messages)", len(kept))
	}
	if kept[0].Content != "two" || kept[3].Content != "c" {
		t.Errorf("kept window = %+v, want the last two user turns", kept)
	}
	if len(eligible) != 2 || eligible[0].Content != "one" {
		t.Errorf("eligible = %+v, want everything before the kept window", eligible)
	}
}

func TestSplitKeepFewerTurnsKeepsAll(t *testing.T) {
	messages := []model.Message{userMsg("one"), assistantMsg("a")}
	eligible, kept := splitKeep(messages, 10)
	if eligible != nil {
		t.Errorf("eligible = %+v, want nil when fewer than KeepTurns user turns exist", eligible)
	}
	if len(kept) != 2 {
		t.Errorf("kept = %+v, want the whole conversation", kept)
	}
}

func TestCompactorAutoFiresAtThreshold(t *testing.T) {
	sum := &recordingSummarizer{summary: "summary"}
	c := NewCompactor(CompactionSettings{
		Mode: CompactionAuto, Threshold: 0.85, KeepTurns: 0, ContextWindow: 100,
	}, sum, summaryAwareCounter())
	messages := []model.Message{userMsg("go"), assistantMsg("working")}

	out, result, armed, err := c.MaybeCompact(context.Background(), messages, true)
	if err != nil {
		t.Fatalf("MaybeCompact() = %v", err)
	}
	if result == nil {
		t.Fatal("compaction did not fire at 85%")
	}
	if armed {
		t.Error("trigger stayed armed after a compaction that freed enough; hysteresis requires re-arm")
	}
	if out[0].Role != model.RoleSystem || !strings.HasPrefix(out[0].Content, summaryPrefix) {
		t.Errorf("compacted conversation = %+v, want a leading summary message", out)
	}
	if len(sum.calls()) != 1 {
		t.Errorf("summarizer calls = %d, want 1", len(sum.calls()))
	}
}

func TestCompactorDoesNotFireBelowThreshold(t *testing.T) {
	counter := &scriptedCounter{tokens: 70}
	c := NewCompactor(CompactionSettings{
		Mode: CompactionAuto, Threshold: 0.85, KeepTurns: 0, ContextWindow: 100,
	}, &recordingSummarizer{summary: "s"}, counter)
	messages := []model.Message{userMsg("go"), assistantMsg("working")}

	out, result, armed, err := c.MaybeCompact(context.Background(), messages, true)
	if err != nil || result != nil || !armed {
		t.Fatalf("MaybeCompact() = (%v, %v, %v), want no fire and still armed", out, result, armed)
	}
}

// summaryAwareCounter reports 90% until a compaction summary is present, then
// 50% — modelling the level actually dropping when summarization succeeds.
func summaryAwareCounter() TokenCounter {
	return TokenCounterFunc(func(messages []model.Message) int {
		for _, m := range messages {
			if isSummary(m) {
				return 50
			}
		}
		return 90
	})
}

func TestCompactorHysteresisRearmsOnlyAfterFalling(t *testing.T) {
	c := NewCompactor(CompactionSettings{
		Mode: CompactionAuto, KeepTurns: 0, ContextWindow: 100,
	}, &recordingSummarizer{summary: "s"}, summaryAwareCounter())
	messages := []model.Message{userMsg("go"), assistantMsg("working")}

	// Fire once; the summary lands the level at 50%, so the arm is satisfied.
	_, result, armed, err := c.MaybeCompact(context.Background(), messages, true)
	if err != nil || result == nil || result.AfterLevel > compactReArmLevel {
		t.Fatalf("first fire = (%+v, armed=%v), want a compaction landing at/below the re-arm level", result, armed)
	}

	// Still above 85% but not yet observed at/under 60%: must not fire again.
	_, result, armed, err = c.MaybeCompact(context.Background(), messages, false)
	if err != nil || result != nil || armed {
		t.Fatalf("disarmed fire = (%v, armed=%v), want no fire and still disarmed", result, armed)
	}

	// Observing the level at <=60% re-arms without firing.
	condensed := []model.Message{{Role: model.RoleSystem, Content: summaryPrefix + "s"}}
	_, result, armed, err = c.MaybeCompact(context.Background(), condensed, false)
	if err != nil || result != nil || !armed {
		t.Fatalf("re-arm = (%v, armed=%v), want no fire and re-armed", result, armed)
	}

	// Back at 90%: fires again.
	_, result, _, err = c.MaybeCompact(context.Background(), messages, armed)
	if err != nil || result == nil {
		t.Fatalf("second fire = (%v, %v), want a fire after re-arm", result, err)
	}
}

func TestCompactorStaysArmedWhenItCannotFreeEnough(t *testing.T) {
	// A scripted counter that ignores compaction models a strategy that lands
	// in (60%, 80%]: eviction freed some but not 25 points. The trigger must
	// stay armed rather than wedge permanently above threshold.
	counter := &scriptedCounter{tokens: 85}
	c := NewCompactor(CompactionSettings{
		Mode: CompactionAuto, KeepTurns: 0, ContextWindow: 100,
	}, &recordingSummarizer{summary: "s"}, counter)
	messages := []model.Message{
		userMsg("go"),
		toolMsg("c1", strings.Repeat("x", 400)),
	}

	_, result, armed, err := c.MaybeCompact(context.Background(), messages, true)
	if err != nil || result == nil {
		t.Fatalf("MaybeCompact() = (%v, %v), want a fire", result, err)
	}
	if !armed {
		t.Error("trigger disarmed after freeing <25 points; it can never re-arm and would wedge")
	}
}

func TestCompactorManualModeNeverAutoFires(t *testing.T) {
	counter := &scriptedCounter{tokens: 200}
	c := NewCompactor(CompactionSettings{
		Mode: CompactionManual, ContextWindow: 100, KeepTurns: 0,
	}, &recordingSummarizer{summary: "s"}, counter)
	messages := []model.Message{userMsg("go"), assistantMsg("working")}

	_, result, _, err := c.MaybeCompact(context.Background(), messages, true)
	if err != nil || result != nil {
		t.Fatalf("manual mode auto-fired: result=%v err=%v", result, err)
	}
}

func TestCompactorEvictionFirstWhenEnough(t *testing.T) {
	// One big tool result dominates; eviction should free enough that no
	// summarization runs.
	big := strings.Repeat("line one\n", 800)
	messages := []model.Message{
		userMsg("start"),
		assistantMsg("calling"),
		toolMsg("c1", big),
		userMsg("next"),
		assistantMsg("done"),
	}
	sum := &recordingSummarizer{summary: "summary"}
	c := NewCompactor(CompactionSettings{
		Mode: CompactionAuto, Threshold: 0.85, KeepTurns: 1, ContextWindow: 1000,
	}, sum, nil)

	out, result, _, err := c.MaybeCompact(context.Background(), messages, true)
	if err != nil {
		t.Fatalf("MaybeCompact() = %v", err)
	}
	if result == nil {
		t.Fatal("auto compaction did nothing")
	}
	if result.Evicted == 0 {
		t.Error("expected at least one tool result to be evicted")
	}
	if result.Summarized != 0 {
		t.Errorf("summarized %d messages, want eviction only when it frees enough", result.Summarized)
	}
	if len(sum.calls()) != 0 {
		t.Error("summarizer ran even though eviction freed enough context")
	}
	// The kept window is untouched, byte for byte.
	if out[len(out)-1].Content != "done" || out[len(out)-2].Content != "next" {
		t.Errorf("kept window changed: %+v", out)
	}
	if !strings.Contains(out[2].Content, evictionMarker) {
		t.Errorf("tool result was not evicted: %q", out[2].Content)
	}
}

func TestCompactorSummarizesWhenEvictionInsufficient(t *testing.T) {
	// Large non-tool messages: eviction cannot free anything, so the oldest
	// segment is summarized.
	var messages []model.Message
	for i := 0; i < 6; i++ {
		messages = append(messages, userMsg(strings.Repeat("u", 500)))
		messages = append(messages, assistantMsg(strings.Repeat("a", 500)))
	}
	sum := &recordingSummarizer{summary: "condensed"}
	c := NewCompactor(CompactionSettings{
		Mode: CompactionAuto, Threshold: 0.85, KeepTurns: 1, ContextWindow: 1000,
	}, sum, nil)

	out, result, err := c.Compact(context.Background(), messages, "")
	if err != nil {
		t.Fatalf("Compact() = %v", err)
	}
	if result == nil || result.Summarized == 0 {
		t.Fatalf("result = %+v, want a summary", result)
	}
	if result.AfterLevel > 0.5 {
		t.Errorf("AfterLevel = %.2f, want the ~50%% watermark", result.AfterLevel)
	}
	if !isSummary(out[0]) {
		t.Errorf("output does not lead with a summary: %+v", out[0])
	}
	// The most recent user turn is preserved verbatim.
	if out[len(out)-1].Content != strings.Repeat("a", 500) {
		t.Error("kept tail was not preserved verbatim")
	}
}

func TestCompactorHonorsCustomInstruction(t *testing.T) {
	messages := []model.Message{userMsg("go"), assistantMsg("work")}
	sum := &recordingSummarizer{summary: "s"}
	c := NewCompactor(CompactionSettings{ContextWindow: 100, KeepTurns: 0}, sum, nil)

	if _, _, err := c.Compact(context.Background(), messages, "preserve every IP address"); err != nil {
		t.Fatalf("Compact() = %v", err)
	}
	if len(sum.instructions) != 1 || sum.instructions[0] != "preserve every IP address" {
		t.Errorf("summarizer instructions = %q, want the custom /compact instruction", sum.instructions)
	}
}

func TestCompactorEvictionIsIdempotent(t *testing.T) {
	messages := []model.Message{
		userMsg("go"),
		toolMsg("c1", strings.Repeat("x", 4000)),
		userMsg("go again"),
		toolMsg("c2", strings.Repeat("y", 4000)),
	}
	c := NewCompactor(CompactionSettings{ContextWindow: 100000, KeepTurns: 0}, nil, nil)

	once, _, err := c.Compact(context.Background(), messages, "")
	if err != nil {
		t.Fatalf("first Compact() = %v", err)
	}
	twice, _, err := c.Compact(context.Background(), once, "")
	if err != nil {
		t.Fatalf("second Compact() = %v", err)
	}
	for i := range once {
		if once[i].Content != twice[i].Content {
			t.Errorf("eviction is not idempotent at %d:\n once=%q\ntwice=%q", i, once[i].Content, twice[i].Content)
		}
	}
}

func TestCompactorPropagatesSummarizerError(t *testing.T) {
	sentinel := errors.New("model down")
	messages := []model.Message{userMsg(strings.Repeat("u", 4000)), assistantMsg("x")}
	c := NewCompactor(CompactionSettings{ContextWindow: 100}, &recordingSummarizer{err: sentinel}, nil)

	if _, _, err := c.Compact(context.Background(), messages, ""); !errors.Is(err, sentinel) {
		t.Fatalf("Compact() = %v, want the summarizer error", err)
	}
}

// calls is a small helper so tests can assert how often the summarizer ran.
func (r *recordingSummarizer) calls() []string { return r.instructions }

func TestEstimateTokensCountsContentAndCalls(t *testing.T) {
	messages := []model.Message{
		{Role: model.RoleAssistant, Content: strings.Repeat("x", 400), ToolCalls: []model.ToolCall{
			{Name: "read_file", Arguments: strings.Repeat("y", 400)},
		}},
	}
	got := EstimateTokens(messages)
	if got < 200 {
		t.Errorf("EstimateTokens = %d, want ~200+ for 800 bytes and framing", got)
	}
}

func TestCompactorNoOpKeepsTriggerArmed(t *testing.T) {
	// The conversation is over threshold but everything sits inside the
	// verbatim window, so there is nothing to compact. The trigger must not be
	// spent on the no-op.
	counter := &scriptedCounter{tokens: 90}
	c := NewCompactor(CompactionSettings{
		Mode: CompactionAuto, KeepTurns: 5, ContextWindow: 100,
	}, &recordingSummarizer{summary: "s"}, counter)
	messages := []model.Message{userMsg("only")}

	_, result, armed, err := c.MaybeCompact(context.Background(), messages, true)
	if err != nil || result != nil || !armed {
		t.Fatalf("no-op MaybeCompact() = (result=%v, armed=%v), want no fire and still armed", result, armed)
	}
}

func TestCompactorSetContextWindowRescalesLevel(t *testing.T) {
	c := NewCompactor(CompactionSettings{ContextWindow: 100},
		nil, TokenCounterFunc(func([]model.Message) int { return 50 }))
	msgs := []model.Message{userMsg("go")}

	if got := c.Level(msgs); got != 0.5 {
		t.Fatalf("Level() = %v, want 0.5 for a 50-token context in a 100-token window", got)
	}
	c.SetContextWindow(200)
	if got := c.Level(msgs); got != 0.25 {
		t.Errorf("Level() after rescale = %v, want 0.25", got)
	}
	if got := c.Settings().ContextWindow; got != 200 {
		t.Errorf("Settings().ContextWindow = %d, want 200", got)
	}

	// A non-positive window is ignored: rescaling to it would make every
	// conversation look over-threshold.
	c.SetContextWindow(0)
	if got := c.Settings().ContextWindow; got != 200 {
		t.Errorf("Settings().ContextWindow after zero = %d, want the prior 200", got)
	}
}
