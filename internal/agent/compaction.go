package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/model"
)

// Compaction mode values. They mirror the config keys of §10.3 without making
// agent depend on config: the app maps its settings onto these.
const (
	// CompactionAuto fires compaction between turns when the threshold is
	// crossed (§4.5).
	CompactionAuto = "auto"
	// CompactionManual leaves compaction to the operator's /compact.
	CompactionManual = "manual"
)

// Compaction policy constants (§4.5).
const (
	// defaultCompactionThreshold is the context-window fraction that fires
	// auto-compaction.
	defaultCompactionThreshold = 0.85
	// defaultCompactionKeepTurns is how many recent user turns stay verbatim.
	defaultCompactionKeepTurns = 10
	// compactReArmLevel is the fraction the context must fall to (freeing ≥25
	// points from the 85% trigger) before the trigger re-arms (§4.5).
	compactReArmLevel = 0.60
	// compactSummarizeLevel is the fraction above which eviction alone is
	// insufficient and the oldest segment is summarized (§4.5). Summarizing
	// the whole eligible segment targets the ~50% watermark.
	compactSummarizeLevel = 0.80
	// evictionFirstLineCap bounds the first-line summary an evicted tool
	// result keeps, so a single giant line still frees context.
	evictionFirstLineCap = 256
)

// summaryPrefix marks a message that is a compaction summary, so a later
// compaction never re-summarizes (and thus never rolls) it (§4.5).
const summaryPrefix = "[compaction summary of earlier conversation]\n"

// evictionMarker marks a tool result whose body was replaced by its first
// line, so eviction is idempotent.
const evictionMarker = "[evicted at compaction:"

// CompactionSettings configures a Compactor (§4.5). The app maps the merged
// config onto it; agent never reads config directly.
type CompactionSettings struct {
	// Mode is CompactionAuto or CompactionManual.
	Mode string
	// Threshold is the context-window fraction that fires auto-compaction.
	// Zero means the spec default (0.85).
	Threshold float64
	// KeepTurns is how many recent user turns stay verbatim. Negative means
	// the spec default (10); zero keeps nothing verbatim.
	KeepTurns int
	// ContextWindow is the active model's context size in tokens (§3.1).
	ContextWindow int
}

// normalized returns the settings with spec defaults filled in.
func (s CompactionSettings) normalized() CompactionSettings {
	if s.Threshold <= 0 {
		s.Threshold = defaultCompactionThreshold
	}
	if s.KeepTurns < 0 {
		s.KeepTurns = defaultCompactionKeepTurns
	}
	return s
}

// Summarizer produces a summary of a conversation segment (§4.5). The
// instruction is the operator's custom /compact guidance, empty for the
// automatic path.
type Summarizer interface {
	Summarize(ctx context.Context, instruction string, segment []model.Message) (string, error)
}

// TokenCounter measures the token size of a conversation. EstimateTokens is
// the production default; tests bind a scripted counter to drive the
// threshold and hysteresis exactly.
type TokenCounter interface {
	Count(messages []model.Message) int
}

// TokenCounterFunc adapts a function to TokenCounter.
type TokenCounterFunc func([]model.Message) int

// Count implements TokenCounter.
func (f TokenCounterFunc) Count(messages []model.Message) int { return f(messages) }

// CompactionResult describes one compaction for the event bus and the status
// bar (§4.5).
type CompactionResult struct {
	// BeforeTokens and AfterTokens are the measured context sizes.
	BeforeTokens int
	AfterTokens  int
	// BeforeLevel and AfterLevel are the context-window fractions.
	BeforeLevel float64
	AfterLevel  float64
	// Evicted is how many tool results were replaced by first-line summaries.
	Evicted int
	// Summarized is how many messages were replaced by one summary; zero means
	// no LLM summary was produced.
	Summarized int
	// Detail is the human-readable notice rendered inline and persisted.
	Detail string
}

// Compactor implements the §4.5 policy: tool-result eviction first, then LLM
// summarization of the oldest segment. It holds no per-conversation state —
// the loop owns the hysteresis flag — so one Compactor is safe to share.
type Compactor struct {
	settings   CompactionSettings
	summarizer Summarizer
	counter    TokenCounter
}

// NewCompactor builds a Compactor. A nil counter means EstimateTokens; a nil
// summarizer disables the summarization step (eviction only).
func NewCompactor(settings CompactionSettings, summarizer Summarizer, counter TokenCounter) *Compactor {
	if counter == nil {
		counter = TokenCounterFunc(EstimateTokens)
	}
	return &Compactor{settings: settings.normalized(), summarizer: summarizer, counter: counter}
}

// Settings returns the normalized settings.
func (c *Compactor) Settings() CompactionSettings { return c.settings }

// Level is the current context-window fraction, in [0, ...).
func (c *Compactor) Level(messages []model.Message) float64 {
	return fraction(c.counter.Count(messages), c.settings.ContextWindow)
}

// MaybeCompact applies the automatic path (§4.5). armed is the hysteresis
// flag: true at session start and after the context has fallen to the re-arm
// level. It returns the (possibly unchanged) messages, a result when
// compaction fired (nil otherwise), the updated armed flag, and any error.
// Manual mode never fires here.
func (c *Compactor) MaybeCompact(ctx context.Context, messages []model.Message, armed bool) ([]model.Message, *CompactionResult, bool, error) {
	if c.settings.Mode != CompactionAuto {
		return messages, nil, armed, nil
	}
	level := c.Level(messages)
	if !armed {
		if level <= compactReArmLevel {
			armed = true
		}
		return messages, nil, armed, nil
	}
	if level < c.settings.Threshold {
		return messages, nil, armed, nil
	}

	out, result, err := c.compact(ctx, messages, "", false)
	if err != nil {
		return messages, nil, armed, err
	}
	if result == nil {
		// Nothing was eligible (everything is inside the verbatim window): the
		// trigger stays armed rather than being spent on a no-op.
		return messages, nil, armed, nil
	}
	// Hysteresis (§4.5): a compaction that freed ≥25 points (landing at ≤60%)
	// marks the work complete, so the trigger waits to observe that low level
	// before it will fire again. A compaction that could not free that much —
	// eviction landed between 60% and 80%, or the verbatim window dominates —
	// stays armed rather than wedging, so later turns keep making progress.
	return out, result, result.AfterLevel > compactReArmLevel, nil
}

// Compact is the manual override: it compacts now, ignoring the threshold and
// the hysteresis flag, and honors the operator's custom instruction. It still
// never touches the last KeepTurns verbatim.
func (c *Compactor) Compact(ctx context.Context, messages []model.Message, instruction string) ([]model.Message, *CompactionResult, error) {
	return c.compact(ctx, messages, instruction, true)
}

// compact runs the progressive strategy over a conversation (system prompt
// excluded). It evicts tool results in the eligible prefix, then summarizes
// that prefix if eviction was not enough (auto) or when forced (manual).
func (c *Compactor) compact(ctx context.Context, messages []model.Message, instruction string, force bool) ([]model.Message, *CompactionResult, error) {
	eligible, kept := splitKeep(messages, c.settings.KeepTurns)
	if len(eligible) == 0 {
		return messages, nil, nil
	}

	beforeTokens := c.counter.Count(messages)
	evicted, evictCount := evictToolResults(eligible)
	if evictCount > 0 {
		eligible = evicted
	}

	// Keep any leading summary verbatim; it is already compressed, so
	// re-summarizing it would be a rolling summary (§4.5).
	leading, toSummarize := splitLeadingSummaries(eligible)

	refreshed := joinMessages(leading, toSummarize, kept)
	afterEviction := c.counter.Count(refreshed)

	needSummary := len(toSummarize) > 0 && c.summarizer != nil &&
		(force || fraction(afterEviction, c.settings.ContextWindow) > compactSummarizeLevel)

	summarized := 0
	final := refreshed
	if needSummary {
		summary, err := c.summarizer.Summarize(ctx, instruction, toSummarize)
		if err != nil {
			return nil, nil, fmt.Errorf("compaction: summarize oldest segment: %w", err)
		}
		if strings.TrimSpace(summary) != "" {
			summaryMsg := model.Message{Role: model.RoleSystem, Content: summaryPrefix + strings.TrimSpace(summary)}
			combined := make([]model.Message, 0, len(leading)+1)
			combined = append(combined, leading...)
			combined = append(combined, summaryMsg)
			final = joinMessages(combined, nil, kept)
			summarized = len(toSummarize)
		}
	}

	// Nothing changed: report a no-op so the caller does not emit an
	// empty compaction event or spend its hysteresis trigger.
	if evictCount == 0 && summarized == 0 {
		return messages, nil, nil
	}

	afterTokens := c.counter.Count(final)
	result := &CompactionResult{
		BeforeTokens: beforeTokens,
		AfterTokens:  afterTokens,
		BeforeLevel:  fraction(beforeTokens, c.settings.ContextWindow),
		AfterLevel:   fraction(afterTokens, c.settings.ContextWindow),
		Evicted:      evictCount,
		Summarized:   summarized,
	}
	result.Detail = describe(result)
	return final, result, nil
}

// splitKeep partitions a conversation into the eligible prefix and the kept
// verbatim suffix. The suffix begins at the start of the KeepTurns-th-from-last
// user turn, so a tool call is never separated from its results. With fewer
// than KeepTurns user turns the whole conversation is kept.
func splitKeep(messages []model.Message, keepTurns int) (eligible, kept []model.Message) {
	if keepTurns <= 0 {
		return messages, nil
	}
	seen := 0
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role != model.RoleUser {
			continue
		}
		seen++
		if seen == keepTurns {
			return messages[:i], messages[i:]
		}
	}
	return nil, messages
}

// splitLeadingSummaries separates already-compressed leading messages from the
// segment a new summary should cover.
func splitLeadingSummaries(messages []model.Message) (leading, rest []model.Message) {
	i := 0
	for i < len(messages) && isSummary(messages[i]) {
		i++
	}
	return messages[:i], messages[i:]
}

// isSummary reports whether a message is a compaction summary.
func isSummary(m model.Message) bool {
	return m.Role == model.RoleSystem && strings.HasPrefix(m.Content, summaryPrefix)
}

// evictToolResults replaces each tool result's body with a bounded first-line
// summary, counting the ones it changed. It is idempotent.
func evictToolResults(messages []model.Message) ([]model.Message, int) {
	out := make([]model.Message, len(messages))
	copy(out, messages)
	n := 0
	for i := range out {
		if out[i].Role != model.RoleTool || strings.Contains(out[i].Content, evictionMarker) {
			continue
		}
		out[i].Content = evictContent(out[i].Content)
		n++
	}
	return out, n
}

// evictContent keeps a bounded first line and records what was dropped, so the
// model still knows a tool ran and roughly what it returned (§4.5).
func evictContent(content string) string {
	first := content
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if len(first) > evictionFirstLineCap {
		first = first[:evictionFirstLineCap]
	}
	return fmt.Sprintf("%s\n%s %d byte(s) omitted]", first, evictionMarker, len(content))
}

// joinMessages concatenates the leading, summarized, and kept parts.
func joinMessages(leading, summarized, kept []model.Message) []model.Message {
	total := len(leading) + len(summarized) + len(kept)
	out := make([]model.Message, 0, total)
	out = append(out, leading...)
	out = append(out, summarized...)
	out = append(out, kept...)
	return out
}

// fraction renders tokens as a context-window fraction.
func fraction(tokens, window int) float64 {
	if window <= 0 {
		return 0
	}
	return float64(tokens) / float64(window)
}

// describe renders the compaction notice.
func describe(r *CompactionResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "context %.0f%% → %.0f%%", r.BeforeLevel*100, r.AfterLevel*100)
	var actions []string
	if r.Evicted > 0 {
		actions = append(actions, fmt.Sprintf("evicted %d tool result(s)", r.Evicted))
	}
	if r.Summarized > 0 {
		actions = append(actions, fmt.Sprintf("summarized %d oldest message(s)", r.Summarized))
	}
	if len(actions) == 0 {
		actions = append(actions, "nothing to free")
	}
	return b.String() + ": " + strings.Join(actions, ", ")
}

// EstimateTokens is the offline token estimator: a coarse ~4-bytes-per-token
// heuristic over message content and tool-call arguments, plus a small
// per-message framing overhead. It never counts reasoning, which the wire
// drops (§3.3).
func EstimateTokens(messages []model.Message) int {
	total := 0
	for _, m := range messages {
		total += 4
		total += estimateString(m.Content)
		for _, c := range m.ToolCalls {
			total += estimateString(c.Name)
			total += estimateString(c.Arguments)
		}
	}
	return total
}

// estimateString is the byte/4 heuristic, rounded up.
func estimateString(s string) int {
	if s == "" {
		return 0
	}
	return (len(s) + 3) / 4
}
