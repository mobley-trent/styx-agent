package agent

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

//go:embed promptdata/summarize.md
var summarizeSystemPrompt string

// ModelSummarizer summarizes a conversation segment with the session's own
// model (§4.5). It is the production Summarizer; tests bind a scripted one.
type ModelSummarizer struct {
	client       model.ModelClient
	resolveModel func() string
	emit         func(sessions.Event)
}

// SummarizerOption configures a ModelSummarizer.
type SummarizerOption func(*ModelSummarizer)

// WithSummarizerUsageEmitter routes the summarizer's own token usage onto the
// session bus, so compaction spend is counted in the session cost too (§3.1,
// §4.5).
func WithSummarizerUsageEmitter(emit func(sessions.Event)) SummarizerOption {
	return func(s *ModelSummarizer) {
		if emit != nil {
			s.emit = emit
		}
	}
}

// NewModelSummarizer builds a summarizer over the session's model client. The
// model ID is the pinned ID requests name; empty keeps the client default.
func NewModelSummarizer(client model.ModelClient, modelID string, opts ...SummarizerOption) *ModelSummarizer {
	return NewDynamicModelSummarizer(client, func() string { return modelID }, opts...)
}

// NewDynamicModelSummarizer builds a summarizer whose model ID is resolved at
// each call, so an operator's /model swap reaches compaction too (§3.1, §4.5).
func NewDynamicModelSummarizer(client model.ModelClient, resolve func() string, opts ...SummarizerOption) *ModelSummarizer {
	if resolve == nil {
		resolve = func() string { return "" }
	}
	s := &ModelSummarizer{client: client, resolveModel: resolve}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Summarize implements Summarizer. The instruction, when non-empty, is the
// operator's custom /compact guidance and is appended to the ask.
func (s *ModelSummarizer) Summarize(ctx context.Context, instruction string, segment []model.Message) (string, error) {
	if s.client == nil {
		return "", errors.New("summarize: no model client is configured")
	}
	if len(segment) == 0 {
		return "", nil
	}

	ask := renderSegment(segment)
	if extra := strings.TrimSpace(instruction); extra != "" {
		ask += "\n\nAdditional instruction from the operator, which takes precedence over the above:\n" + extra
	}

	ch, err := s.client.StreamTurn(ctx, model.ModelRequest{
		Model: s.resolveModel(),
		Messages: []model.Message{
			{Role: model.RoleSystem, Content: summarizeSystemPrompt},
			{Role: model.RoleUser, Content: ask},
		},
	})
	if err != nil {
		return "", fmt.Errorf("summarize: %w", err)
	}

	var b strings.Builder
	for ev := range ch {
		switch ev.Kind {
		case model.EventTextDelta:
			b.WriteString(ev.Text)
		case model.EventError:
			if ev.Err != nil {
				return "", fmt.Errorf("summarize: %w", ev.Err)
			}
			return "", errors.New("summarize: stream ended without a completion event")
		case model.EventDone:
			if ev.Usage != nil && s.emit != nil {
				s.emit(sessions.Event{
					Kind:             sessions.KindUsage,
					Model:            s.resolveModel(),
					PromptTokens:     ev.Usage.PromptTokens,
					CompletionTokens: ev.Usage.CompletionTokens,
					CacheHitTokens:   ev.Usage.CacheHitTokens,
					CacheMissTokens:  ev.Usage.CacheMissTokens,
				})
			}
			if strings.TrimSpace(b.String()) == "" {
				return "", errors.New("summarize: the model returned an empty summary")
			}
			return strings.TrimSpace(b.String()), nil
		}
	}
	return "", errors.New("summarize: stream ended without a completion event")
}

// renderSegment flattens a conversation segment into one text block the
// summarizer can read. It is a rendering, not a wire format: the summarizer
// never sees the segment as conversation turns.
func renderSegment(segment []model.Message) string {
	var b strings.Builder
	b.WriteString("Conversation segment to summarize:\n\n")
	for _, m := range segment {
		switch m.Role {
		case model.RoleUser:
			fmt.Fprintf(&b, "USER:\n%s\n\n", m.Content)
		case model.RoleAssistant:
			if strings.TrimSpace(m.Content) != "" {
				fmt.Fprintf(&b, "ASSISTANT:\n%s\n\n", m.Content)
			}
			for _, c := range m.ToolCalls {
				fmt.Fprintf(&b, "ASSISTANT TOOL CALL: %s(%s)\n\n", c.Name, c.Arguments)
			}
		case model.RoleTool:
			fmt.Fprintf(&b, "TOOL RESULT:\n%s\n\n", m.Content)
		case model.RoleSystem:
			fmt.Fprintf(&b, "NOTE:\n%s\n\n", m.Content)
		}
	}
	return b.String()
}
