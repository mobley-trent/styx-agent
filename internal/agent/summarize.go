package agent

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/model"
)

//go:embed promptdata/summarize.md
var summarizeSystemPrompt string

// ModelSummarizer summarizes a conversation segment with the session's own
// model (§4.5). It is the production Summarizer; tests bind a scripted one.
type ModelSummarizer struct {
	client  model.ModelClient
	modelID string
}

// NewModelSummarizer builds a summarizer over the session's model client. The
// model ID is the pinned ID requests name; empty keeps the client default.
func NewModelSummarizer(client model.ModelClient, modelID string) *ModelSummarizer {
	return &ModelSummarizer{client: client, modelID: modelID}
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
		Model: s.modelID,
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
