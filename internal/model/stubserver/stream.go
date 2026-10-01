package stubserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// serveStream writes one scripted turn as an OpenAI-compatible SSE stream:
// reasoning deltas, then text, then tool-call fragments, a finish chunk, an
// optional usage chunk, and the terminal [DONE] sentinel.
func (h *handler) serveStream(w http.ResponseWriter, wire wireRequest, turn Turn) {
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	model := wire.Model
	if model == "" {
		model = "deepseek-flash"
	}
	const completionID = "chatcmpl-stub"

	write := func(v any) {
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		if flusher != nil {
			flusher.Flush()
		}
	}
	keepAlive := func() {
		if !turn.KeepAlives {
			return
		}
		// A comment line, NOT a standalone SSE event: it is skipped by a
		// conformant decoder and must not be followed by a blank line, which
		// would dispatch an empty event.
		_, _ = io.WriteString(w, ": keep-alive\n")
		if flusher != nil {
			flusher.Flush()
		}
	}
	emit := func(choices []chunkChoice, usage *chunkUsage) {
		keepAlive()
		write(chunk{
			ID: completionID, Object: "chat.completion.chunk",
			Created: h.created, Model: model, Choices: choices, Usage: usage,
		})
	}

	first := true
	delta := func(d chunkDelta) []chunkChoice {
		if first {
			d.Role = "assistant"
			first = false
		}
		return []chunkChoice{{Index: 0, Delta: d}}
	}

	for _, r := range turn.Reasoning {
		emit(delta(chunkDelta{ReasoningContent: r}), nil)
	}
	for _, t := range turn.Text {
		emit(delta(chunkDelta{Content: t}), nil)
	}
	for i, call := range turn.ToolCalls {
		head, tail := splitArgs(call.Arguments)
		emit(delta(chunkDelta{ToolCalls: []chunkToolCall{{
			Index: i, ID: call.ID, Type: "function",
			Function: chunkToolCallParam{Name: call.Name, Arguments: head},
		}}}), nil)
		if tail != "" {
			emit(delta(chunkDelta{ToolCalls: []chunkToolCall{{
				Index: i, Function: chunkToolCallParam{Arguments: tail},
			}}}), nil)
		}
	}

	finish := "stop"
	if len(turn.ToolCalls) > 0 {
		finish = "tool_calls"
	}
	emit([]chunkChoice{{Index: 0, Delta: chunkDelta{}, FinishReason: &finish}}, nil)

	if turn.Usage != nil {
		u := chunkUsage{
			PromptTokens:          turn.Usage.PromptTokens,
			CompletionTokens:      turn.Usage.CompletionTokens,
			TotalTokens:           turn.Usage.TotalTokens,
			PromptCacheHitTokens:  turn.Usage.PromptCacheHitTokens,
			PromptCacheMissTokens: turn.Usage.PromptCacheMissTokens,
		}
		if turn.Usage.ReasoningTokens != 0 {
			rt := turn.Usage.ReasoningTokens
			u.ReasoningTokens = &rt
		}
		emit([]chunkChoice{}, &u)
	}

	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}
