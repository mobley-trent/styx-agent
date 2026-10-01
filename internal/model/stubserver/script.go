// Package stubserver is the in-repo, OpenAI-compatible model server for
// client-path testing (docs/spec.md §11.2, layer 2; §3.3 wire behavior).
//
// It speaks real SSE with tool calls, surfaces DeepSeek's reasoning_content,
// reports cache-token usage, supports strict-mode enforcement, and can inject
// faults (HTTP status errors, malformed tool-call JSON). Recorded sessions
// replay through it as a mode — there is no separate replay mechanism (§11.3).
//
// Boundary rule: this package is a test double for the wire, not part of the
// harness. It depends on nothing in internal/model; it is a server, and the
// client is what is under test.
package stubserver

// Turn is one scripted response. A turn either streams (the default) or, with
// a non-zero Fault, responds with an HTTP error status instead — the fault
// injection the backoff tests need.
type Turn struct {
	// Fault, when non-zero, is the HTTP status returned instead of a stream
	// (429 for rate limiting, 500/502/503 for provider errors). The body is an
	// OpenAI-style error object.
	Fault int
	// FaultMessage overrides the error body's message.
	FaultMessage string

	// Reasoning chunks stream as `reasoning_content`, before Text.
	Reasoning []string
	// Text chunks stream as `content`, after Reasoning.
	Text []string
	// ToolCalls stream as `tool_calls`, after Text. Arguments may be
	// deliberately malformed JSON to exercise the repair layer.
	ToolCalls []ScriptedToolCall
	// Usage rides the final usage chunk. Nil omits it.
	Usage *Usage
	// KeepAlives interleaves SSE comment lines between events, modelling the
	// provider's keep-alives (§3.3).
	KeepAlives bool
}

// ScriptedToolCall is one tool call a turn emits.
type ScriptedToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Usage is the scripted turn's token accounting, including DeepSeek's cache
// fields (§3.1).
type Usage struct {
	PromptTokens          int `json:"prompt_tokens"`
	CompletionTokens      int `json:"completion_tokens"`
	TotalTokens           int `json:"total_tokens"`
	ReasoningTokens       int `json:"reasoning_tokens,omitempty"`
	PromptCacheHitTokens  int `json:"prompt_cache_hit_tokens,omitempty"`
	PromptCacheMissTokens int `json:"prompt_cache_miss_tokens,omitempty"`
}

// Text is a scripted text-only turn.
func Text(chunks ...string) Turn { return Turn{Text: chunks} }

// Reply is a scripted turn with reasoning, final text, and a tool call.
func Reply(reasoning, text, tool, args string) Turn {
	return Turn{
		Reasoning: []string{reasoning},
		Text:      []string{text},
		ToolCalls: []ScriptedToolCall{{ID: "call_1", Name: tool, Arguments: args}},
	}
}

// FaultStatus is a scripted HTTP-fault turn.
func FaultStatus(status int) Turn { return Turn{Fault: status} }
