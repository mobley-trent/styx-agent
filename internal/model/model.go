package model

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ModelClient is the ONLY path from the agent loop to the wire (docs/spec.md
// §3.2). Everything above the wire is harness; everything the model says is
// input. The interface's guarantees are the contract, not its exact shape:
// one model boundary, an in-process fake and an OpenAI-compatible stub server
// both implement it, and recorded-session replay is a stub-server mode (§11.2).
//
//nolint:revive // ModelClient is the spec's name for the single wire seam (§3.2).
type ModelClient interface {
	// StreamTurn streams one model turn for the given request, yielding text
	// deltas, reasoning deltas, and tool-call descriptors as they arrive.
	//
	// A non-nil error means the turn never started (transport failure after
	// the client's own retries, an unusable request, a canceled context). Once
	// the channel is returned, all failures arrive as a terminal EventError on
	// it and the channel closes; the caller must not assume the turn was
	// complete unless it saw an EventDone.
	StreamTurn(ctx context.Context, req ModelRequest) (<-chan StreamEvent, error)
}

// Sentinel errors. Callers branch on these with errors.Is rather than matching
// message text.
var (
	// ErrUnknownModel is a request whose model ID is not in the configured,
	// pinned set. The client never silently falls back to another model.
	ErrUnknownModel = errors.New("model: unknown model")
	// ErrRetryExhausted is a turn whose transport failures outlasted the retry
	// budget (5 attempts by default; §3.3).
	ErrRetryExhausted = errors.New("model: retries exhausted")
	// ErrStream is a failure while consuming an established stream — the
	// connection dropped, the provider emitted an error frame, or a chunk
	// could not be decoded.
	ErrStream = errors.New("model: stream failed")
)

// Role identifies a message author. The set is the OpenAI-compatible wire set
// the provider accepts; "developer" is normalized to "system" (the provider
// has no distinct developer role).
type Role string

const (
	// RoleSystem is the system-prompt author.
	RoleSystem Role = "system"
	// RoleUser is the human (or harness-substituted) author.
	RoleUser Role = "user"
	// RoleAssistant is the model's own prior output.
	RoleAssistant Role = "assistant"
	// RoleTool carries a tool result back to the model.
	RoleTool Role = "tool"
)

// Message is one conversation message. A single type covers every role; the
// zero-valued fields are simply absent on the wire per role:
//
//   - system/user: Content.
//   - assistant: Content (final answer text), ToolCalls.
//   - tool: Content (the tool result), ToolCallID (which call it answers).
//
// Reasoning is the assistant's streamed `reasoning_content`, carried here so
// the harness can persist it while never rendering it as final answer text
// (§3.3). Providers reject assistant reasoning echoed back as input, so the
// wire encoder drops it.
type Message struct {
	Role       Role
	Content    string
	Reasoning  string
	ToolCalls  []ToolCall
	ToolCallID string
}

// Tool is a tool descriptor exposed to the model. Parameters is the tool's
// JSON Schema object, kept as raw JSON so no schema detail is lost in a round
// trip. Strict applies schema-enforced argument generation (§3.3); built-in
// tools are always strict.
type Tool struct {
	Name        string
	Description string
	Parameters  json.RawMessage
	Strict      bool
}

// ToolCall is a model-requested tool invocation. Arguments is the raw JSON
// string exactly as the model emitted it — deliberately unparsed, because the
// repair layer must see malformed output verbatim to judge and report it.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string
}

// Params decodes the call's arguments into a parameter object. It returns the
// decoder's error untouched when the arguments are malformed; the repair layer
// is what turns that into structured feedback, never this method.
func (tc ToolCall) Params() (map[string]any, error) {
	if tc.Arguments == "" {
		return map[string]any{}, nil
	}
	var params map[string]any
	if err := json.Unmarshal([]byte(tc.Arguments), &params); err != nil {
		return nil, fmt.Errorf("model: tool call %q: %w", tc.Name, err)
	}
	return params, nil
}

// ModelRequest is one turn's input. The harness builds it; the client maps it
// to the wire. Messages carry the full conversation; Tools the current tool
// descriptors.
//
//nolint:revive // ModelRequest is the spec's name for one turn's input (§3.2).
type ModelRequest struct {
	// Model is a pinned model ID (never an alias; §3.1).
	Model string
	// Messages is the conversation in order, oldest first.
	Messages []Message
	// Tools is the tool set exposed for this turn.
	Tools []Tool
	// MaxTokens bounds the generated tokens. Zero means the provider default.
	MaxTokens int
	// Temperature, when non-nil, overrides the provider default.
	Temperature *float64
}

// EventKind discriminates a StreamEvent.
type EventKind int

const (
	// EventTextDelta carries a fragment of final answer text.
	EventTextDelta EventKind = iota
	// EventReasoningDelta carries a fragment of reasoning_content. It is
	// surfaced separately from final text and never merged into it (§3.3).
	EventReasoningDelta
	// EventToolCall carries one complete tool-call descriptor. Fragment
	// assembly (the provider streams arguments in pieces) happens in the
	// client; the loop sees whole calls.
	EventToolCall
	// EventDone terminates a successful turn and carries usage.
	EventDone
	// EventError terminates a failed turn. The channel closes immediately
	// after it, and Err is non-nil.
	EventError
)

// StreamEvent is one unit yielded by StreamTurn. Kind says which fields are
// meaningful; the rest are zero.
type StreamEvent struct {
	Kind EventKind
	// Text is set on EventTextDelta.
	Text string
	// Reasoning is set on EventReasoningDelta.
	Reasoning string
	// ToolCall is set on EventToolCall.
	ToolCall *ToolCall
	// Usage is set on EventDone. It is nil when the provider omitted usage.
	Usage *Usage
	// Err is set on EventError and is always non-nil.
	Err error
	// At is when the event was received. The client stamps it from its clock;
	// tests pin the clock.
	At time.Time
}

// Usage is one turn's token accounting. CacheHit/CacheMiss come from the
// provider's `prompt_cache_hit_tokens` / `prompt_cache_miss_tokens` fields and
// drive cost tracking (§3.1).
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	ReasoningTokens  int
	CacheHitTokens   int
	CacheMissTokens  int
}

// validateRequest rejects a request the client cannot faithfully send. It is
// shared by every implementation so the seam's input contract is identical
// regardless of which client a test binds.
func validateRequest(req ModelRequest) error {
	if req.Model == "" {
		return fmt.Errorf("%w: model ID is required", ErrUnknownModel)
	}
	for i, m := range req.Messages {
		switch m.Role {
		case RoleSystem, RoleUser, RoleAssistant, RoleTool:
		case "":
			return fmt.Errorf("model: message %d: role is required", i)
		default:
			return fmt.Errorf("model: message %d: unknown role %q", i, m.Role)
		}
		if m.Role == RoleTool && m.ToolCallID == "" {
			return fmt.Errorf("model: message %d: a tool message requires a tool_call_id", i)
		}
	}
	return nil
}
