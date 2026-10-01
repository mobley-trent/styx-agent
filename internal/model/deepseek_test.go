package model

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/model/stubserver"
)

// newStubClient wires a DeepSeek client at a stub server, with no real waiting
// so retry tests are instant.
func newStubClient(t *testing.T, stub *stubserver.Server, ids ...string) *DeepSeekClient {
	t.Helper()
	infos := make([]Info, 0, len(ids))
	for _, id := range ids {
		infos = append(infos, Info{ID: id, ContextWindow: 1 << 20})
	}
	c, err := NewDeepSeek(DeepSeekConfig{
		APIKey:       "test-key",
		BaseURL:      stub.URL(),
		Models:       infos,
		DefaultModel: ids[0],
		HTTPClient:   stub.Client(),
	},
		WithDeepSeekSleeper(func(context.Context, time.Duration) error { return nil }),
		WithDeepSeekBackoff(func(int) time.Duration { return 0 }),
	)
	if err != nil {
		t.Fatalf("NewDeepSeek() error = %v", err)
	}
	return c
}

// readTools returns a strict tool schema for read_file.
func readTools() []Tool {
	return []Tool{{
		Name:        "read_file",
		Description: "Read a file",
		Strict:      true,
		Parameters:  json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`),
	}}
}

// collect drains a stream, failing on a terminal error event.
func collect(t *testing.T, ch <-chan StreamEvent) []StreamEvent {
	t.Helper()
	var events []StreamEvent
	for ev := range ch {
		if ev.Kind == EventError {
			t.Fatalf("unexpected stream error: %v", ev.Err)
		}
		events = append(events, ev)
	}
	return events
}

// TestStreamTurnToolCallRoundTrip is the client integration acceptance: a
// streaming turn against the stub server carries a tool_calls round-trip, and
// reasoning_content is surfaced separately from final text.
func TestStreamTurnToolCallRoundTrip(t *testing.T) {
	stub := stubserver.New(stubserver.WithScript(stubserver.Turn{
		Reasoning: []string{"Weighing ", "options."},
		Text:      []string{"Reading ", "the file."},
		ToolCalls: []stubserver.ScriptedToolCall{{
			ID: "call_1", Name: "read_file", Arguments: `{"path":"README.md"}`,
		}},
		Usage: &stubserver.Usage{
			PromptTokens: 120, CompletionTokens: 24, TotalTokens: 144,
			PromptCacheHitTokens: 100, PromptCacheMissTokens: 20,
		},
		KeepAlives: true,
	}))
	defer stub.Close()

	c := newStubClient(t, stub, "deepseek-flash")
	ctx := context.Background()
	ch, err := c.StreamTurn(ctx, ModelRequest{
		Model:    "deepseek-flash",
		Messages: []Message{{Role: RoleUser, Content: "read the readme"}},
		Tools:    readTools(),
	})
	if err != nil {
		t.Fatalf("StreamTurn() error = %v", err)
	}
	events := collect(t, ch)

	var reasoning, text strings.Builder
	var calls []ToolCall
	var usage *Usage
	for _, ev := range events {
		switch ev.Kind {
		case EventReasoningDelta:
			reasoning.WriteString(ev.Reasoning)
		case EventTextDelta:
			text.WriteString(ev.Text)
		case EventToolCall:
			calls = append(calls, *ev.ToolCall)
		case EventDone:
			usage = ev.Usage
		}
	}

	if got, want := reasoning.String(), "Weighing options."; got != want {
		t.Errorf("reasoning = %q, want %q", got, want)
	}
	if got, want := text.String(), "Reading the file."; got != want {
		t.Errorf("text = %q, want %q (reasoning must not merge into final text)", got, want)
	}
	if len(calls) != 1 {
		t.Fatalf("tool calls = %d, want 1", len(calls))
	}
	if calls[0].Name != "read_file" || calls[0].Arguments != `{"path":"README.md"}` {
		t.Errorf("tool call = %+v, want the assembled read_file call", calls[0])
	}
	if calls[0].ID != "call_1" {
		t.Errorf("tool call ID = %q, want call_1", calls[0].ID)
	}
	if usage == nil {
		t.Fatal("no usage reported on EventDone")
	}
	if usage.PromptTokens != 120 || usage.CompletionTokens != 24 || usage.TotalTokens != 144 {
		t.Errorf("usage = %+v, want prompt 120 / completion 24 / total 144", usage)
	}
	if usage.CacheHitTokens != 100 || usage.CacheMissTokens != 20 {
		t.Errorf("cache usage = %d/%d, want 100/20", usage.CacheHitTokens, usage.CacheMissTokens)
	}

	// Strict tools go to the beta endpoint (§3.3), and the key rides the wire.
	req, ok := stub.LastRequest()
	if !ok {
		t.Fatal("stub recorded no request")
	}
	if req.Path != "/beta/chat/completions" {
		t.Errorf("request path = %q, want /beta/chat/completions (strict mode)", req.Path)
	}
	if req.Authorization != "Bearer test-key" {
		t.Errorf("Authorization = %q, want Bearer test-key", req.Authorization)
	}
}

// TestStreamTurnNonStrictEndpoint pins that a non-strict turn uses the plain
// endpoint.
func TestStreamTurnNonStrictEndpoint(t *testing.T) {
	stub := stubserver.New(stubserver.WithScript(stubserver.Text("hi")))
	defer stub.Close()

	c := newStubClient(t, stub, "deepseek-flash")
	ch, err := c.StreamTurn(context.Background(), ModelRequest{
		Model:    "deepseek-flash",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("StreamTurn() error = %v", err)
	}
	collect(t, ch)

	req, _ := stub.LastRequest()
	if req.Path != "/chat/completions" {
		t.Errorf("request path = %q, want /chat/completions", req.Path)
	}
}

// TestRetryBacksOffOn429 is the fault acceptance: 429s are retried with
// backoff until the turn succeeds, up to 5 attempts.
func TestRetryBacksOffOn429(t *testing.T) {
	stub := stubserver.New(stubserver.WithScript(
		stubserver.FaultStatus(429),
		stubserver.FaultStatus(429),
		stubserver.Text("recovered"),
	))
	defer stub.Close()

	var delays []time.Duration
	c, err := NewDeepSeek(DeepSeekConfig{
		APIKey: "test-key", BaseURL: stub.URL(),
		Models: []Info{{ID: "deepseek-flash"}}, DefaultModel: "deepseek-flash",
		HTTPClient: stub.Client(),
	},
		WithDeepSeekSleeper(func(_ context.Context, d time.Duration) error {
			delays = append(delays, d)
			return nil
		}),
		WithDeepSeekBackoff(func(attempt int) time.Duration { return time.Duration(attempt) * time.Second }),
	)
	if err != nil {
		t.Fatalf("NewDeepSeek() error = %v", err)
	}

	ch, err := c.StreamTurn(context.Background(), ModelRequest{Model: "deepseek-flash"})
	if err != nil {
		t.Fatalf("StreamTurn() error = %v", err)
	}
	events := collect(t, ch)
	if got := events[len(events)-1].Kind; got != EventDone {
		t.Errorf("last event = %v, want EventDone", got)
	}
	if stub.Calls() != 3 {
		t.Errorf("stub calls = %d, want 3 (two 429s then success)", stub.Calls())
	}
	want := []time.Duration{time.Second, 2 * time.Second}
	if fmt.Sprint(delays) != fmt.Sprint(want) {
		t.Errorf("backoff delays = %v, want %v", delays, want)
	}
}

// TestRetryExhaustedAfterFiveAttempts pins the 5-attempt ceiling.
func TestRetryExhaustedAfterFiveAttempts(t *testing.T) {
	stub := stubserver.New(
		stubserver.WithScript(stubserver.FaultStatus(500)),
		stubserver.WithRepeatLast(true),
	)
	defer stub.Close()

	c := newStubClient(t, stub, "deepseek-flash")
	_, err := c.StreamTurn(context.Background(), ModelRequest{Model: "deepseek-flash"})
	if !errors.Is(err, ErrRetryExhausted) {
		t.Fatalf("StreamTurn() error = %v, want ErrRetryExhausted", err)
	}
	if stub.Calls() != DefaultMaxRetries {
		t.Errorf("stub calls = %d, want %d attempts", stub.Calls(), DefaultMaxRetries)
	}
}

// TestNonRetryableStatusFailsFast pins that a 4xx other than 429 is not
// retried.
func TestNonRetryableStatusFailsFast(t *testing.T) {
	stub := stubserver.New(stubserver.WithScript(stubserver.FaultStatus(401)))
	defer stub.Close()

	c := newStubClient(t, stub, "deepseek-flash")
	_, err := c.StreamTurn(context.Background(), ModelRequest{Model: "deepseek-flash"})
	if err == nil {
		t.Fatal("StreamTurn() = nil error, want auth failure")
	}
	if errors.Is(err, ErrRetryExhausted) {
		t.Errorf("error = %v, want a non-retryable failure", err)
	}
	if stub.Calls() != 1 {
		t.Errorf("stub calls = %d, want 1 (no retry on 401)", stub.Calls())
	}
}

// TestValidateRejectsUnknownModel is the startup acceptance: an unknown pinned
// model ID is rejected against GET /models.
func TestValidateRejectsUnknownModel(t *testing.T) {
	stub := stubserver.New(stubserver.WithModels("deepseek-flash"))
	defer stub.Close()

	c := newStubClient(t, stub, "deepseek-flash", "deepseek-v4-pro")
	err := c.Validate(context.Background())
	if !errors.Is(err, ErrUnknownModel) {
		t.Fatalf("Validate() error = %v, want ErrUnknownModel", err)
	}
	if !strings.Contains(err.Error(), "deepseek-v4-pro") {
		t.Errorf("Validate() error = %q, want it to name the unknown ID", err)
	}
}

// TestValidateAcceptsKnownModels is the positive half of the startup check.
func TestValidateAcceptsKnownModels(t *testing.T) {
	stub := stubserver.New(stubserver.WithModels("deepseek-flash", "deepseek-v4-pro"))
	defer stub.Close()

	c := newStubClient(t, stub, "deepseek-flash", "deepseek-v4-pro")
	if err := c.Validate(context.Background()); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

// TestStreamTurnRejectsUnknownRequestModel pins that an unpinned request model
// never reaches the wire.
func TestStreamTurnRejectsUnknownRequestModel(t *testing.T) {
	stub := stubserver.New(stubserver.WithScript(stubserver.Text("hi")))
	defer stub.Close()

	c := newStubClient(t, stub, "deepseek-flash")
	_, err := c.StreamTurn(context.Background(), ModelRequest{Model: "deepseek-v4-pro"})
	if !errors.Is(err, ErrUnknownModel) {
		t.Fatalf("StreamTurn() error = %v, want ErrUnknownModel", err)
	}
	if stub.Calls() != 0 {
		t.Errorf("stub calls = %d, want 0 (rejected before the wire)", stub.Calls())
	}
}

// TestReplayThroughStubServer is the replay acceptance end to end: the
// versioned transcript fixture is served by the stub server (its replay mode)
// and consumed by the real client.
func TestReplayThroughStubServer(t *testing.T) {
	stub, err := stubserver.ReplayFile("../testdata/transcripts/basic.json")
	if err != nil {
		t.Fatalf("ReplayFile() error = %v", err)
	}
	defer stub.Close()

	c := newStubClient(t, stub, "deepseek-flash")
	ch, err := c.StreamTurn(context.Background(), ModelRequest{
		Model:    "deepseek-flash",
		Messages: []Message{{Role: RoleUser, Content: "read the readme"}},
		Tools:    readTools(),
	})
	if err != nil {
		t.Fatalf("StreamTurn() error = %v", err)
	}
	events := collect(t, ch)

	var reasoning, text strings.Builder
	var calls []ToolCall
	for _, ev := range events {
		switch ev.Kind {
		case EventReasoningDelta:
			reasoning.WriteString(ev.Reasoning)
		case EventTextDelta:
			text.WriteString(ev.Text)
		case EventToolCall:
			calls = append(calls, *ev.ToolCall)
		}
	}
	if !strings.Contains(reasoning.String(), "read_file") {
		t.Errorf("replayed reasoning = %q, want the fixture's reasoning", reasoning.String())
	}
	if !strings.Contains(text.String(), "README.md") {
		t.Errorf("replayed text = %q, want the fixture's text", text.String())
	}
	if len(calls) != 1 || calls[0].Name != "read_file" {
		t.Errorf("replayed tool calls = %+v, want the fixture's read_file call", calls)
	}
}

// TestStreamTurnUsesDefaultModel pins the empty-model fallback: a request that
// names no model uses the configured default.
func TestStreamTurnUsesDefaultModel(t *testing.T) {
	stub := stubserver.New(stubserver.WithScript(stubserver.Text("hi")))
	defer stub.Close()

	c := newStubClient(t, stub, "deepseek-flash")
	ch, err := c.StreamTurn(context.Background(), ModelRequest{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("StreamTurn() error = %v", err)
	}
	collect(t, ch)

	req, _ := stub.LastRequest()
	if req.Model != "deepseek-flash" {
		t.Errorf("wire model = %q, want the configured default", req.Model)
	}
}

// TestNewDeepSeekRejectsBadConfig covers the constructor's input contract.
func TestNewDeepSeekRejectsBadConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  DeepSeekConfig
	}{
		{"no api key", DeepSeekConfig{Models: []Info{{ID: "m"}}}},
		{"no models", DeepSeekConfig{APIKey: "k"}},
		{"empty model id", DeepSeekConfig{APIKey: "k", Models: []Info{{ID: " "}}}},
		{"default not pinned", DeepSeekConfig{APIKey: "k", Models: []Info{{ID: "m"}}, DefaultModel: "other"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewDeepSeek(tt.cfg); err == nil {
				t.Fatal("NewDeepSeek() = nil error, want rejection")
			}
		})
	}
}
