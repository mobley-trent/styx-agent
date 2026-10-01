package fakemodel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/model"
)

// drain collects events until the channel closes, returning the terminal
// error if any.
func drain(ch <-chan model.StreamEvent) ([]model.StreamEvent, error) {
	var events []model.StreamEvent
	var terminal error
	for ev := range ch {
		events = append(events, ev)
		if ev.Kind == model.EventError {
			terminal = ev.Err
		}
	}
	return events, terminal
}

// TestFakePlaysCannedMultiTurnScript is the fake acceptance: canned multi-turn
// scripts, turn counting, and request recording.
func TestFakePlaysCannedMultiTurnScript(t *testing.T) {
	f := New(WithTurns(
		Text("first"),
		Turn{Reasoning: []string{"hmm"}, ToolCalls: []model.ToolCall{Call("c1", "read_file", `{"path":"x"}`)}},
	))
	ctx := context.Background()

	ch, err := f.StreamTurn(ctx, model.ModelRequest{Messages: []model.Message{{Role: model.RoleUser, Content: "one"}}})
	if err != nil {
		t.Fatalf("turn 1: StreamTurn() error = %v", err)
	}
	events, terminal := drain(ch)
	if terminal != nil {
		t.Fatalf("turn 1 terminal error = %v", terminal)
	}
	if got := events[len(events)-1].Kind; got != model.EventDone {
		t.Errorf("turn 1 last event = %v, want EventDone", got)
	}

	ch, err = f.StreamTurn(ctx, model.ModelRequest{Messages: []model.Message{{Role: model.RoleUser, Content: "two"}}})
	if err != nil {
		t.Fatalf("turn 2: StreamTurn() error = %v", err)
	}
	events, _ = drain(ch)

	var reasoning, text strings.Builder
	var calls []model.ToolCall
	for _, ev := range events {
		switch ev.Kind {
		case model.EventReasoningDelta:
			reasoning.WriteString(ev.Reasoning)
		case model.EventTextDelta:
			text.WriteString(ev.Text)
		case model.EventToolCall:
			calls = append(calls, *ev.ToolCall)
		}
	}
	if reasoning.String() != "hmm" {
		t.Errorf("reasoning = %q, want hmm", reasoning.String())
	}
	if text.Len() != 0 {
		t.Errorf("text = %q, want none on a tool-call turn", text.String())
	}
	if len(calls) != 1 || calls[0].Name != "read_file" || calls[0].Arguments != `{"path":"x"}` {
		t.Errorf("calls = %+v, want the scripted read_file call", calls)
	}

	if f.Calls() != 2 {
		t.Errorf("Calls() = %d, want 2 (turn counting)", f.Calls())
	}
	reqs := f.Requests()
	if len(reqs) != 2 || reqs[0].Messages[0].Content != "one" || reqs[1].Messages[0].Content != "two" {
		t.Errorf("Requests() = %+v, want both recorded in order", reqs)
	}
}

// TestFakeFaultInjection covers both fault seams: a transport fault before the
// turn starts, and a mid-stream error event.
func TestFakeFaultInjection(t *testing.T) {
	startErr := errors.New("dial failed")
	f := New(WithTurns(Fault(startErr), StreamError(errors.New("connection reset"))))
	ctx := context.Background()

	if _, err := f.StreamTurn(ctx, model.ModelRequest{}); !errors.Is(err, startErr) {
		t.Fatalf("StreamTurn() error = %v, want the injected start fault", err)
	}

	ch, err := f.StreamTurn(ctx, model.ModelRequest{})
	if err != nil {
		t.Fatalf("StreamTurn() error = %v", err)
	}
	_, terminal := drain(ch)
	if terminal == nil || !strings.Contains(terminal.Error(), "connection reset") {
		t.Fatalf("terminal error = %v, want the injected stream fault", terminal)
	}
}

// TestFakeExhaustion checks the default fail-loud behavior and the repeat-last
// opt-in.
func TestFakeExhaustion(t *testing.T) {
	f := New(WithTurns(Text("only")))
	ctx := context.Background()

	if _, err := f.StreamTurn(ctx, model.ModelRequest{}); err != nil {
		t.Fatalf("StreamTurn() error = %v", err)
	}
	if _, err := f.StreamTurn(ctx, model.ModelRequest{}); err == nil {
		t.Fatal("StreamTurn() = nil error, want script exhaustion")
	}

	repeat := New(WithTurns(Text("only")), WithRepeatLast(true))
	for i := 0; i < 3; i++ {
		ch, err := repeat.StreamTurn(ctx, model.ModelRequest{})
		if err != nil {
			t.Fatalf("repeat turn %d: StreamTurn() error = %v", i, err)
		}
		_, _ = drain(ch)
	}
	if repeat.Calls() != 3 {
		t.Errorf("Calls() = %d, want 3", repeat.Calls())
	}
}

// TestFakeStampsDefaultModelAndRespectsCancellation covers the model default
// and that a cancelled context closes the stream.
func TestFakeStampsDefaultModelAndRespectsCancellation(t *testing.T) {
	// A sleeper that blocks until cancellation makes the turn pause between
	// events, so the cancel genuinely interrupts a live stream.
	f := New(WithTurns(Turn{Text: []string{"a", "b"}, Delay: time.Hour}),
		WithSleeper(func(ctx context.Context, _ time.Duration) error {
			<-ctx.Done()
			return ctx.Err()
		}))

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := f.StreamTurn(ctx, model.ModelRequest{})
	if err != nil {
		t.Fatalf("StreamTurn() error = %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	cancel()
	for range ch { // draining after cancel must terminate
	}
	if _, ok := f.LastRequest(); !ok {
		t.Fatal("LastRequest() reported no request")
	}
	if got := f.Requests()[0].Model; got != "fake-model" {
		t.Errorf("recorded model = %q, want fake-model default", got)
	}
}
