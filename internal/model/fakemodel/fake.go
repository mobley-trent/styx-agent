// Package fakemodel is the in-process, per-test-scriptable stand-in for the
// model (docs/spec.md §11.2, layer 1). It implements the model.ModelClient
// seam — the single model boundary — so every agent-loop, policy, and
// compaction test runs against canned multi-turn scripts with fault injection
// and turn counting, and no test ever talks to a live model.
//
// Boundary rule: this package depends only on internal/model. It never
// executes tools and never reaches the network.
package fakemodel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mobley-trent/styx-agent/internal/model"
)

// Turn is one scripted model turn: the events the fake yields, in order. The
// zero Turn is a successful, empty turn that still emits EventDone.
type Turn struct {
	// Text chunks emit as EventTextDelta events, in order.
	Text []string
	// Reasoning chunks emit as EventReasoningDelta events, in order. They are
	// yielded before Text, matching a reasoning model's stream.
	Reasoning []string
	// ToolCalls emit as complete EventToolCall events, after text/reasoning.
	ToolCalls []model.ToolCall
	// Usage rides the terminal EventDone event (nil is allowed).
	Usage *model.Usage
	// Delay sleeps before each emitted event, letting tests exercise
	// cancellation and slow streams. Zero emits immediately.
	Delay time.Duration
	// StreamErr, when set, terminates the turn with a terminal EventError
	// after everything else has been emitted.
	StreamErr error
	// StartErr, when set, makes StreamTurn itself fail: the turn never starts
	// and no channel is returned. It models a transport failure after the
	// client's own retries.
	StartErr error
}

// Fake is the scriptable fake model. It is safe for concurrent use: each
// StreamTurn consumes the next scripted turn under a lock and records the
// request.
type Fake struct {
	mu       sync.Mutex
	turns    []Turn
	next     int
	calls    int
	requests []model.ModelRequest

	repeatLast bool
	sleeper    func(context.Context, time.Duration) error
	now        func() time.Time
}

var _ model.ModelClient = (*Fake)(nil)

// Option configures a Fake at construction.
type Option func(*Fake)

// WithRepeatLast makes the fake replay its final turn for every request once
// the script is exhausted, instead of failing. Loop tests that only care about
// bounds use it.
func WithRepeatLast(repeat bool) Option {
	return func(f *Fake) { f.repeatLast = repeat }
}

// WithSleeper overrides how the fake waits between events. Tests inject a
// no-op so a scripted Delay costs no wall time.
func WithSleeper(fn func(context.Context, time.Duration) error) Option {
	return func(f *Fake) {
		if fn != nil {
			f.sleeper = fn
		}
	}
}

// WithClock overrides the clock the fake stamps its events with.
func WithClock(now func() time.Time) Option {
	return func(f *Fake) {
		if now != nil {
			f.now = now
		}
	}
}

// WithTurns sets the scripted turns, consumed in order.
func WithTurns(turns ...Turn) Option {
	return func(f *Fake) { f.turns = append([]Turn(nil), turns...) }
}

// New builds a fake model. Script it with WithTurns; behavior (repeat-last,
// injected clock and sleeper) arrives through the other options.
func New(opts ...Option) *Fake {
	f := &Fake{
		sleeper: sleepCtx,
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// Append adds turns to the end of the script. It does not disturb the cursor.
func (f *Fake) Append(turns ...Turn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.turns = append(f.turns, turns...)
}

// Calls reports how many turns have been requested so far (turn counting).
func (f *Fake) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// Requests returns a copy of every request the fake has received, in order.
func (f *Fake) Requests() []model.ModelRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.ModelRequest(nil), f.requests...)
}

// LastRequest returns the most recent request and whether any was made.
func (f *Fake) LastRequest() (model.ModelRequest, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		return model.ModelRequest{}, false
	}
	return f.requests[len(f.requests)-1], true
}

// StreamTurn implements model.ModelClient: it consumes the next scripted turn
// and yields its events on a channel.
func (f *Fake) StreamTurn(ctx context.Context, req model.ModelRequest) (<-chan model.StreamEvent, error) {
	if req.Model == "" {
		req.Model = "fake-model"
	}
	turn, err := f.take(req)
	if err != nil {
		return nil, err
	}
	if turn.StartErr != nil {
		return nil, turn.StartErr
	}

	ch := make(chan model.StreamEvent, 8)
	go f.pump(ctx, turn, ch)
	return ch, nil
}

// take records the request and consumes the next turn under the lock.
func (f *Fake) take(req model.ModelRequest) (Turn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.requests = append(f.requests, req)

	switch {
	case f.next < len(f.turns):
		turn := f.turns[f.next]
		f.next++
		return turn, nil
	case f.repeatLast && len(f.turns) > 0:
		return f.turns[len(f.turns)-1], nil
	default:
		return Turn{}, fmt.Errorf("fakemodel: script exhausted after %d turn(s)", f.next)
	}
}

// pump emits a turn's events and closes the channel.
func (f *Fake) pump(ctx context.Context, turn Turn, ch chan<- model.StreamEvent) {
	defer close(ch)

	emit := func(ev model.StreamEvent) bool {
		if turn.Delay > 0 {
			if err := f.sleeper(ctx, turn.Delay); err != nil {
				f.send(ctx, ch, model.StreamEvent{Kind: model.EventError, Err: err, At: f.now()})
				return false
			}
		}
		return f.send(ctx, ch, ev)
	}

	for _, r := range turn.Reasoning {
		if !emit(model.StreamEvent{Kind: model.EventReasoningDelta, Reasoning: r, At: f.now()}) {
			return
		}
	}
	for _, t := range turn.Text {
		if !emit(model.StreamEvent{Kind: model.EventTextDelta, Text: t, At: f.now()}) {
			return
		}
	}
	for i := range turn.ToolCalls {
		call := turn.ToolCalls[i]
		if !emit(model.StreamEvent{Kind: model.EventToolCall, ToolCall: &call, At: f.now()}) {
			return
		}
	}
	if turn.StreamErr != nil {
		f.send(ctx, ch, model.StreamEvent{Kind: model.EventError, Err: turn.StreamErr, At: f.now()})
		return
	}
	f.send(ctx, ch, model.StreamEvent{Kind: model.EventDone, Usage: turn.Usage, At: f.now()})
}

// send delivers one event unless the context is gone.
func (f *Fake) send(ctx context.Context, ch chan<- model.StreamEvent, ev model.StreamEvent) bool {
	select {
	case ch <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// --- Scripting helpers ---

// Text is a text-only turn, one delta per chunk.
func Text(chunks ...string) Turn { return Turn{Text: chunks} }

// Reasoning is a reasoning-only turn, one delta per chunk.
func Reasoning(chunks ...string) Turn { return Turn{Reasoning: chunks} }

// Call builds a tool-call descriptor.
func Call(id, name, argsJSON string) model.ToolCall {
	return model.ToolCall{ID: id, Name: name, Arguments: argsJSON}
}

// ToolCalls is a turn that emits the given tool calls and nothing else.
func ToolCalls(calls ...model.ToolCall) Turn { return Turn{ToolCalls: calls} }

// Fault is a turn that makes StreamTurn itself fail — a transport fault before
// the turn starts.
func Fault(err error) Turn { return Turn{StartErr: err} }

// StreamError is a turn that starts, emits nothing, then fails mid-stream.
func StreamError(err error) Turn { return Turn{StreamErr: err} }

// ErrExhausted is returned when a script runs out of turns and the fake is not
// set to repeat its last one.
var ErrExhausted = errors.New("fakemodel: script exhausted")
