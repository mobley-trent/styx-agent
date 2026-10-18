package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The TUI's Escape key aborts the in-flight turn through turnRunner: the turn
// runs under its own cancelable context, and interrupting it must never take
// down the program's context or leak into the next turn
// (docs/tui-parity.md §5).

func TestTurnRunnerRunsOneTurnAtATime(t *testing.T) {
	turns := &turnRunner{}
	release := make(chan struct{})
	started := make(chan struct{})

	if !turns.run(context.Background(), func(context.Context) {
		close(started)
		<-release
	}) {
		t.Fatal("first run was refused, want it to start")
	}
	<-started

	// The loop is not reentrant: a second turn while one is in flight is
	// dropped rather than queued.
	if turns.run(context.Background(), func(context.Context) {}) {
		t.Error("second run was accepted while a turn was in flight")
	}
	if !turns.active() {
		t.Error("active() = false while a turn is in flight")
	}

	close(release)
	waitIdle(t, turns)
	if !turns.run(context.Background(), func(context.Context) {}) {
		t.Error("run was refused after the previous turn finished")
	}
	waitIdle(t, turns)
}

func TestTurnRunnerInterruptCancelsTheInFlightTurn(t *testing.T) {
	idle := make(chan struct{})
	turns := &turnRunner{onIdle: func() { close(idle) }}
	canceled := make(chan struct{})
	started := make(chan struct{})

	turns.run(context.Background(), func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		if err := ctx.Err(); !errors.Is(err, context.Canceled) {
			t.Errorf("turn context err = %v, want context.Canceled", err)
		}
		close(canceled)
	})
	<-started

	turns.interrupt()

	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("interrupt did not cancel the in-flight turn")
	}
	select {
	case <-idle:
	case <-time.After(5 * time.Second):
		t.Fatal("the turn never reported itself idle again")
	}
	if turns.active() {
		t.Error("active() = true after the interrupted turn ended")
	}
	// Interrupting again is harmless: the finished turn's cancel func is gone.
	turns.interrupt()
}

// A turn's context is a child of the program's, so interrupting one turn leaves
// the program's context — and the next turn — alive.
func TestTurnRunnerInterruptLeavesTheProgramContextAlive(t *testing.T) {
	program, cancelProgram := context.WithCancel(context.Background())
	defer cancelProgram()

	turns := &turnRunner{}
	started := make(chan struct{})
	done := make(chan error, 1)
	turns.run(program, func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		done <- ctx.Err()
	})
	<-started
	turns.interrupt()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("interrupted turn err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("interrupt did not cancel the in-flight turn")
	}
	waitIdle(t, turns)
	if program.Err() != nil {
		t.Errorf("program context err = %v, want it untouched by an interrupt", program.Err())
	}
}

// An interrupt that arrives while nothing is running is a no-op: it must not
// cancel a turn that has not started yet.
func TestTurnRunnerInterruptWhileIdleIsNoop(t *testing.T) {
	turns := &turnRunner{}
	turns.interrupt()

	ran := make(chan struct{})
	turns.run(context.Background(), func(ctx context.Context) {
		close(ran)
		if ctx.Err() != nil {
			t.Errorf("turn context err = %v, want a live context", ctx.Err())
		}
	})
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("the turn did not run")
	}
	waitIdle(t, turns)
}

// waitIdle blocks until the runner reports no turn in flight.
func waitIdle(t *testing.T, turns *turnRunner) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for turns.active() {
		if time.Now().After(deadline) {
			t.Fatal("runner never became idle")
		}
		time.Sleep(time.Millisecond)
	}
}
