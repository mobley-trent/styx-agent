package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
)

// TestLazyModelClientRetriesAfterFailure pins the deferred provider's
// recoverability (§1 "fail on demand"): a failed build is reported at its point
// of use, marks the status bar degraded, and is not cached, so the next turn
// retries and can recover without a restart.
func TestLazyModelClientRetriesAfterFailure(t *testing.T) {
	var calls atomic.Int32
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("ok")))
	client := newLazyModelClient(func(context.Context) (model.ModelClient, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("offline")
		}
		return fake, nil
	}, "")

	if _, err := client.StreamTurn(context.Background(), model.ModelRequest{Model: "m"}); err == nil {
		t.Fatal("first StreamTurn() = nil error, want the deferred-build failure")
	}
	if got := client.ProviderStatus(); got != "provider unavailable" {
		t.Errorf("ProviderStatus() = %q, want %q", got, "provider unavailable")
	}

	ch, err := client.StreamTurn(context.Background(), model.ModelRequest{Model: "m"})
	if err != nil {
		t.Fatalf("second StreamTurn() = %v, want a recovered turn", err)
	}
	for range ch { //nolint:revive // drain the stream so the fake's goroutine ends.
	}
	if got := client.ProviderStatus(); got != "" {
		t.Errorf("ProviderStatus() after recovery = %q, want empty", got)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("resolve called %d times, want 2 (a failure is not cached)", got)
	}
}

// TestLazyModelClientCachesSuccess pins that a resolved provider is built once.
func TestLazyModelClientCachesSuccess(t *testing.T) {
	var calls atomic.Int32
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("one"), fakemodel.Text("two")))
	client := newLazyModelClient(func(context.Context) (model.ModelClient, error) {
		calls.Add(1)
		return fake, nil
	}, "")

	for i := 0; i < 2; i++ {
		ch, err := client.StreamTurn(context.Background(), model.ModelRequest{Model: "m"})
		if err != nil {
			t.Fatalf("StreamTurn(%d) = %v, want nil", i, err)
		}
		for range ch { //nolint:revive // drain the stream.
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("resolve called %d times, want 1 (a success is cached)", got)
	}
}

// TestNewLazyModelClientInitialStatus pins that a known-before-first-turn
// problem (a missing credential) shows in the status bar immediately.
func TestNewLazyModelClientInitialStatus(t *testing.T) {
	client := newLazyModelClient(func(context.Context) (model.ModelClient, error) {
		return nil, errNoAPIKey
	}, "no api key")
	if got := client.ProviderStatus(); got != "no api key" {
		t.Errorf("ProviderStatus() = %q, want %q", got, "no api key")
	}
}
