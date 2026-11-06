package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/engagementstate"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
)

// headlessOptions is buildOptions plus the two streams a headless run writes
// to, so a test can assert the split itself.
func headlessOptions(t *testing.T, dir string, client *fakemodel.Fake, task string, out, errOut *strings.Builder) Options {
	t.Helper()
	opts := buildOptions(t, dir, client)
	opts.NonInteractive = true
	opts.Task = task
	opts.Version = "v0.1.0"
	opts.Stdout = out
	opts.Stderr = errOut
	return opts
}

// TestHeadlessPromptDeniedNoOperator covers §3: with no operator a prompt is a
// deny carrying `no-operator`, the turn continues, and the run reports itself
// not clean.
func TestHeadlessPromptDeniedNoOperator(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "old\n")
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "write_file", `{"path":"a.txt","content":"new\n"}`)),
		fakemodel.Text("done"),
	))
	var out, errOut strings.Builder

	if err := Run(context.Background(), headlessOptions(t, dir, fake, "write a.txt", &out, &errOut)); err != nil {
		t.Fatalf("Run() = %v", err)
	}

	if got := readAppFile(t, filepath.Join(dir, "a.txt")); got != "old\n" {
		t.Errorf("a.txt = %q, want the prompted write denied", got)
	}
	if got := strings.TrimSpace(out.String()); got != "done" {
		t.Errorf("stdout = %q, want the answer alone", out.String())
	}
	transcript := errOut.String()
	for _, want := range []string{
		"styx: v0.1.0 · safe mode · session ",
		"! deny write_file (no operator: not permitted non-interactively)",
		"styx: done — 2 turns",
		"styx: usage ",
		"styx: denied 1 prompt (run not clean)",
		"(audit ",
	} {
		if !strings.Contains(transcript, want) {
			t.Errorf("stderr does not contain %q:\n%s", want, transcript)
		}
	}

	// The audit distinguishes the silence from a rule deny (§3).
	var found bool
	for _, rec := range readAuditRecords(t, dir) {
		if rec.Tool != "write_file" {
			continue
		}
		found = true
		if rec.Verdict != audit.VerdictDeny || rec.Reason != "no-operator" {
			t.Errorf("audit record = %s/%s, want deny/no-operator", rec.Verdict, rec.Reason)
		}
	}
	if !found {
		t.Fatal("no audit record for the denied write")
	}
}

// TestHeadlessAppliesAllowedDiff covers §4.1: a committed overlay rule that
// already allowed the write is what authorizes the change, so the diff applies
// without a card.
func TestHeadlessAppliesAllowedDiff(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "old\n")
	if err := os.MkdirAll(filepath.Join(dir, ".styx"), 0o750); err != nil {
		t.Fatalf("mkdir .styx: %v", err)
	}
	writeFile(t, dir, ".styx/config.yaml", "permissions:\n  rules:\n    - tool: write_file\n      action: allow\n")
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "write_file", `{"path":"a.txt","content":"new\n"}`)),
		fakemodel.Text("done"),
	))
	var out, errOut strings.Builder

	if err := Run(context.Background(), headlessOptions(t, dir, fake, "write a.txt", &out, &errOut)); err != nil {
		t.Fatalf("Run() = %v", err)
	}

	if got := readAppFile(t, filepath.Join(dir, "a.txt")); got != "new\n" {
		t.Errorf("a.txt = %q, want the already-allowed write applied", got)
	}
	if strings.Contains(errOut.String(), "! rejected") {
		t.Errorf("stderr reports a rejection for an allowed write:\n%s", errOut.String())
	}
	if strings.Contains(errOut.String(), "(run not clean)") {
		t.Errorf("stderr reports a blocked run for an allowed write:\n%s", errOut.String())
	}
}

// TestHeadlessInterruptsTurn covers §7: the first signal cancels the in-flight
// turn and the run ends broken, not successful.
func TestHeadlessInterruptsTurn(t *testing.T) {
	dir := t.TempDir()
	// The turn blocks until its context is canceled, so the signal is certain
	// to be delivered while the turn is in flight.
	fake := fakemodel.New(
		fakemodel.WithTurns(fakemodel.Turn{Text: []string{"late"}, Delay: time.Second}),
		fakemodel.WithSleeper(func(ctx context.Context, _ time.Duration) error {
			<-ctx.Done()
			return ctx.Err()
		}),
	)
	var out, errOut strings.Builder

	signals := make(chan os.Signal, 2)
	previous := notifyHeadlessSignals
	notifyHeadlessSignals = func() (<-chan os.Signal, func()) {
		return signals, func() {}
	}
	t.Cleanup(func() { notifyHeadlessSignals = previous })
	signals <- os.Interrupt

	err := Run(context.Background(), headlessOptions(t, dir, fake, "long task", &out, &errOut))
	if !errors.Is(err, errInterrupted) {
		t.Fatalf("Run() = %v, want errInterrupted", err)
	}
	if !strings.Contains(errOut.String(), "! interrupted") {
		t.Errorf("stderr does not report the interrupt:\n%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "styx: session ") {
		t.Errorf("stderr has no end summary after an interrupt:\n%s", errOut.String())
	}
	if got := strings.TrimSpace(out.String()); got != "" {
		t.Errorf("stdout = %q, want no answer from an interrupted turn", got)
	}
}

// TestHeadlessRefusesLockedEngagementStore covers §5.4: a headless run that
// would record nothing refuses to start rather than exit successfully having
// scanned nothing.
func TestHeadlessRefusesLockedEngagementStore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "engagement.yaml", inSessionEngagement)
	var out, errOut strings.Builder
	opts := headlessOptions(t, dir, fakemodel.New(fakemodel.WithTurns(fakemodel.Text("hi"))), "look around", &out, &errOut)
	opts.Engagement = filepath.Join(dir, "engagement.yaml")

	// Hold the write lock from a different session in this process: the store
	// opens read-only, which is what the headless run must refuse.
	held, err := engagementstate.Open(dir, "in-session")
	if err != nil {
		t.Fatalf("open engagement state: %v", err)
	}
	defer func() { _ = held.Close() }()

	err = Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run() = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "locked by") || !strings.Contains(err.Error(), "pid") {
		t.Errorf("error = %v, want a refusal naming the holder", err)
	}
}

// TestHeadlessDenialCountIsAuthoritative keeps the summary's count honest: two
// denied prompts are two, and an ROE hard deny is not a prompt denial.
func TestHeadlessDenialCountIsAuthoritative(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "old\n")
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(
			fakemodel.Call("call-1", "bash", `{"command":"ls"}`),
			fakemodel.Call("call-2", "write_file", `{"path":"a.txt","content":"x"}`),
			fakemodel.Call("call-3", "read_file", `{"path":"a.txt"}`),
		),
		fakemodel.Text("done"),
	))
	var out, errOut strings.Builder

	if err := Run(context.Background(), headlessOptions(t, dir, fake, "two calls", &out, &errOut)); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if !strings.Contains(errOut.String(), "styx: denied 2 prompts (run not clean)") {
		t.Errorf("stderr does not count both denials:\n%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "> read_file path=a.txt") {
		t.Errorf("stderr has no operation line for the allowed read:\n%s", errOut.String())
	}
	if strings.Count(errOut.String(), "no operator: not permitted non-interactively") != 2 {
		t.Errorf("stderr should report each denial once:\n%s", errOut.String())
	}
}
