package app

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// engagementFixture is the repo's IP-only engagement fixture: it loads without
// DNS, so wiring tests stay hermetic.
var engagementFixture = filepath.Join("..", "testdata", "engagement", "acme-q4-redteam.yaml")

// buildOptions prepares options for a hermetic build: config and session
// stores point at temp directories, and the clock is pinned.
func buildOptions(t *testing.T, workDir string, client model.ModelClient) Options {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	at, err := time.Parse(time.RFC3339, "2026-10-01T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		ProjectDir: workDir,
		Client:     client,
		Stdout:     io.Discard,
		Stderr:     io.Discard,
		Now:        func() time.Time { return at },
	}
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBuildSafeModeAndTurn(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n")
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "read_file", `{"path":"main.go"}`)),
		fakemodel.Text("It is a hello-world program."),
	))

	h, err := Build(context.Background(), buildOptions(t, dir, fake))
	if err != nil {
		t.Fatalf("Build() = %v, want nil", err)
	}
	defer func() { _ = h.Close() }()

	if h.Mode != policy.ModeSafe {
		t.Errorf("mode = %q, want safe (no engagement file)", h.Mode)
	}
	if h.Engagement != nil {
		t.Error("safe mode carries an engagement")
	}
	if !strings.Contains(h.Prompt, "# Coding workflow") {
		t.Error("system prompt lacks the always-on coding pack")
	}
	if strings.Contains(h.Prompt, "# Engagement") {
		t.Error("safe-mode prompt contains an engagement section")
	}

	if err := h.Submit(context.Background(), "what does main.go do?"); err != nil {
		t.Fatalf("Submit() = %v, want nil", err)
	}
	if got := h.Messages(); len(got) == 0 {
		t.Fatal("the turn produced no messages")
	} else if got[len(got)-1].Content != "It is a hello-world program." {
		t.Errorf("last message = %q, want the answer", got[len(got)-1].Content)
	}

	// Session JSONL: the turn is on disk, renderable and replayable.
	events, err := h.sessions.Replay(dir, h.SessionID())
	if err != nil {
		t.Fatalf("Replay() = %v, want nil", err)
	}
	if len(events) < 3 {
		t.Fatalf("session holds %d events, want the user turn, the call, and the answer", len(events))
	}
	if events[0].Kind != "user" || events[0].Text != "what does main.go do?" {
		t.Errorf("first session event = %+v, want the user turn", events[0])
	}

	// Audit JSONL: one record per tool call.
	auditPath := filepath.Join(dir, audit.SessionFileName(h.now()))
	//nolint:gosec // the audit path is the one the harness wrote in this test.
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit trail: %v", err)
	}
	if lines := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; lines != 1 {
		t.Errorf("audit trail holds %d records, want 1", lines)
	}
	if !strings.Contains(string(data), `"verdict":"allow"`) {
		t.Errorf("audit trail = %s, want an allow verdict", data)
	}
}

func TestBuildEngagementMode(t *testing.T) {
	dir := t.TempDir()
	opts := buildOptions(t, dir, fakemodel.New())
	opts.Engagement = engagementFixture

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v, want nil", err)
	}
	defer func() { _ = h.Close() }()

	if h.Mode != policy.ModeEngagement {
		t.Errorf("mode = %q, want engagement", h.Mode)
	}
	if h.Engagement == nil || h.Engagement.Name() != "acme-q4-redteam" {
		t.Fatalf("engagement = %+v, want the loaded fixture", h.Engagement)
	}
	prompt := h.Prompt
	for _, want := range []string{"# Engagement", "acme-q4-redteam", "- 10.0.0.0/24", "destructive-tagged calls: forbidden"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("engagement prompt is missing %q", want)
		}
	}
	if !strings.Contains(h.statusText(), "engagement: acme-q4-redteam") {
		t.Errorf("/status does not report the engagement:\n%s", h.statusText())
	}
}

func TestBuildRefusesBadEngagement(t *testing.T) {
	dir := t.TempDir()
	bad := writeFile(t, dir, "engagement.yaml", "apiVersion: styx.engagement/v1\nname: broken\n")
	opts := buildOptions(t, dir, fakemodel.New())
	opts.Engagement = bad

	if _, err := Build(context.Background(), opts); err == nil {
		t.Fatal("Build(bad engagement) = nil error, want a refuse-to-start error")
	} else if !strings.Contains(err.Error(), "refusing to start") {
		t.Errorf("Build(bad engagement) error = %v, want it to say it refused to start", err)
	}
}

func TestBuildMissingEngagementFile(t *testing.T) {
	opts := buildOptions(t, t.TempDir(), fakemodel.New())
	opts.Engagement = filepath.Join(t.TempDir(), "absent.yaml")
	if _, err := Build(context.Background(), opts); err == nil {
		t.Fatal("Build(missing engagement) = nil error, want a refuse-to-start error")
	}
}

func TestConfigOverlayPrecedence(t *testing.T) {
	dir := t.TempDir()
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	writeFile(t, configHome, filepath.Join("styx", "config.yaml"), "compaction:\n  threshold: 0.9\n  keep_turns: 5\nupdate_notifier: false\n")
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"), "compaction:\n  keep_turns: 2\nupdate_notifier: true\n")

	h, err := Build(context.Background(), Options{
		ProjectDir: dir,
		Client:     fakemodel.New(),
		Stdout:     io.Discard,
	})
	if err != nil {
		t.Fatalf("Build() = %v, want nil", err)
	}
	defer func() { _ = h.Close() }()

	if got := h.Config.Compaction.Threshold; got != 0.9 {
		t.Errorf("threshold = %v, want 0.9 (from global)", got)
	}
	if got := h.Config.Compaction.KeepTurns; got != 2 {
		t.Errorf("keep_turns = %d, want 2 (project overrides global)", got)
	}
	if !h.Config.UpdateNotifier {
		t.Error("update_notifier = false, want true (project overrides global)")
	}
}

func TestProjectRulesReachThePolicyEngine(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n")
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"), "permissions:\n  rules:\n    - tool: read_file\n      action: deny\n")

	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v, want nil", err)
	}
	defer func() { _ = h.Close() }()

	if got := h.Engine.Decide(policy.Call{Tool: "read_file"}); got.Verdict != policy.VerdictDeny {
		t.Errorf("project rule did not reach the engine: decide = %v/%s", got.Verdict, got.Reason)
	}
}

func TestBuildRequiresAPIKey(t *testing.T) {
	t.Setenv("DEEPSEEK_API_KEY", "")
	opts := buildOptions(t, t.TempDir(), nil)
	opts.SkipModelCheck = true

	_, err := Build(context.Background(), opts)
	if err == nil {
		t.Fatal("Build(no API key, no client) = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "DEEPSEEK_API_KEY") {
		t.Errorf("error = %v, want it to name the missing secret", err)
	}
}

func TestResumeRestoresConversation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n")
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.Text("the first answer"),
		fakemodel.Text("the second answer"),
	))
	opts := buildOptions(t, dir, fake)

	first, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Submit(context.Background(), "remember this question"); err != nil {
		t.Fatal(err)
	}
	id := first.SessionID()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()

	summary, err := second.Resume(id)
	if err != nil {
		t.Fatalf("Resume() = %v, want nil", err)
	}
	if summary.ID != id {
		t.Errorf("resumed %q, want %q", summary.ID, id)
	}
	if len(second.Messages()) == 0 || second.Messages()[0].Content != "remember this question" {
		t.Fatalf("restored conversation = %+v, want the original user turn", second.Messages())
	}
	if second.SessionID() != id {
		t.Errorf("session id after resume = %q, want %q", second.SessionID(), id)
	}

	// The resumed conversation is what the next model call receives.
	if err := second.Submit(context.Background(), "and this one"); err != nil {
		t.Fatal(err)
	}
	requests := fake.Requests()
	last := requests[len(requests)-1]
	if !containsMessage(last.Messages, "remember this question") || !containsMessage(last.Messages, "the first answer") {
		t.Errorf("resumed context was not replayed to the model: %+v", last.Messages)
	}
}

func containsMessage(messages []model.Message, content string) bool {
	for _, m := range messages {
		if m.Content == content {
			return true
		}
	}
	return false
}

func TestResumeListingAndUnknownID(t *testing.T) {
	dir := t.TempDir()
	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()

	out, err := h.command("resume", "")
	if err != nil {
		t.Fatalf("resume listing = %v, want nil", err)
	}
	if !strings.Contains(out, "no past sessions") {
		t.Errorf("empty resume listing = %q, want a friendly empty message", out)
	}
	if _, err := h.command("resume", "nope"); err == nil {
		t.Error("resume(unknown id) = nil error, want an error")
	}
	if _, err := h.command("bogus", ""); err == nil {
		t.Error("unknown command = nil error, want an error")
	}
	if out, err := h.command("help", ""); err != nil || !strings.Contains(out, "/resume") {
		t.Errorf("help = %q/%v, want the command list", out, err)
	}
}

func TestMemoryLoadsIntoPrompt(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "STYX.md", "# Notes\n\nRun make check.\n")

	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()

	if !strings.Contains(h.Prompt, "# Project memory (STYX.md)") || !strings.Contains(h.Prompt, "Run make check.") {
		t.Errorf("project memory did not reach the prompt:\n%s", h.Prompt)
	}
}

func TestCompactionFiresPersistsAndSurfaces(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "big.txt", strings.Repeat("noise line\n", 3000))
	writeFile(t, dir, "small.txt", "ok\n")
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"), `model: deepseek-flash
models:
  - id: deepseek-flash
    context_window: 100
    input_per_million: 0.3
    output_per_million: 1.2
    cache_hit_per_million: 0.006
compaction:
  mode: auto
  threshold: 0.85
  keep_turns: 1
`)

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "read_file", `{"path":"big.txt"}`)),
		fakemodel.Text("first done"),
		fakemodel.ToolCalls(fakemodel.Call("c2", "read_file", `{"path":"small.txt"}`)),
		fakemodel.Text("second done"),
	))
	h, err := Build(context.Background(), buildOptions(t, dir, fake))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if err := h.Submit(context.Background(), "read the big file"); err != nil {
		t.Fatalf("first Submit() = %v", err)
	}
	if err := h.Submit(context.Background(), "now read the small file"); err != nil {
		t.Fatalf("second Submit() = %v", err)
	}

	// The old tool result was evicted and the session conversation replaced,
	// not appended to (a compaction that the next turn replays away is a bug).
	foundEviction := false
	for _, m := range h.Messages() {
		if strings.Contains(m.Content, "evicted at compaction") {
			foundEviction = true
		}
	}
	if !foundEviction {
		t.Error("the session conversation does not reflect the compaction")
	}

	// The compaction is a persisted session event (§4.3, §10.1).
	events, err := h.sessions.Replay(dir, h.SessionID())
	if err != nil {
		t.Fatalf("Replay() = %v", err)
	}
	var compactions []sessions.Event
	for _, ev := range events {
		if ev.Kind == sessions.KindCompaction {
			compactions = append(compactions, ev)
		}
	}
	if len(compactions) == 0 {
		t.Fatal("no compaction event was persisted")
	}
	if compactions[0].Detail == "" {
		t.Error("persisted compaction event carries no detail")
	}

	// The status bar surfaces the context level (§9.1).
	if st := h.Status(false); st.Compaction == "" {
		t.Error("status bar does not surface the compaction level")
	}

	// The manual override honors a custom instruction and reaches the
	// summarizer.
	fake.Append(fakemodel.Text("condensed"))
	if _, err := h.Compact(context.Background(), "preserve every file path"); err != nil {
		t.Fatalf("Compact() = %v", err)
	}
	last, ok := fake.LastRequest()
	if !ok {
		t.Fatal("the summarizer never called the model")
	}
	if len(last.Messages) < 2 || !strings.Contains(last.Messages[1].Content, "preserve every file path") {
		t.Errorf("the custom /compact instruction did not reach the summarizer: %+v", last.Messages)
	}
}
