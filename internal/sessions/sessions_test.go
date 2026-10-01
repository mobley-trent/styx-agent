package sessions

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// scripted returns a store whose clock advances one second per call, so
// session names and timestamps are deterministic.
func scripted(t *testing.T) *Store {
	t.Helper()
	base, err := time.Parse(time.RFC3339, "2026-10-01T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	return NewStore(t.TempDir(), WithClock(func() time.Time {
		at := base.Add(time.Duration(n) * time.Second)
		n++
		return at
	}))
}

func TestRoundTrip(t *testing.T) {
	store := scripted(t)
	project := t.TempDir()

	sess, err := store.Open(project)
	if err != nil {
		t.Fatal(err)
	}
	want := []Event{
		{Kind: KindUser, Text: "what does main.go do?"},
		{Kind: KindAssistant, Text: "Let me look.", Reasoning: "need to read"},
		{Kind: KindToolCall, Tool: "read_file", CallID: "call-1", Params: map[string]any{"path": "main.go"}, Verdict: "allow", Reason: "rule-match"},
		{Kind: KindToolResult, Tool: "read_file", CallID: "call-1", Result: "package main\n"},
		{Kind: KindAssistant, Text: "It prints usage."},
	}
	for _, ev := range want {
		if err := sess.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := store.Replay(project, sess.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("replayed %d events, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Kind != want[i].Kind || got[i].Text != want[i].Text || got[i].Tool != want[i].Tool {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// Timestamps were stamped on append.
	if got[0].Time.IsZero() {
		t.Error("event timestamp was not stamped")
	}
	if !reflect.DeepEqual(got[2].Params, map[string]any{"path": "main.go"}) {
		t.Errorf("params = %#v, want the verbatim parameter object", got[2].Params)
	}
}

func TestStreamingDeltasAreNotPersisted(t *testing.T) {
	store := scripted(t)
	project := t.TempDir()
	sess, err := store.Open(project)
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Append(Event{Kind: KindTextDelta, Text: "hel"}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Append(Event{Kind: KindReasoningDelta, Text: "hmm"}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Append(Event{Kind: KindAssistant, Text: "hello"}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := store.Replay(project, sess.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != KindAssistant || got[0].Text != "hello" {
		t.Fatalf("replayed %+v, want only the assembled assistant message", got)
	}
}

func TestListNewestFirst(t *testing.T) {
	store := scripted(t)
	project := t.TempDir()

	first, err := store.Open(project)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Append(Event{Kind: KindUser, Text: "first session"}); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := store.Open(project)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Append(Event{Kind: KindUser, Text: "second session"}); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	list, err := store.List(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("List() = %d sessions, want 2", len(list))
	}
	if list[0].ID != second.ID() {
		t.Errorf("List()[0] = %s, want the newest (%s)", list[0].ID, second.ID())
	}
	if list[0].FirstPrompt() != "second session" {
		t.Errorf("FirstPrompt() = %q, want %q", list[0].FirstPrompt(), "second session")
	}
	if list[1].FirstPrompt() != "first session" {
		t.Errorf("FirstPrompt() = %q, want %q", list[1].FirstPrompt(), "first session")
	}
}

func TestListEmptyProject(t *testing.T) {
	store := scripted(t)
	list, err := store.List(t.TempDir())
	if err != nil {
		t.Fatalf("List(empty) = %v, want nil", err)
	}
	if len(list) != 0 {
		t.Fatalf("List(empty) = %d sessions, want 0", len(list))
	}
}

func TestResumeAppendsToSameSession(t *testing.T) {
	store := scripted(t)
	project := t.TempDir()

	sess, err := store.Open(project)
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Append(Event{Kind: KindUser, Text: "hello"}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	id := sess.ID()

	resumed, err := store.Resume(project, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.Append(Event{Kind: KindUser, Text: "again"}); err != nil {
		t.Fatal(err)
	}
	if err := resumed.Close(); err != nil {
		t.Fatal(err)
	}

	events, err := store.Replay(project, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Text != "again" {
		t.Fatalf("resumed session = %+v, want both messages", events)
	}

	if _, err := store.Resume(project, "does-not-exist"); err == nil {
		t.Error("Resume(unknown id) = nil error, want an error")
	}
	if _, err := store.Resume(project, "../escape"); err == nil {
		t.Error("Resume(path traversal) = nil error, want an error")
	}
}

func TestReplayToleratesUnknownKeysAndTornTail(t *testing.T) {
	store := scripted(t)
	project := t.TempDir()
	dir := filepath.Join(store.Root(), ProjectKey(project))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "custom.jsonl")
	body := `{"kind":"user","text":"hi","some_future_field":42}
{"kind":"future_kind","text":"?",  "nested":{"a":1}}
{"kind":"user","text":"torn`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	events, err := store.Replay(project, "custom")
	if err != nil {
		t.Fatalf("Replay() = %v, want nil (unknown keys and torn tails are tolerated)", err)
	}
	if len(events) != 2 {
		t.Fatalf("Replay() = %d events, want 2 (the torn tail is dropped)", len(events))
	}
	if events[0].Text != "hi" || events[1].Kind != Kind("future_kind") {
		t.Errorf("events = %+v, want the recognized and future kinds read back", events)
	}
}

func TestCorruptLineFailsReplay(t *testing.T) {
	store := scripted(t)
	project := t.TempDir()
	dir := filepath.Join(store.Root(), ProjectKey(project))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := "{\"kind\":\"user\",\"text\":\"ok\"}\nnot json at all\n{\"kind\":\"user\"}\n"
	if err := os.WriteFile(filepath.Join(dir, "bad.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Replay(project, "bad"); err == nil {
		t.Error("Replay(corrupt middle line) = nil error, want an error")
	}
}

func TestProjectKeyIsStableAndDistinct(t *testing.T) {
	first := ProjectKey("/home/eddy/code/styx-agent")
	again := ProjectKey("/home/eddy/code/styx-agent")
	if first != again {
		t.Errorf("ProjectKey is not stable: %q vs %q", first, again)
	}
	if first == ProjectKey("/home/eddy/other/styx-agent") {
		t.Error("same basename in different directories shares a session directory")
	}
	if strings.ContainsAny(first, `/\`) {
		t.Errorf("ProjectKey %q contains a path separator", first)
	}
}
