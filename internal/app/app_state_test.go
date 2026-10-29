package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
	"github.com/mobley-trent/styx-agent/internal/memory"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// upsertHostOps is a well-formed state_update batch the fake model can call.
const upsertHostOps = `{"ops_json":"[{\"op\":\"upsert_entity\",\"kind\":\"host\",\"addresses\":[\"10.0.0.7\"],\"hostname\":\"web01\"}]"}`

func TestEngagementOpensTheStateStoreAndRegistersItsTools(t *testing.T) {
	dir := t.TempDir()
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "state_update", upsertHostOps)),
		fakemodel.Text("recorded"),
		fakemodel.ToolCalls(fakemodel.Call("c2", "state_query", `{"kind":"host","id":"","where_json":"","hops":0,"include_inactive":false,"limit":0}`)),
		fakemodel.Text("read back"),
	))
	opts := buildOptions(t, dir, fake)
	opts.Engagement = engagementFixture

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if h.state == nil {
		t.Fatalf("an engagement session should open a state store")
	}
	if !h.state.Writable() {
		t.Fatalf("the first session should hold the state write lock")
	}
	if !strings.Contains(h.state.Path(), "acme-q4-redteam") {
		t.Errorf("store path = %q, want the engagement's name", h.state.Path())
	}
	if dataHome := os.Getenv("XDG_DATA_HOME"); !strings.HasPrefix(h.state.Path(), dataHome) {
		t.Errorf("store path = %q, want it under the XDG data home %q", h.state.Path(), dataHome)
	}
	for _, name := range []string{"state_query", "state_update", "attack_path_suggest"} {
		if _, ok := h.Tools.Lookup(name); !ok {
			t.Errorf("tool %q is not registered in engagement mode", name)
		}
	}

	// A schema-valid write reaches the store and comes back with a receipt.
	if err := h.Submit(context.Background(), "record the host"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	snapshot := h.state.Snapshot()
	if len(snapshot.Entities) != 1 || snapshot.Entities[0].Hostname != "web01" {
		t.Fatalf("store entities = %+v, want the host the model wrote", snapshot.Entities)
	}
	if snapshot.Entities[0].Provenance.Source != "state_update" ||
		snapshot.Entities[0].Provenance.Session != h.SessionID() {
		t.Errorf("provenance = %+v, want the harness stamp with this session", snapshot.Entities[0].Provenance)
	}

	// The digest rides the prompt: a system message the conversation carries,
	// persisting as a session event.
	if err := h.Submit(context.Background(), "what do we have"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	var digests, withHost int
	for _, m := range h.Messages() {
		if !strings.HasPrefix(m.Content, "[engagement state]") {
			continue
		}
		digests++
		if strings.Contains(m.Content, "hosts 1") {
			withHost++
		}
	}
	if digests == 0 {
		t.Fatalf("no digest message reached the conversation")
	}
	if withHost == 0 {
		t.Errorf("no digest reports the host the model recorded: %+v", h.Messages())
	}
	events, err := h.sessions.Replay(dir, h.SessionID())
	if err != nil {
		t.Fatalf("Replay() = %v", err)
	}
	var persisted int
	for _, ev := range events {
		if ev.Kind == sessions.KindStateDigest {
			persisted++
		}
	}
	if persisted == 0 {
		t.Errorf("the digest should be persisted like any other content")
	}

	// The document lives outside the repo: never inside the project tree.
	if strings.HasPrefix(h.state.Path(), dir) {
		t.Errorf("store path %q must not live inside the project (%q)", h.state.Path(), dir)
	}
}

func TestSafeModeDeniesTheStateTools(t *testing.T) {
	dir := t.TempDir()
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "state_query", `{"kind":"host","id":"","where_json":"","hops":0,"include_inactive":false,"limit":0}`)),
		fakemodel.Text("understood"),
	))
	opts := buildOptions(t, dir, fake)

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if h.Mode != policy.ModeSafe {
		t.Fatalf("mode = %q, want safe", h.Mode)
	}
	if h.state != nil {
		t.Errorf("safe mode should have no state store")
	}
	// The tools are registered in both modes: the rule table is what refuses.
	for _, name := range []string{"state_query", "attack_path_suggest"} {
		if _, ok := h.Tools.Lookup(name); !ok {
			t.Errorf("%s should be registered in safe mode too", name)
		}
	}

	if err := h.Submit(context.Background(), "list the hosts"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	var denied bool
	for _, m := range h.Messages() {
		if strings.Contains(m.Content, "denied") && strings.Contains(m.Content, "state_query") {
			denied = true
		}
	}
	if !denied {
		t.Errorf("a safe-mode state_query should be denied by the rule table: %+v", h.Messages())
	}
}

func TestEngagementNotesCarryTheStoresFindings(t *testing.T) {
	dir := t.TempDir()
	ops := `{"ops_json":"[` +
		`{\"op\":\"upsert_entity\",\"kind\":\"host\",\"addresses\":[\"10.0.0.7\"]},` +
		`{\"op\":\"upsert_finding\",\"title\":\"SMB signing disabled\",\"severity\":\"medium\",\"confidence\":\"high\"}` +
		`]"}`
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "state_update", ops)),
		fakemodel.Text("recorded"),
	))
	opts := buildOptions(t, dir, fake)
	opts.Engagement = engagementFixture

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	if err := h.Submit(context.Background(), "record what we found"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	if err := h.Deactivate(); err != nil {
		t.Fatalf("Deactivate() = %v", err)
	}
	defer func() { _ = h.Close() }()

	notes, err := memory.Load(dir)
	if err != nil {
		t.Fatalf("Load(STYX.md) = %v", err)
	}
	if !strings.Contains(notes, "SMB signing disabled") {
		t.Errorf("engagement notes should carry the store's finding:\n%s", notes)
	}
	if !strings.Contains(notes, "medium · SMB signing disabled (detected, unverified)") {
		t.Errorf("the finding line should name severity, status, and verification:\n%s", notes)
	}
	if h.state != nil {
		t.Errorf("deactivation should close and release the store")
	}
}

// sharedStateOptions builds harness options whose state store lives under one
// data home, so two sessions in a test really do share an engagement's record
// (buildOptions picks a fresh data home on every call).
func sharedStateOptions(t *testing.T, dir, dataHome string) Options {
	t.Helper()
	opts := buildOptions(t, dir, fakemodel.New(fakemodel.WithTurns(fakemodel.Text("ok"))))
	opts.Engagement = engagementFixture
	t.Setenv("XDG_DATA_HOME", dataHome)
	return opts
}

func TestSecondEngagementSessionCannotWriteState(t *testing.T) {
	dir := t.TempDir()
	dataHome := t.TempDir()

	first, err := Build(context.Background(), sharedStateOptions(t, dir, dataHome))
	if err != nil {
		t.Fatalf("Build(first) = %v", err)
	}
	defer func() { _ = first.Close() }()

	second, err := Build(context.Background(), sharedStateOptions(t, dir, dataHome))
	if err != nil {
		t.Fatalf("Build(second) = %v", err)
	}
	defer func() { _ = second.Close() }()

	if second.state == nil {
		t.Fatalf("the second session should still open the store for reads")
	}
	if second.state.Writable() {
		t.Fatalf("a second session must not hold the write lock")
	}
	if !strings.Contains(second.state.Holder(), first.SessionID()) {
		t.Errorf("Holder() = %q, want the first session's id", second.state.Holder())
	}

	// Closing the first releases the lock for a later session.
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first) = %v", err)
	}
	third, err := Build(context.Background(), sharedStateOptions(t, dir, dataHome))
	if err != nil {
		t.Fatalf("Build(third) = %v", err)
	}
	defer func() { _ = third.Close() }()
	if !third.state.Writable() {
		t.Fatalf("a released lock should be re-acquirable, Holder() = %q", third.state.Holder())
	}
}

func TestAnUnreadableStateDocumentRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "engagement.yaml"), []byte(inSessionEngagement), 0o600); err != nil {
		t.Fatalf("write engagement: %v", err)
	}
	opts := buildOptions(t, dir, fakemodel.New(fakemodel.WithTurns(fakemodel.Text("ok"))))
	opts.Engagement = filepath.Join(dir, "engagement.yaml")

	// A document with an incompatible major in this engagement's own directory
	// is a startup refusal, not a degradation: it is the forensic record.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	store, err := engagementstate.Open(dir, "in-session")
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	path := store.Path()
	if err := store.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	//nolint:gosec // the test writes its own document.
	if err := os.WriteFile(path, []byte(`{"schema_version": 9}`), 0o600); err != nil {
		t.Fatalf("write document: %v", err)
	}

	if _, err := Build(context.Background(), opts); err == nil {
		t.Fatalf("Build() = nil error, want a refusal naming the unreadable document")
	} else if !strings.Contains(err.Error(), path) {
		t.Errorf("refusal %q should name the document", err)
	}
}
