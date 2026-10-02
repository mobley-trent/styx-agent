package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/tui"
)

// readAppFile reads a file this test created, keeping gosec quiet.
func readAppFile(t *testing.T, path string) string {
	t.Helper()
	//nolint:gosec // a test-only read of a path the test itself built.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestBuildRegistersFileTools(t *testing.T) {
	dir := t.TempDir()
	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	want := map[string]bool{
		"read_file": true, "write_file": true, "edit_file": true,
		"glob": true, "grep": true, "propose_plan": true,
	}
	for _, name := range h.Tools.Names() {
		delete(want, name)
	}
	if len(want) != 0 {
		t.Errorf("registry is missing tools: %v", want)
	}
}

func TestUnattendedWriteIsDenied(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "old\n")
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "write_file", `{"path":"a.txt","content":"new\n"}`)),
		fakemodel.Text("done"),
	))
	h, err := Build(context.Background(), buildOptions(t, dir, fake))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	// No operator is attached (no TUI), so the guarded write takes its safe
	// default: deny.
	if err := h.Submit(context.Background(), "write a.txt"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	if got := readAppFile(t, filepath.Join(dir, "a.txt")); got != "old\n" {
		t.Errorf("a.txt = %q, want the unattended write denied", got)
	}
}

func TestOperatorCardsDriveWrites(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "old\n")
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "write_file", `{"path":"a.txt","content":"new\n"}`)),
		fakemodel.Text("done"),
	))
	h, err := Build(context.Background(), buildOptions(t, dir, fake))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	var kinds []tui.PromptKind
	h.setPromptUI(func(msg tui.PromptMsg) {
		kinds = append(kinds, msg.Prompt.Kind)
		switch msg.Prompt.Kind {
		case tui.PromptPermission:
			if msg.Prompt.Tool != "write_file" || msg.Prompt.Risk != "write" {
				t.Errorf("permission card = %+v, want write_file with a write risk class", msg.Prompt)
			}
			msg.Reply(tui.ChoiceAllowOnce)
		case tui.PromptDiff:
			if msg.Prompt.Diff == nil || msg.Prompt.Diff.Empty() {
				t.Errorf("diff card carries no diff: %+v", msg.Prompt)
			}
			msg.Reply(tui.ChoiceAccept)
		}
	})

	if err := h.Submit(context.Background(), "write a.txt"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	if got := readAppFile(t, filepath.Join(dir, "a.txt")); got != "new\n" {
		t.Errorf("a.txt = %q, want the accepted write applied", got)
	}
	if len(kinds) != 2 || kinds[0] != tui.PromptPermission || kinds[1] != tui.PromptDiff {
		t.Errorf("cards shown = %v, want a permission card then a diff card", kinds)
	}
}
