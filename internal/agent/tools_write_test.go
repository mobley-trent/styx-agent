package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileToolCreatesAndPreviews(t *testing.T) {
	dir := workspace(t, map[string]string{"existing.txt": "old contents\n"})
	tool := WriteFileTool(dir)

	// Preview computes the diff but touches nothing.
	preview, err := tool.Preview(map[string]any{"path": "existing.txt", "content": "new contents\n"})
	if err != nil {
		t.Fatalf("Preview() = %v", err)
	}
	if preview.Empty() || preview.Path != "existing.txt" {
		t.Fatalf("Preview() = %+v, want a change to existing.txt", preview)
	}
	onDisk := readWorkspace(t, filepath.Join(dir, "existing.txt"))
	if string(onDisk) != "old contents\n" {
		t.Errorf("Preview modified the file: %q", onDisk)
	}

	// Apply writes it.
	out, err := tool.Handler(context.Background(), map[string]any{"path": "existing.txt", "content": "new contents\n"})
	if err != nil {
		t.Fatalf("Handler() = %v", err)
	}
	if !strings.Contains(out, "wrote existing.txt") {
		t.Errorf("Handler() = %q, want a write summary", out)
	}
	onDisk = readWorkspace(t, filepath.Join(dir, "existing.txt"))
	if string(onDisk) != "new contents\n" {
		t.Errorf("file contents = %q, want the new contents", onDisk)
	}

	// A new file in a new directory is created.
	if _, err := tool.Handler(context.Background(), map[string]any{"path": "sub/new.txt", "content": "hi\n"}); err != nil {
		t.Fatalf("Handler(new file) = %v", err)
	}
	if got := readWorkspace(t, filepath.Join(dir, "sub", "new.txt")); got != "hi\n" {
		t.Errorf("new file contents = %q", got)
	}
}

func TestWriteFileToolConfined(t *testing.T) {
	dir := workspace(t, nil)
	if _, err := WriteFileTool(dir).Handler(context.Background(), map[string]any{"path": "../escape.txt", "content": "x"}); err == nil {
		t.Error("Handler(../escape.txt) = nil error, want a confinement error")
	}
	if _, err := WriteFileTool(dir).Preview(map[string]any{"path": "../escape.txt", "content": "x"}); err == nil {
		t.Error("Preview(../escape.txt) = nil error, want a confinement error")
	}
}

func TestEditFileToolReplaces(t *testing.T) {
	dir := workspace(t, map[string]string{"main.go": "a\nb\nc\n"})
	tool := EditFileTool(dir)

	out, err := tool.Handler(context.Background(), map[string]any{
		"path": "main.go", "old_string": "b", "new_string": "B",
	})
	if err != nil {
		t.Fatalf("Handler() = %v", err)
	}
	if !strings.Contains(out, "1 replacement") {
		t.Errorf("Handler() = %q, want one replacement", out)
	}
	got := readWorkspace(t, filepath.Join(dir, "main.go"))
	if got != "a\nB\nc\n" {
		t.Errorf("file = %q, want the replacement applied", got)
	}
}

func TestEditFileToolRefusesAmbiguousAndMissing(t *testing.T) {
	dir := workspace(t, map[string]string{"dup.txt": "x\nx\n"})
	tool := EditFileTool(dir)

	if _, err := tool.Handler(context.Background(), map[string]any{
		"path": "dup.txt", "old_string": "x", "new_string": "y",
	}); err == nil || !strings.Contains(err.Error(), "occurs 2 times") {
		t.Errorf("Handler(ambiguous) = %v, want an ambiguity error", err)
	}

	if _, err := tool.Handler(context.Background(), map[string]any{
		"path": "dup.txt", "old_string": "nope", "new_string": "y",
	}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("Handler(missing) = %v, want a not-found error", err)
	}

	out, err := tool.Handler(context.Background(), map[string]any{
		"path": "dup.txt", "old_string": "x", "new_string": "y", "replace_all": true,
	})
	if err != nil {
		t.Fatalf("Handler(replace_all) = %v", err)
	}
	if !strings.Contains(out, "2 replacement") {
		t.Errorf("Handler(replace_all) = %q, want two replacements", out)
	}
	got := readWorkspace(t, filepath.Join(dir, "dup.txt"))
	if got != "y\ny\n" {
		t.Errorf("file = %q, want both replaced", got)
	}
}

func TestWriteEditDescriptorsAreDiffClass(t *testing.T) {
	dir := workspace(t, nil)
	for _, tool := range []Tool{WriteFileTool(dir), EditFileTool(dir)} {
		if tool.Preview == nil {
			t.Errorf("%s has no Preview: it is not diff-class", tool.Name)
		}
		if desc := tool.Descriptor(); !desc.Strict {
			t.Errorf("%s descriptor is not strict", tool.Name)
		}
	}
}
