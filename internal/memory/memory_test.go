package memory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMissingIsEmpty(t *testing.T) {
	got, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load() = %v, want nil for a missing file", err)
	}
	if got != "" {
		t.Errorf("Load() = %q, want empty", got)
	}
}

func TestAppendEngagementNotesCreatesAndAppends(t *testing.T) {
	dir := t.TempDir()

	block, err := AppendEngagementNotes(dir, EngagementNotes{
		Name:                 "acme-q4-redteam",
		Operator:             "eddy",
		Targets:              []string{"10.0.0.0/24", "192.0.2.44"},
		ExploitAllowed:       true,
		DestructiveForbidden: true,
		Expires:              "2026-10-15T23:59:59Z",
		Started:              "2026-09-30T12:00:00Z",
		Ended:                "2026-09-30T13:00:00Z",
		Tools:                map[string]int{"web_fetch": 2, "bash": 1},
		Artifacts:            []string{"b.txt", "a.txt"},
	})
	if err != nil {
		t.Fatalf("AppendEngagementNotes() = %v", err)
	}
	for _, want := range []string{
		"## Engagement notes — 2026-09-30T13:00:00Z",
		"- engagement: acme-q4-redteam",
		"- operator: eddy",
		"- targets: 10.0.0.0/24, 192.0.2.44",
		"exploit_allowed=true destructive_forbidden=true",
		"- expires: 2026-10-15T23:59:59Z",
		"- activated: 2026-09-30T12:00:00Z",
		"- tool calls: bash×1, web_fetch×2",
		"- artifacts: a.txt, b.txt",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("notes block is missing %q:\n%s", want, block)
		}
	}

	//nolint:gosec // a test-only read of a path the test itself built.
	written, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("read STYX.md: %v", err)
	}
	if string(written) != block {
		t.Errorf("STYX.md = %q, want the block", written)
	}

	// A second engagement appends, preserving the operator's memory.
	if _, err := AppendEngagementNotes(dir, EngagementNotes{
		Name:  "second",
		Ended: "2026-10-01T08:00:00Z",
	}); err != nil {
		t.Fatalf("second AppendEngagementNotes() = %v", err)
	}
	//nolint:gosec // a test-only read of a path the test itself built.
	again, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	text := string(again)
	if !strings.Contains(text, "## Engagement notes — 2026-09-30T13:00:00Z") ||
		!strings.Contains(text, "## Engagement notes — 2026-10-01T08:00:00Z") {
		t.Errorf("second append did not preserve the first record:\n%s", text)
	}
	if !strings.Contains(text, "\n\n---\n\n") {
		t.Error("records are not separated by a horizontal rule")
	}
}

func TestAppendEngagementNotesPreservesExistingMemory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("# Notes\n\nRun make check.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	block, err := AppendEngagementNotes(dir, EngagementNotes{Name: "x", Ended: "2026-10-01T08:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "Run make check.") {
		t.Errorf("existing memory was lost:\n%s", got)
	}
	if !strings.HasSuffix(got, block) {
		t.Errorf("notes were not appended to the end:\n%s", got)
	}
}
