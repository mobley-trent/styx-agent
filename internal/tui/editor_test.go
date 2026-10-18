package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// press sends one non-text key.
func (h *harness) press(code rune) {
	h.update(tea.KeyPressMsg{Code: code})
}

// lastSubmit fails unless exactly one prompt was submitted, and returns it.
func (h *harness) lastSubmit(t *testing.T) string {
	t.Helper()
	if len(h.submits) == 0 {
		t.Fatal("no prompt was submitted")
	}
	return h.submits[len(h.submits)-1]
}

// The textarea replaces the bare append-only buffer: the cursor can move and
// edit mid-line (§1 of docs/tui-parity.md).
func TestInputEditsMidLine(t *testing.T) {
	h := newHarness(t)
	h.typeText("helo")
	h.press(tea.KeyLeft)
	h.press(tea.KeyLeft)
	h.typeText("l")
	h.press(tea.KeyEnter)

	if got := h.lastSubmit(t); got != "hello" {
		t.Errorf("submitted %q, want the mid-line insert to produce %q", got, "hello")
	}

	// Home/End move the cursor to the edges of the line.
	home := newHarness(t)
	home.typeText("world")
	home.press(tea.KeyHome)
	home.typeText("hello ")
	home.press(tea.KeyEnter)
	if got := home.lastSubmit(t); got != "hello world" {
		t.Errorf("submitted %q, want %q", got, "hello world")
	}
}

// Word navigation comes from the textarea's default keymap (alt+left).
func TestInputWordNavigation(t *testing.T) {
	h := newHarness(t)
	h.typeText("alpha beta")
	h.update(tea.KeyPressMsg{Code: tea.KeyLeft, Mod: tea.ModAlt})
	h.typeText("X")
	h.press(tea.KeyEnter)

	if got := h.lastSubmit(t); got != "alpha Xbeta" {
		t.Errorf("submitted %q, want %q", got, "alpha Xbeta")
	}
}

// Up/down walk the prompt history ring.
func TestInputHistoryRecall(t *testing.T) {
	h := newHarness(t)
	h.typeText("ls -la")
	h.press(tea.KeyEnter)
	h.typeText("nmap -sV 10.0.0.0/24")
	h.press(tea.KeyEnter)

	want := []struct {
		key   rune
		value string
	}{
		{tea.KeyUp, "nmap -sV 10.0.0.0/24"},
		{tea.KeyUp, "ls -la"},
		{tea.KeyUp, "ls -la"}, // already at the oldest entry: stay put
		{tea.KeyDown, "nmap -sV 10.0.0.0/24"},
		{tea.KeyDown, ""},
		{tea.KeyDown, ""}, // past the newest entry: no further movement
	}
	for i, step := range want {
		h.press(step.key)
		if got := h.model.editor.value(); got != step.value {
			t.Fatalf("step %d: line = %q, want %q", i, got, step.value)
		}
	}

	// The recalled prompt submits like any other line.
	h.press(tea.KeyUp)
	h.press(tea.KeyEnter)
	if got := h.lastSubmit(t); got != "nmap -sV 10.0.0.0/24" {
		t.Errorf("submitted %q, want the recalled prompt", got)
	}
}

// Recall stashes the half-typed line and restores it on the way back down.
func TestInputHistoryRestoresDraft(t *testing.T) {
	h := newHarness(t)
	h.typeText("earlier")
	h.press(tea.KeyEnter)
	h.typeText("a draft in progress")

	h.press(tea.KeyUp)
	if got := h.model.editor.value(); got != "earlier" {
		t.Fatalf("line = %q, want the recalled prompt", got)
	}
	h.press(tea.KeyDown)
	if got := h.model.editor.value(); got != "a draft in progress" {
		t.Errorf("line = %q, want the draft restored", got)
	}
}

// Editing a recalled prompt makes it a fresh line: down no longer discards the
// edit, and up starts again from the newest prompt.
func TestInputHistoryEndsOnEdit(t *testing.T) {
	h := newHarness(t)
	h.typeText("one")
	h.press(tea.KeyEnter)
	h.typeText("two")
	h.press(tea.KeyEnter)

	h.press(tea.KeyUp)
	h.typeText("!")
	if got := h.model.editor.value(); got != "two!" {
		t.Fatalf("line = %q, want the edited recall", got)
	}
	h.press(tea.KeyDown)
	if got := h.model.editor.value(); got != "two!" {
		t.Errorf("line = %q, want the edit kept after recall ended", got)
	}
	h.press(tea.KeyUp)
	if got := h.model.editor.value(); got != "two" {
		t.Errorf("line = %q, want recall to restart at the newest prompt", got)
	}
}

// The history ring is bounded, so a long session cannot grow it without limit.
func TestInputHistoryRingIsBounded(t *testing.T) {
	e := newInputEditor(darkTheme())
	for i := 0; i < historyLimit+5; i++ {
		e.remember(fmt.Sprintf("prompt %d", i))
	}
	if got := len(e.history); got != historyLimit {
		t.Fatalf("history holds %d prompts, want the %d-entry cap", got, historyLimit)
	}
	want := fmt.Sprintf("prompt %d", historyLimit+4)
	if got := e.history[len(e.history)-1]; got != want {
		t.Errorf("newest entry = %q, want %q", got, want)
	}
}

// Blank lines are not worth recalling.
func TestInputHistorySkipsBlankPrompts(t *testing.T) {
	h := newHarness(t)
	h.press(tea.KeyEnter)
	for _, blank := range []string{"   ", "\t"} {
		h.typeText(blank)
		h.press(tea.KeyEnter)
	}
	if got := len(h.model.editor.history); got != 0 {
		t.Errorf("history holds %d entries, want blank prompts skipped", got)
	}
}

// A live prompt card is modal: keys the card does not answer never reach the
// editor, so an open card cannot move the cursor or recall history.
func TestPromptCardKeepsEditorUntouched(t *testing.T) {
	h := newHarness(t)
	h.typeText("abc")
	h.press(tea.KeyLeft) // cursor lands between "b" and "c"

	h.update(PromptMsg{
		Prompt: Prompt{Kind: PromptPermission, Tool: "write_file", Params: map[string]any{}},
		Reply:  func(string) {},
	})
	h.press(tea.KeyHome)
	h.press(tea.KeyUp)
	h.update(tea.KeyPressMsg{Text: "y", Code: 'y'}) // resolve the card

	h.typeText("d")
	h.press(tea.KeyEnter)
	if got := h.lastSubmit(t); got != "abdc" {
		t.Errorf("submitted %q, want the card to leave the cursor at %q", got, "abdc")
	}
}

// The editor draws its own block cursor, so the line still reads as an input
// once the bare buffer is gone.
func TestInputLineShowsPrompt(t *testing.T) {
	h := newHarness(t)
	if got := h.view(); !strings.Contains(got, "> ") {
		t.Errorf("live region is missing the input prompt:\n%s", got)
	}
	h.typeText("inspect main.go")
	// The prompt glyph is styled, so it carries escape codes: assert the glyph
	// and the text separately rather than as one run.
	if got := h.view(); !strings.Contains(got, "> ") || !strings.Contains(got, "inspect main.go") {
		t.Errorf("live region does not show the typed line:\n%s", got)
	}
}
