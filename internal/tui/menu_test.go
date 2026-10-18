package tui

import (
	"fmt"
	"image/color"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// menu reads the inline command menu out of the live region.
func (h *harness) menuNames() []string {
	names := make([]string, 0, len(h.model.menu.matches))
	for _, info := range h.model.menu.matches {
		names = append(names, info.Name)
	}
	return names
}

// Typing "/" opens the inline menu over the registry (docs/tui-parity.md §4).
func TestSlashOpensCommandMenu(t *testing.T) {
	h := newHarness(t)
	if h.model.menu.active() {
		t.Fatal("the menu is open before anything is typed")
	}

	h.typeText("/")
	if !h.model.menu.active() {
		t.Fatal("typing / did not open the command menu")
	}
	if got := h.menuNames(); len(got) != 5 {
		t.Errorf("menu lists %v, want the whole registry", got)
	}
	view := h.view()
	for _, want := range []string{"/help", "/model [id]", "list the pinned models", "/resume [id]"} {
		if !strings.Contains(view, want) {
			t.Errorf("live region is missing %q:\n%s", want, view)
		}
	}

	// The menu closes when the line stops being a command name.
	h.typeText("x y")
	if h.model.menu.active() {
		t.Error("the menu stayed open after an argument was typed")
	}
}

// Typing narrows the menu fuzzily: a subsequence of the command name matches,
// and the best match leads.
func TestSlashMenuFiltersFuzzily(t *testing.T) {
	h := newHarness(t)
	h.typeText("/rsm")

	got := h.menuNames()
	if len(got) != 1 || got[0] != "resume" {
		t.Fatalf("menu lists %v, want only resume for query %q", got, "rsm")
	}

	// A subsequence that several names share keeps the registry's order, and
	// the ranking puts the entry that matches more tightly first.
	h2 := newHarness(t)
	h2.typeText("/")
	if got := h2.menuNames(); len(got) == 0 || got[0] != "help" {
		t.Errorf("menu lists %v, want the registry order for an empty query", got)
	}
	h2.typeText("mdl")
	if got := h2.menuNames(); len(got) != 1 || got[0] != "model" {
		t.Errorf("menu lists %v, want only model for query %q", got, "mdl")
	}

	// A query nothing matches leaves the menu with no rows rather than a
	// stale selection.
	h3 := newHarness(t)
	h3.typeText("/zzz")
	if got := h3.menuNames(); len(got) != 0 {
		t.Errorf("menu lists %v, want no matches for an unmatched query", got)
	}
	if h3.model.menu.active() {
		t.Error("an unmatched query left the menu holding the keyboard")
	}
}

// Enter runs the highlighted command; Tab completes its name into the line.
func TestSlashMenuRunsAndCompletes(t *testing.T) {
	h := newHarness(t)
	h.typeText("/mem")
	h.press(tea.KeyEnter)

	if len(h.commands) != 1 || h.commands[0] != "memory|" {
		t.Fatalf("commands = %v, want the highlighted memory command", h.commands)
	}
	if got := h.model.editor.value(); got != "" {
		t.Errorf("line = %q, want the submitted line cleared", got)
	}

	tab := newHarness(t)
	tab.typeText("/res")
	tab.press(tea.KeyTab)
	if got := tab.model.editor.value(); got != "/resume" {
		t.Errorf("line after Tab = %q, want the completed %q", got, "/resume")
	}
	if len(tab.commands) != 0 {
		t.Errorf("Tab ran %v, want completion only", tab.commands)
	}
	tab.press(tea.KeyEnter)
	if len(tab.commands) != 0 {
		t.Errorf("commands = %v, want /resume to open its picker, not print a list", tab.commands)
	}
	if tab.model.picker == nil {
		t.Error("Enter on /resume did not open the picker")
	}
}

// Up/down walk the selection instead of the prompt history while the menu is
// open, and the chosen row is what Enter runs.
func TestSlashMenuMovesSelection(t *testing.T) {
	h := newHarness(t)
	h.typeText("/")
	if info, _ := h.model.menu.current(); info.Name != "help" {
		t.Fatalf("selection = %q, want the first registry entry", info.Name)
	}

	h.press(tea.KeyDown)
	if info, _ := h.model.menu.current(); info.Name != "memory" {
		t.Fatalf("selection after down = %q, want memory", info.Name)
	}
	// The ends wrap rather than stick.
	h.press(tea.KeyUp)
	if info, _ := h.model.menu.current(); info.Name != "help" {
		t.Fatalf("selection after up = %q, want help", info.Name)
	}
	h.press(tea.KeyUp)
	if info, _ := h.model.menu.current(); info.Name != "theme" {
		t.Errorf("selection after wrapping up = %q, want the last entry", info.Name)
	}

	if got := h.model.editor.history; len(got) != 0 {
		t.Errorf("history = %v, want browsing the menu to leave history alone", got)
	}
}

// Escape closes the menu and leaves the line it was completing; the next
// Escape, with no menu open, clears the line (§5).
func TestSlashMenuEscapeKeepsTheLine(t *testing.T) {
	h := newHarness(t)
	h.busy = false
	h.typeText("/mem")
	h.press(tea.KeyEscape)

	if h.model.menu.active() {
		t.Error("Escape did not close the menu")
	}
	if got := h.model.editor.value(); got != "/mem" {
		t.Fatalf("line = %q, want the completed line kept", got)
	}

	h.press(tea.KeyEscape)
	if got := h.model.editor.value(); got != "" {
		t.Errorf("line = %q, want the second Escape to clear it", got)
	}
}

// A command the registry does not know still submits as typed, so an unmatched
// query never swallows the line.
func TestSlashMenuLeavesUnknownCommandsAlone(t *testing.T) {
	h := newHarness(t)
	h.typeText("/boom")
	h.press(tea.KeyEnter)

	if len(h.commands) != 1 || h.commands[0] != "boom|" {
		t.Fatalf("commands = %v, want the typed command dispatched", h.commands)
	}
	if got := h.printedText(); !strings.Contains(got, "command failed") {
		t.Errorf("the unknown command's error is not rendered:\n%s", got)
	}
}

// A command that declares picker options opens a modal list when run bare
// (§4): the live region shows the options and the editor is not in play.
func TestBareCommandOpensPicker(t *testing.T) {
	h := newHarness(t)
	h.typeText("/model")
	h.press(tea.KeyEnter)

	if h.model.picker == nil {
		t.Fatal("/model did not open a picker")
	}
	if len(h.commands) != 0 {
		t.Errorf("commands = %v, want the picker opened before anything ran", h.commands)
	}
	view := h.view()
	for _, want := range []string{"select a model", "deepseek-flash", "64k token window"} {
		if !strings.Contains(view, want) {
			t.Errorf("picker is missing %q:\n%s", want, view)
		}
	}
	// The picker owns the keyboard: the input line is not rendered under it.
	if strings.Contains(view, promptPrefix) {
		t.Errorf("the input line is still rendered under the modal picker:\n%s", view)
	}
}

// Choosing a row submits the command line it stands for, so the picker runs the
// same path as typing the command out.
func TestPickerSelectionRunsTheCommand(t *testing.T) {
	h := newHarness(t)
	h.typeText("/model")
	h.press(tea.KeyEnter)
	h.press(tea.KeyEnter)

	if h.model.picker != nil {
		t.Error("the picker stayed open after a row was chosen")
	}
	if len(h.commands) != 1 || h.commands[0] != "model|deepseek-flash" {
		t.Fatalf("commands = %v, want the selected model passed to /model", h.commands)
	}
	if got := h.printedText(); !strings.Contains(got, "theme: ") && !strings.Contains(got, "model: ") {
		t.Errorf("the command's output is not rendered:\n%s", got)
	}
}

// The picker sizes its list so every option is on one page, and draws no blank
// line between its header and the rows (§4).
func TestPickerFitsItsOptions(t *testing.T) {
	h := newHarness(t)
	h.modelOptions = make([]Option, 5)
	for i := range h.modelOptions {
		h.modelOptions[i] = Option{Value: fmt.Sprintf("model-%d", i), Label: fmt.Sprintf("model-%d", i), Detail: "64k token window"}
	}
	h.typeText("/model")
	h.press(tea.KeyEnter)
	if h.model.picker == nil {
		t.Fatal("/model did not open a picker")
	}
	if got := h.model.picker.list.Paginator.PerPage; got != len(h.modelOptions) {
		t.Errorf("the picker pages %d options at a time, want all %d", got, len(h.modelOptions))
	}

	lines := h.model.picker.view(h.model.styles)
	if len(lines) < 2 {
		t.Fatalf("picker view = %v, want a header and rows", lines)
	}
	if strings.TrimSpace(lines[1]) == "" {
		t.Errorf("the picker draws a blank line under its header:\n%s", strings.Join(lines, "\n"))
	}
}

// Arrow keys move the picker's cursor, so the second row is what Enter runs.
func TestPickerMovesSelection(t *testing.T) {
	h := newHarness(t)
	h.typeText("/model")
	h.press(tea.KeyEnter)
	h.press(tea.KeyDown)
	h.press(tea.KeyEnter)

	if len(h.commands) != 1 || h.commands[0] != "model|deepseek-v4-pro" {
		t.Fatalf("commands = %v, want the second model chosen", h.commands)
	}
}

// Escape closes the picker without running anything, and q does not quit: a
// modal must never end the program through the list's own keys.
func TestPickerEscapeAndKeysStayInThePicker(t *testing.T) {
	h := newHarness(t)
	h.typeText("/resume")
	h.press(tea.KeyEnter)
	if h.model.picker == nil {
		t.Fatal("/resume did not open a picker")
	}

	h.update(tea.KeyPressMsg{Code: 'q'})
	if h.quit {
		t.Error("q in the picker quit the program")
	}
	if h.model.picker == nil {
		t.Error("q closed the picker")
	}

	h.press(tea.KeyEscape)
	if h.model.picker != nil {
		t.Error("Escape did not close the picker")
	}
	if len(h.commands) != 0 {
		t.Errorf("commands = %v, want a cancelled picker to run nothing", h.commands)
	}
	if got := h.model.editor.value(); got != "" {
		t.Errorf("line = %q, want the picker to leave the input alone", got)
	}
}

// A command with an argument typed runs directly: the picker is for the bare
// command only.
func TestCommandWithArgumentSkipsPicker(t *testing.T) {
	h := newHarness(t)
	h.typeText("/model deepseek-v4-pro")
	h.press(tea.KeyEnter)

	if h.model.picker != nil {
		t.Fatal("a typed argument opened the picker")
	}
	if len(h.commands) != 1 || h.commands[0] != "model|deepseek-v4-pro" {
		t.Errorf("commands = %v, want the typed argument dispatched", h.commands)
	}
}

// A command whose picker has nothing to offer runs its own listing instead of
// opening an empty modal.
func TestEmptyPickerFallsBackToTheCommand(t *testing.T) {
	h := newHarness(t)
	h.resumeOptions = nil
	h.typeText("/resume")
	h.press(tea.KeyEnter)

	if h.model.picker != nil {
		t.Error("an empty picker opened")
	}
	if len(h.commands) != 1 || h.commands[0] != "resume|" {
		t.Fatalf("commands = %v, want the command's own listing", h.commands)
	}
}

// Without a registry attached the menu stays shut: the TUI needs the harness's
// command surface to draw one, and invents none of its own.
func TestMenuNeedsARegistry(t *testing.T) {
	m := New(Config{})
	for _, r := range "/help" {
		_, _ = m.Update(tea.KeyPressMsg{Text: string(r), Code: r})
	}
	if m.menu.active() {
		t.Error("the menu opened without a command registry")
	}
}

// The /theme choice overrides the terminal background, and auto hands the
// choice back to it (§9.6).
func TestThemeChoiceOverridesTerminalBackground(t *testing.T) {
	h := newHarness(t)
	// The terminal reports a dark background; the operator asks for light.
	h.update(tea.BackgroundColorMsg{Color: color.Black})
	h.typeText("/theme light")
	h.press(tea.KeyEnter)
	if h.model.dark || h.model.styles.name != "light" {
		t.Fatalf("theme = %q (dark=%v), want the /theme choice in force", h.model.styles.name, h.model.dark)
	}

	// A later background report must not override the operator's choice.
	h.update(tea.BackgroundColorMsg{Color: color.Black})
	if h.model.dark {
		t.Error("a terminal background report overrode the /theme choice")
	}

	// auto hands the choice back to the terminal.
	h.typeText("/theme auto")
	h.press(tea.KeyEnter)
	if !h.model.dark || h.model.styles.name != "dark" {
		t.Errorf("theme = %q (dark=%v), want auto to follow the terminal again", h.model.styles.name, h.model.dark)
	}
}

// fuzzyScore ranks a prefix best, then word starts and contiguous runs, and
// rejects anything that is not a subsequence.
func TestFuzzyScore(t *testing.T) {
	if _, ok := fuzzyScore("xyz", "resume"); ok {
		t.Error("a non-subsequence matched")
	}
	prefix, ok := fuzzyScore("res", "resume")
	if !ok {
		t.Fatal("a prefix did not match")
	}
	sparse, _ := fuzzyScore("rsm", "resume")
	if !ok || sparse >= prefix {
		t.Errorf("sparse score %d >= prefix score %d, want the prefix ranked first", sparse, prefix)
	}
	if _, ok := fuzzyScore("", "resume"); !ok {
		t.Error("an empty query matched nothing")
	}
}
