package tui

import (
	"errors"
	"image/color"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/mobley-trent/styx-agent/internal/diff"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// harness wires a Model with recording callbacks.
type harness struct {
	model    *Model
	submits  []string
	commands []string
	quit     bool
	// printed collects the transcript lines committed to the terminal's
	// scrollback: the harness replaces the model's print seam so tests can read
	// what the terminal receives above the live region.
	printed []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{}
	h.model = New(Config{
		Status: func() Status {
			return Status{Mode: "safe", Packs: "coding+red-team", Model: "deepseek-flash", Session: "abc123", Busy: true}
		},
		Submit: func(text string) { h.submits = append(h.submits, text) },
		Command: func(name, arg string) (string, error) {
			h.commands = append(h.commands, name+"|"+arg)
			switch name {
			case "help":
				return "commands: /help /resume /quit", nil
			case "boom":
				return "", errors.New("command failed")
			default:
				return "", nil
			}
		},
		Quit: func() { h.quit = true },
	})
	h.model.print = func(lines ...string) tea.Cmd {
		h.printed = append(h.printed, lines...)
		return nil
	}
	return h
}

// newCapturedModel builds a Model whose print seam records the committed
// transcript lines that would be printed above the live region.
func newCapturedModel(cfg Config) (*Model, *[]string) {
	m := New(cfg)
	printed := new([]string)
	m.print = func(lines ...string) tea.Cmd {
		*printed = append(*printed, lines...)
		return nil
	}
	return m, printed
}

func (h *harness) update(msg tea.Msg) {
	_, _ = h.model.Update(msg)
}

func (h *harness) typeText(s string) {
	for _, r := range s {
		h.update(tea.KeyPressMsg{Text: string(r), Code: r})
	}
}

func (h *harness) view() string { return h.model.View().Content }

// printedText is the committed transcript, as the terminal's scrollback holds it.
func (h *harness) printedText() string { return strings.Join(h.printed, "\n") }

func TestStreamRendersModelOutput(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindUser, Text: "what is in main.go?"}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindTextDelta, Text: "Let "}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindTextDelta, Text: "me look."}})

	// The in-flight partial streams in the live region, not in scrollback.
	if got := h.view(); !strings.Contains(got, "Let me look.") {
		t.Errorf("live region does not show the streaming partial answer:\n%s", got)
	}
	if got := h.printedText(); strings.Contains(got, "Let me look.") {
		t.Errorf("the streaming partial was committed before the turn moved on:\n%s", got)
	}

	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindToolCall, Tool: "read_file",
		Params: map[string]any{"path": "main.go"}, Verdict: "allow", Reason: "rule-match",
	}})
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindToolResult, Tool: "read_file", Result: "package main\n",
	}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindAssistant, Text: "It prints usage."}})

	printed := h.printedText()
	for _, want := range []string{"> what is in main.go?", "Let me look.", "read_file", "allow", "package main", "It prints usage."} {
		if !strings.Contains(printed, want) {
			t.Errorf("scrollback is missing %q:\n%s", want, printed)
		}
	}
	if live := h.view(); strings.Contains(live, "> what is in main.go?") || strings.Contains(live, "It prints usage.") {
		t.Errorf("committed transcript leaked into the live region:\n%s", live)
	}
}

func TestStreamRendersFailures(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindToolResult, Tool: "read_file", Failure: "no such file"}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindError, Failure: "turn cap reached"}})
	got := h.printedText()
	if !strings.Contains(got, "no such file") || !strings.Contains(got, "turn cap reached") {
		t.Errorf("failures are not rendered:\n%s", got)
	}
}

func TestEnterSubmitsPrompt(t *testing.T) {
	h := newHarness(t)
	h.typeText("hello there")
	h.update(tea.KeyPressMsg{Code: tea.KeyEnter})

	if len(h.submits) != 1 || h.submits[0] != "hello there" {
		t.Fatalf("submits = %v, want one \"hello there\"", h.submits)
	}
	if got := h.view(); strings.Contains(got, "hello there") {
		t.Errorf("the input buffer was not cleared after submit:\n%s", got)
	}
}

func TestSlashCommandDispatched(t *testing.T) {
	h := newHarness(t)
	h.typeText("/help")
	h.update(tea.KeyPressMsg{Code: tea.KeyEnter})

	if len(h.commands) != 1 || h.commands[0] != "help|" {
		t.Fatalf("commands = %v, want one help invocation", h.commands)
	}
	if got := h.printedText(); !strings.Contains(got, "commands: /help /resume /quit") {
		t.Errorf("command output is not rendered:\n%s", got)
	}

	h.typeText("/resume 20260101T000000Z-abcd")
	h.update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if len(h.commands) != 2 || h.commands[1] != "resume|20260101T000000Z-abcd" {
		t.Errorf("commands = %v, want the resume argument preserved", h.commands)
	}

	h.typeText("/boom")
	h.update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if got := h.printedText(); !strings.Contains(got, "command failed") {
		t.Errorf("command error is not rendered:\n%s", got)
	}
}

func TestQuitPaths(t *testing.T) {
	h := newHarness(t)
	h.typeText("/quit")
	_, cmd := h.model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if !h.quit {
		t.Error("/quit did not ask the app to quit")
	}
	if cmd == nil {
		t.Fatal("/quit returned no quit command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("/quit command did not produce a QuitMsg")
	}

	exit := newHarness(t)
	exit.typeText("/exit")
	_, exitCmd := exit.model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if !exit.quit {
		t.Error("/exit did not ask the app to quit")
	}
	if exitCmd == nil {
		t.Fatal("/exit returned no quit command")
	}
	if _, ok := exitCmd().(tea.QuitMsg); !ok {
		t.Error("/exit command did not produce a QuitMsg")
	}

	other := newHarness(t)
	_, ctrlCmd := other.model.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if !other.quit {
		t.Error("ctrl+c did not ask the app to quit")
	}
	if ctrlCmd == nil {
		t.Fatal("ctrl+c returned no quit command")
	}
	if _, ok := ctrlCmd().(tea.QuitMsg); !ok {
		t.Error("ctrl+c command did not produce a QuitMsg")
	}
}

func TestBackspaceAndEscapeEdit(t *testing.T) {
	h := newHarness(t)
	h.typeText("abc")
	h.update(tea.KeyPressMsg{Code: tea.KeyBackspace})
	h.typeText("d")
	h.update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if len(h.submits) != 1 || h.submits[0] != "abd" {
		t.Fatalf("submits = %v, want \"abd\"", h.submits)
	}

	h.typeText("gone")
	h.update(tea.KeyPressMsg{Code: tea.KeyEscape})
	h.update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if len(h.submits) != 1 {
		t.Errorf("submits = %v, want the escaped input to submit nothing", h.submits)
	}
}

func TestStatusBarShowsModeAndModel(t *testing.T) {
	h := newHarness(t)
	got := h.view()
	if !strings.Contains(got, "safe") || !strings.Contains(got, "deepseek-flash") {
		t.Errorf("status bar is missing mode/model:\n%s", got)
	}
	if !strings.Contains(got, "coding+red-team") {
		t.Errorf("status bar is missing the active pack:\n%s", got)
	}
	if !strings.Contains(got, "working…") {
		t.Errorf("status bar does not show the busy indicator:\n%s", got)
	}
}

// Committed transcript is never trimmed to the terminal height: it prints in
// full into the terminal's own scrollback, which owns scrolling (ADR-0001).
func TestTranscriptPrintsInFull(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 40; i++ {
		h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindUser, Text: "line"}})
	}
	h.update(tea.WindowSizeMsg{Width: 60, Height: 10})

	if got := strings.Count(h.printedText(), "line"); got != 40 {
		t.Errorf("scrollback holds %d of 40 committed lines, want all of them", got)
	}
	if got := h.view(); strings.Contains(got, "> line") {
		t.Errorf("committed lines were re-rendered in the live region:\n%s", got)
	}
}

// A tall committed payload is printed in chunks no taller than the terminal:
// Bubble Tea's print-above path cannot insert more lines than the screen
// height and leaves the overflow as blank scrollback otherwise.
func TestFlushChunksCommittedLinesToTerminalHeight(t *testing.T) {
	m := New(Config{Status: func() Status { return Status{Mode: "safe"} }})
	var batches [][]string
	m.print = func(lines ...string) tea.Cmd {
		batches = append(batches, append([]string(nil), lines...))
		return nil
	}
	// Width below the banner guard, so the banner is skipped and the transcript
	// is exactly the lines appended below.
	m.Update(tea.WindowSizeMsg{Width: 40, Height: 10})

	lines := make([]string, 0, 25)
	for i := 0; i < 24; i++ {
		lines = append(lines, "line")
	}
	lines = append(lines, strings.Repeat("x", 100)) // wraps to 3 rows at width 40
	for _, ln := range lines {
		m.append(ln)
	}
	m.flush()

	if len(batches) < 2 {
		t.Fatalf("print calls = %d, want the payload split across chunks", len(batches))
	}
	var got []string
	for _, b := range batches {
		if rows := renderedHeight(b, 40); rows > 9 {
			t.Errorf("a chunk renders %d rows, want at most the 10-row terminal minus one", rows)
		}
		got = append(got, b...)
	}
	if strings.Join(got, "\n") != strings.Join(lines, "\n") {
		t.Errorf("chunks changed the transcript order or content:\n%v", got)
	}
}

// renderedHeight sums the wrapped row height of a batch of lines.
func renderedHeight(lines []string, width int) int {
	rows := 0
	for _, ln := range lines {
		rows += renderedRows(ln, width)
	}
	return rows
}

// The view is the fixed live region only; AltScreen must stay off so the
// terminal, not styx, owns scrollback (ADR-0001).
func TestViewIsLiveRegionWithoutAltScreen(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindUser, Text: "a committed line"}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindTextDelta, Text: "streaming"}})

	v := h.model.View()
	if v.AltScreen {
		t.Error("View still uses AltScreen; native scrollback would be discarded")
	}
	if !strings.Contains(v.Content, "streaming") {
		t.Errorf("live region is missing the streaming partial:\n%s", v.Content)
	}
	if strings.Contains(v.Content, "a committed line") {
		t.Errorf("committed line was re-rendered in the live region:\n%s", v.Content)
	}
}

func TestStreamRendersInlineDiff(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindDiff,
		Tool: "write_file",
		Path: "a.txt",
		Diff: diff.File("a.txt", "one\ntwo\n", "one\nTWO\n"),
	}})
	got := h.printedText()
	for _, want := range []string{"a.txt (+1 -1)", "-two", "+TWO", "one"} {
		if !strings.Contains(got, want) {
			t.Errorf("inline diff is missing %q:\n%s", want, got)
		}
	}
}

func TestStreamRendersMCPLifecycle(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindMCP, Server: "nmap", Status: "ready", Detail: "2 tool(s)"}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindMCP, Server: "ghidra", Status: "failed", Detail: "launch failed: executable not found"}})

	view := h.printedText()
	if !strings.Contains(view, "mcp nmap: ready") {
		t.Errorf("view = %q, want the ready server rendered", view)
	}
	if !strings.Contains(view, "mcp ghidra unavailable") || !strings.Contains(view, "executable not found") {
		t.Errorf("view = %q, want the failed server and its reason rendered", view)
	}
}

func TestStreamRendersPlan(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindPlan,
		Steps: []sessions.PlanStep{
			{Tool: "write_file", Params: map[string]any{"path": "a.txt"}},
		},
	}})
	got := h.printedText()
	if !strings.Contains(got, "plan") || !strings.Contains(got, "write_file") {
		t.Errorf("plan block is not rendered:\n%s", got)
	}
}

func TestPermissionPromptCardResolves(t *testing.T) {
	h := newHarness(t)
	var reply string
	h.update(PromptMsg{
		Prompt: Prompt{
			Kind:   PromptPermission,
			Tool:   "write_file",
			Params: map[string]any{"path": "a.txt"},
			Reason: "rule-match",
			Risk:   "write",
		},
		Reply: func(choice string) { reply = choice },
	})

	got := h.view()
	for _, want := range []string{"permission", "write_file", "a.txt", "allow-once", "allow-session", "deny"} {
		if !strings.Contains(got, want) {
			t.Errorf("permission card is missing %q:\n%s", want, got)
		}
	}

	h.update(tea.KeyPressMsg{Text: "y", Code: 'y'})
	if reply != ChoiceAllowOnce {
		t.Errorf("reply = %q, want %q", reply, ChoiceAllowOnce)
	}
	if strings.Contains(h.view(), "permission") {
		t.Errorf("the card did not clear after resolving:\n%s", h.view())
	}
}

func TestDiffPromptCardResolves(t *testing.T) {
	cases := []struct {
		name string
		key  tea.KeyPressMsg
		want string
	}{
		{name: "accept", key: tea.KeyPressMsg{Text: "a", Code: 'a'}, want: ChoiceAccept},
		{name: "reject", key: tea.KeyPressMsg{Text: "r", Code: 'r'}, want: ChoiceReject},
		{name: "accept rest", key: tea.KeyPressMsg{Text: "A", Code: 'A'}, want: ChoiceAcceptRest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			var reply string
			h.update(PromptMsg{
				Prompt: Prompt{Kind: PromptDiff, Tool: "edit_file", Path: "a.txt", Diff: diff.File("a.txt", "one\n", "two\n")},
				Reply:  func(choice string) { reply = choice },
			})
			if got := h.view(); !strings.Contains(got, "accept-all-rest-of-turn") || !strings.Contains(got, "+two") {
				t.Fatalf("diff card is missing its controls or content:\n%s", got)
			}
			h.update(tc.key)
			if reply != tc.want {
				t.Errorf("reply = %q, want %q", reply, tc.want)
			}
		})
	}
}

func TestPromptCardCapturesKeyboard(t *testing.T) {
	h := newHarness(t)
	h.update(PromptMsg{
		Prompt: Prompt{Kind: PromptPermission, Tool: "write_file", Params: map[string]any{}},
		Reply:  func(string) {},
	})
	h.typeText("hello")
	h.update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if len(h.submits) != 0 {
		t.Errorf("submits = %v, want the open card to swallow input", h.submits)
	}
}

func TestQuitWorksWhileCardOpen(t *testing.T) {
	h := newHarness(t)
	h.update(PromptMsg{
		Prompt: Prompt{Kind: PromptPermission, Tool: "write_file", Params: map[string]any{}},
		Reply:  func(string) {},
	})
	_, cmd := h.model.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if !h.quit {
		t.Error("ctrl+c did not quit while a card was open")
	}
	if cmd == nil {
		t.Fatal("ctrl+c returned no quit command")
	}
}

func TestToolResultDisplayIsCapped(t *testing.T) {
	h := newHarness(t)
	body := strings.Join(make([]string, 50), "line\n")
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindToolResult, Result: body}})
	if got := h.printedText(); !strings.Contains(got, "more lines") {
		t.Errorf("a long tool result is not capped in the stream:\n%s", got)
	}
}

func TestPermissionCardShowsSubagentAttribution(t *testing.T) {
	h := newHarness(t)
	h.update(PromptMsg{
		Prompt: Prompt{Kind: PromptPermission, Tool: "bash", Subagent: "recon", Params: map[string]any{"command": "nmap -sV target"}},
		Reply:  func(string) {},
	})
	got := h.view()
	if !strings.Contains(got, "subagent recon") || !strings.Contains(got, "bash") {
		t.Errorf("permission card lacks subagent attribution:\n%s", got)
	}
}

// A subagent block is mutable only while its run is live: it renders in the
// live region (animated, expandable) and is committed to scrollback, final,
// when the run finishes (ADR-0001; spec "scrollback is the pager").
func TestSubagentBlockIsLiveThenPrints(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindSubagent, Subagent: "coder", Detail: "start", Text: "fix the build",
	}})
	got := h.view()
	for _, want := range []string{"subagent coder", "running", "fix the build"} {
		if !strings.Contains(got, want) {
			t.Fatalf("live block is missing %q:\n%s", want, got)
		}
	}

	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindToolCall, Subagent: "coder", Tool: "read_file",
		Params: map[string]any{"path": "main.go"}, Verdict: "allow",
	}})
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindToolResult, Subagent: "coder", Tool: "read_file", Result: "package main\n",
	}})

	// Expanded while still live, the transcript shows in the live region.
	h.update(tea.KeyPressMsg{Code: tea.KeyTab})
	if got := h.view(); !strings.Contains(got, "package main") {
		t.Fatalf("expanded live block does not show its transcript:\n%s", got)
	}

	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindSubagent, Subagent: "coder", Detail: "report", Text: "build fixed",
	}})

	printed := h.printedText()
	for _, want := range []string{"subagent coder", "done", "package main", "build fixed", "report"} {
		if !strings.Contains(printed, want) {
			t.Errorf("committed block is missing %q:\n%s", want, printed)
		}
	}
	if strings.Contains(h.view(), "subagent coder") {
		t.Errorf("the committed block is still in the live region:\n%s", h.view())
	}
}

func TestCollapsedSubagentBlockPrintsItsHeaderOnly(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindSubagent, Subagent: "coder", Detail: "start", Text: "fix the build",
	}})
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindToolResult, Subagent: "coder", Tool: "read_file", Result: "package main\n",
	}})
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindSubagent, Subagent: "coder", Detail: "report", Text: "build fixed",
	}})

	printed := h.printedText()
	if !strings.Contains(printed, "subagent coder") || !strings.Contains(printed, "build fixed") {
		t.Fatalf("committed block header is wrong:\n%s", printed)
	}
	if strings.Contains(printed, "package main") {
		t.Errorf("a collapsed block printed its transcript:\n%s", printed)
	}
}

func TestSubagentBlocksSeparateSameRoleRuns(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindSubagent, Subagent: "coder", RunID: "coder-1", Detail: "start", Text: "first",
	}})
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindSubagent, Subagent: "coder", RunID: "coder-2", Detail: "start", Text: "second",
	}})
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindToolResult, Subagent: "coder", RunID: "coder-1", Tool: "read_file", Result: "first-output",
	}})
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindToolResult, Subagent: "coder", RunID: "coder-2", Tool: "read_file", Result: "second-output",
	}})

	// Each run's transcript holds only its own events.
	b1 := h.model.subagents["coder-1"]
	b2 := h.model.subagents["coder-2"]
	if b1 == nil || b2 == nil {
		t.Fatalf("blocks = %v, want one per run", h.model.subagents)
	}
	if len(b1.lines) != 1 || b1.lines[0] != "first-output" {
		t.Errorf("run coder-1 transcript = %v, want only its own output", b1.lines)
	}
	if len(b2.lines) != 1 || b2.lines[0] != "second-output" {
		t.Errorf("run coder-2 transcript = %v, want only its own output", b2.lines)
	}
}

func TestSubagentBlockSuppressesDispatchResult(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindToolResult, Tool: "dispatch_subagent", Result: "the duplicated report",
	}})
	if strings.Contains(h.printedText(), "the duplicated report") {
		t.Errorf("the dispatch result was rendered twice:\n%s", h.printedText())
	}
}

func TestStatusBarShowsCompactionLevel(t *testing.T) {
	m := New(Config{Status: func() Status {
		return Status{Mode: "safe", Model: "deepseek-flash", Compaction: "ctx 42%"}
	}})
	if got := m.View().Content; !strings.Contains(got, "ctx 42%") {
		t.Errorf("status bar does not surface the compaction level:\n%s", got)
	}
}

func TestStatusBarShowsDegradedProvider(t *testing.T) {
	m := New(Config{Status: func() Status {
		return Status{Mode: "safe", Model: "deepseek-flash", Provider: "no api key"}
	}})
	got := m.View().Content
	if !strings.Contains(got, "provider no api key") {
		t.Errorf("status bar does not surface the degraded provider:\n%s", got)
	}
}

func TestStreamRendersCompaction(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{
		Kind:   sessions.KindCompaction,
		Detail: "context 87% → 41%: evicted 2 tool result(s)",
	}})
	got := h.printedText()
	if !strings.Contains(got, "compacted") || !strings.Contains(got, "evicted 2 tool result(s)") {
		t.Errorf("compaction card is not rendered:\n%s", got)
	}
}

func TestThemeAutoSelectsFromBackground(t *testing.T) {
	h := newHarness(t)

	// The dark theme is the default before the terminal answers.
	if !h.model.dark || h.model.styles.name != "dark" {
		t.Fatalf("default theme = %q (dark=%v), want dark", h.model.styles.name, h.model.dark)
	}

	h.update(tea.BackgroundColorMsg{Color: color.White})
	if h.model.dark || h.model.styles.name != "light" {
		t.Errorf("light background selected %q (dark=%v), want light", h.model.styles.name, h.model.dark)
	}

	h.update(tea.BackgroundColorMsg{Color: color.Black})
	if !h.model.dark || h.model.styles.name != "dark" {
		t.Errorf("dark background selected %q (dark=%v), want dark", h.model.styles.name, h.model.dark)
	}
}

func TestThemesDiffer(t *testing.T) {
	dark, light := darkTheme(), lightTheme()
	for _, pair := range []struct {
		name string
		d, l color.Color
	}{
		{"add", dark.addColor, light.addColor},
		{"del", dark.delColor, light.delColor},
		{"accent", dark.accent, light.accent},
		{"text", dark.text, light.text},
	} {
		if pair.d == pair.l {
			t.Errorf("%s color is identical in dark and light themes (%v)", pair.name, pair.d)
		}
	}
}

func TestStatusBarShowsTargetsAndCost(t *testing.T) {
	m := New(Config{Status: func() Status {
		return Status{
			Mode:    "engagement",
			Model:   "deepseek-flash",
			Targets: "scope 10.0.0.0/24,192.0.2.44",
			Cost:    "cost $0.0012",
		}
	}})
	got := m.View().Content
	for _, want := range []string{"scope 10.0.0.0/24,192.0.2.44", "cost $0.0012"} {
		if !strings.Contains(got, want) {
			t.Errorf("status bar is missing %q:\n%s", want, got)
		}
	}
}

func TestStatusBarReflectsLiveIsolationChange(t *testing.T) {
	isolation := ""
	m := New(Config{Status: func() Status { return Status{Mode: "safe", Isolation: isolation} }})
	if strings.Contains(m.View().Content, "degraded-isolation") {
		t.Fatal("setup: isolation was already degraded")
	}

	// The isolation level samples live state, so a degradation surfacing on
	// the event bus updates the bar without a restart (§9.5).
	isolation = "degraded-isolation"
	_, _ = m.Update(EventMsg{Event: sessions.Event{Kind: sessions.KindIsolation, Detail: "degraded isolation"}})
	if !strings.Contains(m.View().Content, "degraded-isolation") {
		t.Errorf("status bar did not reflect the degraded isolation:\n%s", m.View().Content)
	}
}

func TestClearResetsModelContextButKeepsScrollback(t *testing.T) {
	cleared := false
	h := &harness{}
	h.model = New(Config{
		Status:  func() Status { return Status{Mode: "safe"} },
		Submit:  func(string) {},
		Clear:   func() { cleared = true },
		Command: func(string, string) (string, error) { return "", nil },
	})
	h.model.print = func(lines ...string) tea.Cmd {
		h.printed = append(h.printed, lines...)
		return nil
	}
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindUser, Text: "remember this"}})
	if !strings.Contains(h.printedText(), "remember this") {
		t.Fatal("setup: the turn was not committed to scrollback")
	}

	h.typeText("/clear")
	h.update(tea.KeyPressMsg{Code: tea.KeyEnter})

	if !cleared {
		t.Error("/clear did not reset the harness conversation")
	}
	if !strings.Contains(h.printedText(), "cleared") {
		t.Errorf("no confirmation that context cleared:\n%s", h.printedText())
	}
	// Committed lines are immutable: /clear cannot reach back into scrollback.
	if !strings.Contains(h.printedText(), "remember this") {
		t.Errorf("the immutable scrollback was rewritten by /clear:\n%s", h.printedText())
	}
	if live := h.view(); strings.Contains(live, "remember this") {
		t.Errorf("cleared content is still in the live region:\n%s", live)
	}
}

func TestBannerRendersOnWideTerminal(t *testing.T) {
	h := newHarness(t)
	h.update(tea.WindowSizeMsg{Width: bannerWidth + 11, Height: 40})
	got := h.printedText()
	for _, want := range []string{"/$$$$$$$", "|  $$$$$$/", `\______/`} {
		if !strings.Contains(got, want) {
			t.Errorf("wide terminal does not render the wordmark (%q):\n%s", want, got)
		}
	}
}

func TestBannerSkippedOnNarrowTerminal(t *testing.T) {
	h := newHarness(t)
	h.update(tea.WindowSizeMsg{Width: bannerWidth - 1, Height: 40})
	if got := h.printedText(); strings.Contains(got, "/$$$$$$$") {
		t.Errorf("narrow terminal rendered the wordmark instead of skipping it:\n%s", got)
	}
}

func TestBannerWidthMatchesArt(t *testing.T) {
	widest := 0
	for _, ln := range bannerLines() {
		if w := lipgloss.Width(ln); w > widest {
			widest = w
		}
	}
	if widest != bannerWidth {
		t.Errorf("wordmark widest row = %d columns, guard = %d", widest, bannerWidth)
	}

	// Exactly at the guard it renders; one column under it does not.
	at := newHarness(t)
	at.update(tea.WindowSizeMsg{Width: bannerWidth, Height: 40})
	if !strings.Contains(at.printedText(), "/$$$$$$$") {
		t.Errorf("the banner was skipped at its own %d-column width:\n%s", bannerWidth, at.printedText())
	}
}

func TestBannerPlacedOnce(t *testing.T) {
	// A resize below the guard after placement keeps the banner: it belongs to
	// the transcript, not the live layout.
	wide := newHarness(t)
	wide.update(tea.WindowSizeMsg{Width: bannerWidth, Height: 40})
	wide.update(tea.WindowSizeMsg{Width: bannerWidth - 1, Height: 40})
	if !strings.Contains(wide.printedText(), "/$$$$$$$") {
		t.Error("banner disappeared after a resize below the guard")
	}

	// A narrow startup skips it, and widening later does not resurrect it.
	narrow := newHarness(t)
	narrow.update(tea.WindowSizeMsg{Width: bannerWidth - 1, Height: 40})
	narrow.update(tea.WindowSizeMsg{Width: bannerWidth + 11, Height: 40})
	if strings.Contains(narrow.printedText(), "/$$$$$$$") {
		t.Error("banner was added after a narrow startup")
	}
}

func TestBannerStampsVersionBottomRight(t *testing.T) {
	m, printed := newCapturedModel(Config{
		Version: "v9.9.9",
		Status:  func() Status { return Status{Mode: "safe"} },
	})
	m.Update(tea.WindowSizeMsg{Width: bannerWidth + versionGap + 20, Height: 40})
	got := strings.Join(*printed, "\n")
	var row string
	for _, ln := range *printed {
		if strings.Contains(ln, "v9.9.9") {
			row = ln
			break
		}
	}
	if row == "" {
		t.Fatalf("version is not stamped on any banner row:\n%s", got)
	}
	if !strings.Contains(row, `\______/`) {
		t.Errorf("version is not on the bottom art row:\n%s", row)
	}
	if i := strings.Index(row, "v9.9.9"); i < 0 || lipgloss.Width(row[:i]) < bannerWidth {
		t.Errorf("version is not right of the %d-column art:\n%s", bannerWidth, row)
	}
}

func TestBannerDropsVersionWhenTooNarrow(t *testing.T) {
	m, printed := newCapturedModel(Config{
		Version: "v9.9.9",
		Status:  func() Status { return Status{Mode: "safe"} },
	})
	m.Update(tea.WindowSizeMsg{Width: bannerWidth, Height: 40})
	got := strings.Join(*printed, "\n")
	if !strings.Contains(got, "/$$$$$$$") {
		t.Fatalf("banner skipped at its own width:\n%s", got)
	}
	if strings.Contains(got, "v9.9.9") {
		t.Errorf("version stamped without room for it:\n%s", got)
	}
}
