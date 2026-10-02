package tui

import (
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/mobley-trent/styx-agent/internal/diff"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// harness wires a Model with recording callbacks.
type harness struct {
	model    *Model
	submits  []string
	commands []string
	quit     bool
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{}
	h.model = New(Config{
		Status: func() Status {
			return Status{Mode: "safe", Model: "deepseek-flash", Session: "abc123", Busy: true}
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
	return h
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

func TestStreamRendersModelOutput(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindUser, Text: "what is in main.go?"}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindTextDelta, Text: "Let "}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindTextDelta, Text: "me look."}})

	if got := h.view(); !strings.Contains(got, "Let me look.") {
		t.Errorf("stream does not show the live partial answer:\n%s", got)
	}

	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindToolCall, Tool: "read_file",
		Params: map[string]any{"path": "main.go"}, Verdict: "allow", Reason: "rule-match",
	}})
	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindToolResult, Tool: "read_file", Result: "package main\n",
	}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindAssistant, Text: "It prints usage."}})

	got := h.view()
	for _, want := range []string{"> what is in main.go?", "read_file", "allow", "package main", "It prints usage."} {
		if !strings.Contains(got, want) {
			t.Errorf("stream is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Let me look.") && !strings.Contains(got, "It prints usage.") {
		t.Error("the assembled answer did not replace the live deltas")
	}
}

func TestStreamRendersFailures(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindToolResult, Tool: "read_file", Failure: "no such file"}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindError, Failure: "turn cap reached"}})
	got := h.view()
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
	if got := h.view(); !strings.Contains(got, "commands: /help /resume /quit") {
		t.Errorf("command output is not rendered:\n%s", got)
	}

	h.typeText("/resume 20260101T000000Z-abcd")
	h.update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if len(h.commands) != 2 || h.commands[1] != "resume|20260101T000000Z-abcd" {
		t.Errorf("commands = %v, want the resume argument preserved", h.commands)
	}

	h.typeText("/boom")
	h.update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if got := h.view(); !strings.Contains(got, "command failed") {
		t.Errorf("command error is not rendered:\n%s", got)
	}
}

func TestQuitPaths(t *testing.T) {
	h := newHarness(t)
	h.typeText("/quit")
	h.update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if !h.quit {
		t.Error("/quit did not ask the app to quit")
	}

	other := newHarness(t)
	_, cmd := other.model.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if !other.quit {
		t.Error("ctrl+c did not ask the app to quit")
	}
	if cmd == nil {
		t.Fatal("ctrl+c returned no quit command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
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
	if !strings.Contains(got, "working…") {
		t.Errorf("status bar does not show the busy indicator:\n%s", got)
	}
}

func TestViewTrimsToWindowHeight(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 40; i++ {
		h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindUser, Text: "line"}})
	}
	h.update(tea.WindowSizeMsg{Width: 60, Height: 10})
	got := strings.Count(h.view(), "\n")
	if got > 11 {
		t.Errorf("view has %d newlines for a 10-line terminal, want it trimmed", got)
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
	got := h.view()
	for _, want := range []string{"a.txt (+1 -1)", "-two", "+TWO", "one"} {
		if !strings.Contains(got, want) {
			t.Errorf("inline diff is missing %q:\n%s", want, got)
		}
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
	got := h.view()
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
	if got := h.view(); !strings.Contains(got, "more lines") {
		t.Errorf("a long tool result is not capped in the stream:\n%s", got)
	}
}
