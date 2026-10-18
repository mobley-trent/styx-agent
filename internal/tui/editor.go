package tui

import (
	"strings"

	"charm.land/bubbles/v2/textarea"
	tea "charm.land/bubbletea/v2"
)

const (
	// promptPrefix is the glyph ahead of the input line.
	promptPrefix = "> "
	// historyLimit is how many submitted prompts the ring recalls. It is
	// bounded so a long session cannot grow the model without limit.
	historyLimit = 200
)

// inputEditor is the prompt line: a bubbles textarea for cursor movement, word
// navigation, selection, and mid-line editing, wrapped in a small history ring
// bound to up/down (docs/tui-parity.md §1).
//
// The editor is single-line in practice. Enter never reaches the textarea —
// the model intercepts it to submit — and the textarea's sanitizer collapses
// pasted newlines and tabs to spaces, so a prompt can never span rows.
type inputEditor struct {
	area textarea.Model
	// history holds submitted prompts, oldest first.
	history []string
	// draft is the line that was being edited when recall began, restored
	// when recall runs past the newest entry.
	draft string
	// recalled is the history index being viewed, or -1 when the line is the
	// operator's own.
	recalled int
}

// newInputEditor builds a focused, theme-tinted editor.
func newInputEditor(th theme) inputEditor {
	e := inputEditor{area: textarea.New(), recalled: -1}
	e.area.Prompt = promptPrefix
	e.area.ShowLineNumbers = false
	e.area.EndOfBufferCharacter = ' '
	e.area.SetHeight(1)
	e.area.SetVirtualCursor(true)
	e.setTheme(th)
	e.area.Focus()
	return e
}

// setTheme retints the prompt and the block cursor for the active theme.
func (e *inputEditor) setTheme(th theme) {
	styles := textarea.DefaultStyles(th.dark)
	styles.Focused.Prompt = th.prompt
	styles.Blurred.Prompt = th.prompt
	styles.Cursor.Color = th.accent
	e.area.SetStyles(styles)
}

// setWidth fits the editor to the terminal width.
func (e *inputEditor) setWidth(width int) { e.area.SetWidth(width) }

// value is the current line.
func (e *inputEditor) value() string { return e.area.Value() }

// reset clears the line and leaves history recall.
func (e *inputEditor) reset() {
	e.area.Reset()
	e.recalled, e.draft = -1, ""
}

// endRecall leaves history recall, keeping the line as it stands. An edit to a
// recalled prompt is a fresh line, so the next up starts from the newest
// prompt again.
func (e *inputEditor) endRecall() {
	e.recalled, e.draft = -1, ""
}

// remember adds a submitted prompt to the ring.
func (e *inputEditor) remember(text string) {
	if text = strings.TrimSpace(text); text == "" {
		return
	}
	e.history = append(e.history, text)
	if len(e.history) > historyLimit {
		e.history = append([]string(nil), e.history[len(e.history)-historyLimit:]...)
	}
}

// historyPrev recalls the previous prompt, stashing the draft first so a later
// historyNext can bring it back.
func (e *inputEditor) historyPrev() {
	if len(e.history) == 0 {
		return
	}
	if e.recalled < 0 {
		e.draft = e.area.Value()
		e.recalled = len(e.history)
	}
	if e.recalled > 0 {
		e.recalled--
		e.show(e.history[e.recalled])
	}
}

// historyNext walks back toward the draft, then restores it.
func (e *inputEditor) historyNext() {
	if e.recalled < 0 {
		return
	}
	if e.recalled < len(e.history)-1 {
		e.recalled++
		e.show(e.history[e.recalled])
		return
	}
	e.recalled = -1
	e.show(e.draft)
}

// show replaces the line and puts the cursor at its end.
func (e *inputEditor) show(text string) {
	e.area.SetValue(text)
	e.area.CursorEnd()
}

// update forwards a message to the textarea, returning its command (cursor
// blink and clipboard work happen there).
func (e *inputEditor) update(msg tea.Msg) tea.Cmd {
	area, cmd := e.area.Update(msg)
	e.area = area
	return cmd
}

// view renders the line, prompt included.
func (e *inputEditor) view() string { return e.area.View() }

// typed reports whether a key press edits the line, so history recall ends the
// moment the operator starts changing a recalled prompt.
func typed(msg tea.KeyPressMsg) bool {
	key := msg.Key()
	return key.Text != "" ||
		key.Code == tea.KeyBackspace ||
		key.Code == tea.KeyDelete ||
		key.Code == tea.KeySpace
}
