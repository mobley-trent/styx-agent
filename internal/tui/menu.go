package tui

import (
	"fmt"
	"sort"
	"strings"

	"charm.land/lipgloss/v2"
)

// CommandInfo is one entry in the harness command registry as the TUI draws
// it: a row in the inline slash-command menu, and — when it declares Options —
// a modal picker (docs/tui-parity.md §4). The registry is the harness's single
// source of truth; the TUI never keeps a second copy.
type CommandInfo struct {
	// Name is the canonical command, without the leading slash.
	Name string
	// Usage is the command as it is typed, arguments included ("/model [id]").
	// It is the menu's first column.
	Usage string
	// Description is the one-line explanation shown beside the usage.
	Description string
	// Options lists the command's picker entries. A command that declares them
	// opens a modal picker when it is run with no argument.
	Options func() []Option
}

// Option is one row of a command's modal picker.
type Option struct {
	// Value is the argument the picker submits with the command.
	Value string
	// Label is the row's primary text.
	Label string
	// Detail is the row's secondary text.
	Detail string
}

// menuRows is how many command matches the inline menu shows at once. The
// registry is small, so a window follows the cursor rather than scrolling.
const menuRows = 6

// slashMenu is the inline fuzzy command menu drawn above the input line. It
// opens the moment the line begins with "/" and narrows as the operator types
// the command name; it closes again once an argument is typed, because past
// that point the line is a command invocation rather than a command name.
type slashMenu struct {
	open    bool
	query   string
	matches []CommandInfo
	cursor  int
	// selected is the command under the cursor from the last refresh, so a
	// keystroke that narrows the filter keeps the selection on the same
	// command when it survives.
	selected string
}

// close resets the menu.
func (s *slashMenu) close() { *s = slashMenu{} }

// active reports whether the menu is both open and holding a selection, so a
// key press belongs to it.
func (s *slashMenu) active() bool { return s.open && len(s.matches) > 0 }

// current returns the selected command.
func (s *slashMenu) current() (CommandInfo, bool) {
	if !s.active() || s.cursor < 0 || s.cursor >= len(s.matches) {
		return CommandInfo{}, false
	}
	return s.matches[s.cursor], true
}

// move walks the selection, wrapping at either end, and remembers it.
func (s *slashMenu) move(delta int) {
	if !s.active() {
		return
	}
	s.cursor = (s.cursor + delta + len(s.matches)) % len(s.matches)
	s.selected = s.matches[s.cursor].Name
}

// window is the slice of matches the menu renders: at most menuRows, following
// the cursor.
func (s *slashMenu) window() (int, int) {
	if len(s.matches) <= menuRows {
		return 0, len(s.matches)
	}
	start := s.cursor - menuRows/2
	if start < 0 {
		start = 0
	}
	if start+menuRows > len(s.matches) {
		start = len(s.matches) - menuRows
	}
	return start, start + menuRows
}

// menuQuery reports the command name being typed: the text after "/" while no
// argument has been started. ok is false for a line that is not a command name
// — no slash, or an argument already typed.
func menuQuery(line string) (string, bool) {
	if !strings.HasPrefix(line, "/") {
		return "", false
	}
	body := line[1:]
	if strings.ContainsAny(body, " \t") {
		return "", false
	}
	return body, true
}

// commandRegistry returns the harness command registry, or nil when the app
// attached none.
func (m *Model) commandRegistry() []CommandInfo {
	if m.cfg.Commands == nil {
		return nil
	}
	return m.cfg.Commands()
}

// commandInfo resolves a typed command name against the registry.
func (m *Model) commandInfo(name string) (CommandInfo, bool) {
	for _, info := range m.commandRegistry() {
		if info.Name == name {
			return info, true
		}
	}
	return CommandInfo{}, false
}

// refreshMenu recomputes the inline menu from the line as it now stands.
func (m *Model) refreshMenu() {
	if m.picker != nil {
		m.menu.close()
		return
	}
	query, ok := menuQuery(m.editor.value())
	if !ok {
		m.menu.close()
		return
	}
	matches := filterCommands(query, m.commandRegistry())
	cursor := 0
	for i, info := range matches {
		if info.Name == m.menu.selected {
			cursor = i
			break
		}
	}
	m.menu.open = true
	m.menu.query = query
	m.menu.matches = matches
	m.menu.cursor = cursor
	if len(matches) > 0 {
		m.menu.selected = matches[cursor].Name
	}
}

// filterCommands ranks the registry against a fuzzy query. Registry order
// breaks score ties, so a query that matches several commands keeps the
// curated order.
func filterCommands(query string, registry []CommandInfo) []CommandInfo {
	type scored struct {
		info  CommandInfo
		score int
	}
	hits := make([]scored, 0, len(registry))
	for _, info := range registry {
		score, ok := fuzzyScore(query, info.Name)
		if !ok {
			continue
		}
		hits = append(hits, scored{info: info, score: score})
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	out := make([]CommandInfo, 0, len(hits))
	for _, hit := range hits {
		out = append(out, hit.info)
	}
	return out
}

// fuzzyScore ranks query against target. It is a subsequence match — "rsm"
// finds "resume" — with bonuses for a prefix, a word boundary, and contiguous
// runs, so typing a command's opening letters puts it first.
func fuzzyScore(query, target string) (int, bool) {
	if query == "" {
		return 0, true
	}
	q := []rune(strings.ToLower(query))
	t := []rune(strings.ToLower(target))
	score, at, last := 0, 0, -2
	for _, want := range q {
		found := -1
		for ; at < len(t); at++ {
			if t[at] == want {
				found = at
				break
			}
		}
		if found < 0 {
			return 0, false
		}
		if found == 0 || t[found-1] == '-' || t[found-1] == '_' {
			score += 2
		}
		if found == last+1 {
			score++
		}
		last = found
		at = found + 1
	}
	if strings.HasPrefix(string(t), string(q)) {
		score += 4
	}
	return score, true
}

// menuBlock renders the inline command menu above the input line. It is empty
// when the menu is closed or nothing matches.
func (m *Model) menuBlock() []string {
	if !m.menu.active() {
		return nil
	}
	start, end := m.menu.window()

	width := 0
	for _, info := range m.menu.matches[start:end] {
		if w := lipgloss.Width(info.Usage); w > width {
			width = w
		}
	}
	out := make([]string, 0, menuRows)
	for i := start; i < end; i++ {
		info := m.menu.matches[i]
		marker := "  "
		if i == m.menu.cursor {
			marker = "› "
		}
		row := fmt.Sprintf("%s%-*s  %s", marker, width, info.Usage, info.Description)
		row = truncate(row, m.width)
		if i == m.menu.cursor {
			out = append(out, m.styles.cardKey.Render(row))
			continue
		}
		out = append(out, m.styles.tool.Render(row))
	}
	return out
}
