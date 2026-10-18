package tui

import (
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// picker is one modal command picker: a bubbles list over the options a
// command's registry entry declares (docs/tui-parity.md §4). While it is open
// it owns the keyboard and the live region; choosing a row runs the command
// with that row's value, and Escape closes it without running anything.
type picker struct {
	// command is the registry name the chosen value is submitted with.
	command string
	list    list.Model
}

// optionItem is one picker row: the label is the row's title and the detail is
// its description, both matching against the filter.
type optionItem struct {
	opt Option
}

func (o optionItem) FilterValue() string { return o.opt.Label + " " + o.opt.Detail }

func (o optionItem) Title() string { return o.opt.Label }

func (o optionItem) Description() string { return o.opt.Detail }

// newPicker builds a themed, focused picker for a command's options.
func newPicker(th theme, command string, options []Option, width, height int) *picker {
	items := make([]list.Item, 0, len(options))
	for _, opt := range options {
		items = append(items, optionItem{opt: opt})
	}
	delegate := list.NewDefaultDelegate()
	delegate.Styles = optionStyles(th)

	l := list.New(items, delegate, width, height)
	// The picker draws its own header and the status bar below it, so the
	// list's title bar and key help would only duplicate chrome.
	l.SetShowTitle(false)
	l.SetShowHelp(false)
	l.Styles.StatusBar = lipgloss.NewStyle().Faint(true).Foreground(th.muted).Padding(0, 0, 0, 2)
	l.Styles.StatusEmpty = l.Styles.StatusBar
	l.Styles.NoItems = lipgloss.NewStyle().Foreground(th.muted).Padding(0, 0, 0, 2)
	// Escape and q belong to the picker, never to the program: the list's own
	// quit bindings would otherwise end styx from inside a modal.
	l.KeyMap.Quit = key.NewBinding()
	l.KeyMap.ForceQuit = key.NewBinding()

	return &picker{command: command, list: l}
}

// optionStyles retints the list delegate from the active theme.
func optionStyles(th theme) list.DefaultItemStyles {
	s := list.NewDefaultItemStyles(th.dark)
	s.NormalTitle = lipgloss.NewStyle().Foreground(th.text).Padding(0, 0, 0, 2)
	s.NormalDesc = s.NormalTitle.Foreground(th.muted)
	s.SelectedTitle = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(th.accent).
		Foreground(th.accent).
		Padding(0, 0, 0, 1)
	// The description keeps the border so the two lines stay aligned.
	s.SelectedDesc = s.SelectedTitle.Foreground(th.muted)
	s.DimmedTitle = lipgloss.NewStyle().Foreground(th.muted).Padding(0, 0, 0, 2)
	s.DimmedDesc = s.DimmedTitle
	s.FilterMatch = lipgloss.NewStyle().Underline(true).Foreground(th.accent)
	return s
}

// setSize fits the picker to the live region it owns.
func (p *picker) setSize(width, height int) { p.list.SetSize(width, height) }

// rows is how many options the picker holds, so a resize can size it again.
func (p *picker) rows() int { return len(p.list.Items()) }

// selected returns the row under the cursor.
func (p *picker) selected() (Option, bool) {
	item, ok := p.list.SelectedItem().(optionItem)
	if !ok {
		return Option{}, false
	}
	return item.opt, true
}

// update forwards a message to the list, returning its command (blink and
// filter work happen there).
func (p *picker) update(msg tea.Msg) tea.Cmd {
	l, cmd := p.list.Update(msg)
	p.list = l
	return cmd
}

// view renders the picker: a header naming the choice and the keys that resolve
// it, then the list.
func (p *picker) view(th theme) []string {
	header := th.cardKey.Render("select a "+p.command) +
		th.card.Render("   ↑/↓ move · enter select · esc cancel")
	lines := []string{header}
	body := strings.Split(p.list.View(), "\n")
	// The list opens with the title bar it was told not to draw, which reaches
	// the view as one blank line. Drop it, so the picker's own header sits
	// directly above the list's rows.
	if len(body) > 0 && strings.TrimSpace(body[0]) == "" {
		body = body[1:]
	}
	return append(lines, body...)
}

// pickerKey handles a key press while the picker is modal. It returns the
// command to run, which is nil unless a row was chosen.
func (m *Model) pickerKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.Key().Code {
	case tea.KeyEscape:
		m.picker = nil
		return nil
	case tea.KeyEnter:
		// While the picker's own filter is open, Enter applies the filter;
		// otherwise it chooses the row under the cursor.
		if m.picker.list.SettingFilter() {
			break
		}
		opt, ok := m.picker.selected()
		command := m.picker.command
		m.picker = nil
		if !ok {
			return nil
		}
		// The chosen value is submitted as the command line it stands for, so
		// the picker runs the same path as typing the command out.
		m.editor.show("/" + command + " " + opt.Value)
		return m.submit()
	}
	if m.picker == nil {
		return nil
	}
	return m.picker.update(msg)
}

// openPicker opens a command's modal picker over its options.
func (m *Model) openPicker(command string, options []Option) {
	m.menu.close()
	m.picker = newPicker(m.styles, command, options, m.width, m.pickerHeight(len(options)))
}

// pickerHeight sizes the picker's list to its content, bounded by the live
// region: the status bar stays visible below the picker, and one row of headroom
// keeps the inline renderer's repaint inside the terminal. A selector with more
// rows than fit paginates rather than growing past the screen.
func (m *Model) pickerHeight(options int) int {
	// The list lays each option out as a label, its detail, and a spacer, and
	// keeps a status bar and a pagination row beneath them; four rows of slack
	// make every option fit on one page.
	h := options*3 + 4
	if limit := m.height - 3; h > limit {
		h = limit
	}
	if h < 4 {
		h = 4
	}
	return h
}
