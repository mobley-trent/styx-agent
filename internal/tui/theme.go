package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// theme is the terminal color scheme (§9.6): one polished dark theme and one
// light variant, auto-selected from the terminal background. The palette
// fields are kept alongside the rendered styles so the selection is inspectable
// without a color-capable terminal.
type theme struct {
	// name is "dark" or "light".
	name string
	// dark reports whether this is the dark variant.
	dark bool

	addColor  color.Color
	delColor  color.Color
	accent    color.Color
	warnColor color.Color
	danger    color.Color
	muted     color.Color
	text      color.Color

	status     lipgloss.Style
	prompt     lipgloss.Style
	tool       lipgloss.Style
	fail       lipgloss.Style
	card       lipgloss.Style
	cardKey    lipgloss.Style
	banner     lipgloss.Style
	diffHeader lipgloss.Style
	add        lipgloss.Style
	del        lipgloss.Style
}

// themeFor selects a theme from the terminal's background (§9.6).
func themeFor(dark bool) theme {
	if dark {
		return darkTheme()
	}
	return lightTheme()
}

// styled derives the rendered styles from the palette, so the two themes share
// one style-construction definition.
func (t theme) styled() theme {
	t.status = lipgloss.NewStyle().Bold(true).Foreground(t.text)
	t.prompt = lipgloss.NewStyle().Bold(true).Foreground(t.accent)
	t.tool = lipgloss.NewStyle().Faint(true).Foreground(t.muted)
	t.fail = lipgloss.NewStyle().Bold(true).Foreground(t.danger)
	t.card = lipgloss.NewStyle().Faint(true)
	t.cardKey = lipgloss.NewStyle().Bold(true).Foreground(t.accent)
	t.banner = lipgloss.NewStyle().Bold(true).Foreground(t.warnColor)
	t.diffHeader = lipgloss.NewStyle().Bold(true).Foreground(t.accent)
	t.add = lipgloss.NewStyle().Foreground(t.addColor)
	t.del = lipgloss.NewStyle().Foreground(t.delColor)
	return t
}

// darkTheme is the default scheme: a bright foreground on the terminal's dark
// background.
func darkTheme() theme {
	return theme{
		name:      "dark",
		dark:      true,
		addColor:  lipgloss.Color("#50fa7b"),
		delColor:  lipgloss.Color("#ff5555"),
		accent:    lipgloss.Color("#8be9fd"),
		warnColor: lipgloss.Color("#f1fa8c"),
		danger:    lipgloss.Color("#ff5555"),
		muted:     lipgloss.Color("#6272a4"),
		text:      lipgloss.Color("#f8f8f2"),
	}.styled()
}

// lightTheme is the variant for a light terminal background: darker, more
// saturated colors so each surface stays legible.
func lightTheme() theme {
	return theme{
		name:      "light",
		dark:      false,
		addColor:  lipgloss.Color("#2f9e44"),
		delColor:  lipgloss.Color("#c92a2a"),
		accent:    lipgloss.Color("#0b7285"),
		warnColor: lipgloss.Color("#946200"),
		danger:    lipgloss.Color("#c92a2a"),
		muted:     lipgloss.Color("#868e96"),
		text:      lipgloss.Color("#212529"),
	}.styled()
}
