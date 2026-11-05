package tui

import (
	"io"
	"strings"

	"charm.land/lipgloss/v2"
)

// bannerWidth is the column width of the STYX AGENT wordmark: its widest glyph
// row is 96 columns. A terminal narrower than this skips the banner entirely
// rather than wrapping or truncating it (art-direction decision, issue #56).
const bannerWidth = 96

// versionGap is the space between the wordmark's right edge and the version
// stamp that rides beside it.
const versionGap = 2

// bannerWordmark is the "STYX AGENT" wordmark shown once at the top of the
// initial transcript and reused as the README logo. It is plain ASCII; the
// TUI tints it through theme.banner at render time (art-direction decision,
// issue #56).
const bannerWordmark = `             /$$                                                                         /$$    
            | $$                                                                        | $$    
  /$$$$$$$ /$$$$$$   /$$   /$$ /$$   /$$        /$$$$$$   /$$$$$$   /$$$$$$  /$$$$$$$  /$$$$$$  
 /$$_____/|_  $$_/  | $$  | $$|  $$ /$$//$$$$$$|____  $$ /$$__  $$ /$$__  $$| $$__  $$|_  $$_/  
|  $$$$$$   | $$    | $$  | $$ \  $$$$/|______/ /$$$$$$$| $$  \ $$| $$$$$$$$| $$  \ $$  | $$    
 \____  $$  | $$ /$$| $$  | $$  >$$  $$        /$$__  $$| $$  | $$| $$_____/| $$  | $$  | $$ /$$
 /$$$$$$$/  |  $$$$/|  $$$$$$$ /$$/\  $$      |  $$$$$$$|  $$$$$$$|  $$$$$$$| $$  | $$  |  $$$$/
|_______/    \___/   \____  $$|__/  \__/       \_______/ \____  $$ \_______/|__/  |__/   \___/  
                     /$$  | $$                           /$$  \ $$                              
                    |  $$$$$$/                          |  $$$$$$/                              
                     \______/                            \______/                               `

// bannerLines returns the wordmark's glyph rows.
func bannerLines() []string {
	return strings.Split(strings.TrimRight(bannerWordmark, "\n"), "\n")
}

// WriteBanner writes the startup wordmark to w for a terminal of the given
// width, stamped with the running version at the bottom-right when there is
// room for both. A terminal narrower than the art gets nothing at all.
//
// The wordmark is written directly, before the Bubble Tea program starts,
// rather than through tea.Println. Until the renderer has tracked a cursor
// position it prints committed lines by scrolling the screen once per line,
// and while the screen above is still empty every one of those scrolls leaves
// a blank line in the scrollback above the art. The tint is the dark theme's:
// the terminal has not reported its background yet when the banner is written.
func WriteBanner(w io.Writer, width int, version string) error {
	if width < bannerWidth {
		return nil
	}
	lines := bannerLines()
	if v := strings.TrimSpace(version); v != "" && width >= bannerWidth+versionGap+lipgloss.Width(v) {
		lines[len(lines)-1] += strings.Repeat(" ", versionGap) + v
	}
	style := themeFor(true).banner
	var b strings.Builder
	for _, ln := range lines {
		b.WriteString(style.Render(ln))
		b.WriteByte('\n')
	}
	_, err := io.WriteString(w, b.String())
	return err
}
