package tui

import (
	"fmt"
	"image/color"
	"strings"
	"unicode"
	"unicode/utf8"

	"charm.land/glamour/v2"
	"charm.land/glamour/v2/ansi"
	"charm.land/glamour/v2/styles"
)

// markdownMinWidth is the narrowest wrap width handed to glamour. Below it a
// paragraph would break on nearly every word, so the renderer uses it as the
// floor rather than following the terminal further down.
const markdownMinWidth = 20

// markdownRenderer renders committed assistant answers as formatted terminal
// markdown (docs/tui-parity.md §3). Streamed deltas still show raw in the live
// region; the line that reaches the scrollback is the rendered form.
//
// The renderer is cached per theme and width, so a long stream pays for one
// construction rather than one per committed answer.
type markdownRenderer struct {
	renderer *glamour.TermRenderer
	dark     bool
	width    int
}

// rendererFor returns the renderer for the theme and width in force, rebuilding
// the cached one when either changed. nil means no renderer could be built; the
// caller then prints the text verbatim rather than losing the answer.
func (m *markdownRenderer) rendererFor(th theme, width int) *glamour.TermRenderer {
	if width < markdownMinWidth {
		width = markdownMinWidth
	}
	if m.renderer != nil && m.dark == th.dark && m.width == width {
		return m.renderer
	}
	r, err := glamour.NewTermRenderer(
		glamour.WithStyles(markdownStyle(th)),
		glamour.WithWordWrap(width),
	)
	if err != nil {
		m.renderer, m.dark, m.width = nil, th.dark, width
		return nil
	}
	m.renderer, m.dark, m.width = r, th.dark, width
	return r
}

// render renders one assistant answer for the scrollback. An empty answer, a
// renderer that could not be built, and a render failure all return the text
// unchanged: a formatting problem must never swallow what the model said.
func (m *markdownRenderer) render(text string, th theme, width int) string {
	if strings.TrimSpace(text) == "" {
		return text
	}
	r := m.rendererFor(th, width)
	if r == nil {
		return text
	}
	out, err := r.Render(text)
	if err != nil {
		return text
	}
	// glamour brackets every document with newlines, and fills each block to
	// the wrap width with styled spaces. The transcript supplies its own line
	// breaks and needs neither, so both go.
	lines := strings.Split(strings.Trim(out, "\n"), "\n")
	for i, line := range lines {
		lines[i] = trimLinePadding(line)
	}
	return strings.Join(lines, "\n")
}

// trimLinePadding drops the trailing padding glamour writes to fill every block
// to the wrap width: visible spaces, each one wrapped in its own style sequence.
// Left in place, a committed line would carry a terminal's width of escapes, and
// copying one out of the scrollback would drag a train of trailing spaces with
// it. Padding-only lines become empty.
//
// The cut lands after the last visible non-space rune, so it can fall inside an
// open style or hyperlink. A cut line therefore closes what was still open: SGR
// always, the hyperlink only while one was open at the cut.
func trimLinePadding(line string) string {
	end, link := 0, false
	open := false
	for i := 0; i < len(line); {
		size, escape := ansiToken(line[i:])
		if escape {
			open = hyperlinkOpen(line[i:i+size], open)
			i += size
			continue
		}
		r, size := utf8.DecodeRuneInString(line[i:])
		i += size
		if !unicode.IsSpace(r) {
			end, link = i, open
		}
	}
	switch {
	case end == 0:
		return ""
	case end == len(line):
		return line
	}
	out := line[:end] + sgrReset
	if link {
		out += hyperlinkReset
	}
	return out
}

// hyperlinkOpen reports the OSC 8 hyperlink state after seq: parameters that
// carry a URI open a hyperlink, empty parameters close it.
func hyperlinkOpen(seq string, open bool) bool {
	const prefix = "\x1b]8;"
	if !strings.HasPrefix(seq, prefix) {
		return open
	}
	params := strings.TrimSuffix(strings.TrimSuffix(seq[len(prefix):], "\x07"), "\x1b\\")
	return params != ""
}

// The two sequences that leave the pen clean after a cut.
const (
	sgrReset       = "\x1b[m"
	hyperlinkReset = "\x1b]8;;\x07"
)

// stripANSI removes escape sequences, leaving the visible text. A one-line
// preview of rendered markdown needs it: a cut inside a sequence would leak the
// sequence into the header.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		size, escape := ansiToken(s[i:])
		if !escape {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// ansiToken is the length of the token at the start of s, and whether it is an
// escape sequence rather than text.
func ansiToken(s string) (int, bool) {
	if s[0] != 0x1b {
		_, size := utf8.DecodeRuneInString(s)
		return size, false
	}
	if len(s) == 1 {
		return 1, true
	}
	switch s[1] {
	case '[': // CSI: parameters, then a final byte in 0x40–0x7e.
		for i := 2; i < len(s); i++ {
			if s[i] >= 0x40 && s[i] <= 0x7e {
				return i + 1, true
			}
		}
		return len(s), true
	case ']': // OSC: runs to BEL or ST.
		for i := 2; i < len(s); i++ {
			switch {
			case s[i] == 0x07:
				return i + 1, true
			case s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\':
				return i + 2, true
			}
		}
		return len(s), true
	default: // Any other escape is its introducer plus one byte.
		return 2, true
	}
}

// markdownStyle is the glamour style config for a theme: the builtin light or
// dark markdown style, retinted from the palette so a rendered answer belongs
// to the same scheme as the rest of the UI. The builtin style keeps the parts
// the palette has no opinion on — code-block syntax colors, table borders,
// list markers.
func markdownStyle(th theme) ansi.StyleConfig {
	cfg := styles.LightStyleConfig
	if th.dark {
		cfg = styles.DarkStyleConfig
	}
	text, accent := hexOf(th.text), hexOf(th.accent)

	// Body text takes the palette on Text, not Document. glamour fills every block
	// to the wrap width with the document style, so a document color emits a
	// styled escape per padded cell — a terminal width of them per line, and a
	// measurable stall on a long answer. With the document uncolored the padding
	// is bare spaces, and the text still carries the palette.
	cfg.Document.Color = nil
	cfg.Text.Color = &text
	cfg.Heading.Color = &accent
	// The builtin H1 is a banner: glyphs on a saturated background block. In a
	// transcript it only has to outrank H2, so it keeps the accent alone.
	cfg.H1.Color = &accent
	cfg.H1.BackgroundColor = nil
	cfg.Link.Color = &accent
	cfg.LinkText.Color = &accent
	cfg.Item.Color = &accent
	cfg.Enumeration.Color = &accent
	return cfg
}

// hexOf renders a palette color as the #rrggbb string a glamour style config
// takes — its color fields are strings, not colors.
func hexOf(c color.Color) string {
	r, g, b, _ := c.RGBA()
	return fmt.Sprintf("#%02x%02x%02x", r>>8, g>>8, b>>8)
}
