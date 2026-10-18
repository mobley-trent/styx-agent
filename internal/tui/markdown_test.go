package tui

import (
	"fmt"
	"image/color"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// markdownAnswer exercises every construct the ticket names: a heading,
// emphasis, inline code, a list, a table, a link, and a fenced block.
const markdownAnswer = "## Findings\n" +
	"\n" +
	"The host runs **nginx** 1.18 with `mod_ssl`.\n" +
	"\n" +
	"- port 80 open\n" +
	"- port 443 open\n" +
	"\n" +
	"| port | service |\n" +
	"|---|---|\n" +
	"| 80 | http |\n" +
	"| 443 | https |\n" +
	"\n" +
	"See [the advisory](https://nvd.nist.gov/x).\n" +
	"\n" +
	"```go\n" +
	"func main() {}\n" +
	"```\n"

// The committed answer is the rendered form: the markdown source syntax is gone
// and the terminal holds the formatted blocks (docs/tui-parity.md §3).
func TestMarkdownRendersAssistantAnswer(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindAssistant, Text: markdownAnswer}})
	got, visible := h.printedText(), h.plainPrinted()

	for _, raw := range []string{"**", "```", "|--", "](", "`mod_ssl`"} {
		if strings.Contains(visible, raw) {
			t.Errorf("raw markdown %q reached the scrollback:\n%s", raw, visible)
		}
	}
	for _, want := range []string{
		"## Findings",            // heading
		"nginx 1.18 with",        // emphasis renders as text, not asterisks
		"mod_ssl",                // inline code
		"• port 80 open",         // list marker
		"port",                   // table cell
		"│",                      // table column separator
		"────",                   // table rule
		"the advisory",           // link text
		"https://nvd.nist.gov/x", // link target
		"func main() {}",         // fenced code
	} {
		if !strings.Contains(visible, want) {
			t.Errorf("rendered answer is missing %q:\n%s", want, visible)
		}
	}
	if !strings.Contains(got, "\x1b[") {
		t.Errorf("rendered answer carries no styling:\n%q", got)
	}
	// glamour pads each block to the wrap width; the padding must not survive as
	// trailing whitespace or a line's worth of styling escapes.
	for _, line := range h.printed {
		if strings.HasSuffix(line, " ") {
			t.Errorf("committed line carries trailing padding: %q", line)
		}
	}
}

// The live partial still streams raw above the prompt; only the committed line
// is rendered. A turn that ends on a partial (an interrupted one) commits the
// rendered form too.
func TestMarkdownRendersCommittedPartial(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindTextDelta, Text: "**done** "}})
	if live := h.view(); !strings.Contains(live, "**done**") {
		t.Errorf("the streaming partial should still show its source:\n%s", live)
	}

	h.update(EventMsg{Event: sessions.Event{
		Kind: sessions.KindToolCall, Tool: "read_file",
		Params: map[string]any{"path": "a"}, Verdict: "allow",
	}})
	visible := h.plainPrinted()
	if strings.Contains(visible, "**done**") {
		t.Errorf("the committed partial is not rendered markdown:\n%s", visible)
	}
	if !strings.Contains(visible, "done") {
		t.Errorf("the committed partial lost its text:\n%s", visible)
	}
}

// A subagent's answer is assistant output too, so it prints formatted inside the
// block's indentation.
func TestMarkdownRendersSubagentAnswer(t *testing.T) {
	h := newHarness(t)
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindSubagent, Subagent: "recon", RunID: "r1", Detail: "start"}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindAssistant, Subagent: "recon", RunID: "r1", Text: "**found** the port"}})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindSubagent, Subagent: "recon", RunID: "r1", Text: "**found** the port"}})

	visible := h.plainPrinted()
	if strings.Contains(visible, "**found**") {
		t.Errorf("subagent markdown reached the scrollback unrendered:\n%s", visible)
	}
	if !strings.Contains(visible, "found the port") {
		t.Errorf("subagent answer is missing from the scrollback:\n%s", visible)
	}
}

// The renderer follows the terminal background: the answer committed under a
// light background is tinted from the light palette, not the dark one.
func TestMarkdownFollowsTheme(t *testing.T) {
	h := newHarness(t)
	darkText := sgrForeground(darkTheme().text)
	lightText := sgrForeground(lightTheme().text)

	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindAssistant, Text: "**bold** answer"}})
	darkPrinted := h.printedText()
	if !strings.Contains(darkPrinted, darkText) {
		t.Errorf("dark answer is not tinted with the dark palette (%s):\n%q", darkText, darkPrinted)
	}

	committed := len(h.printed)
	h.update(tea.BackgroundColorMsg{Color: color.White})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindAssistant, Text: "**bold** answer"}})

	lightPrinted := strings.Join(h.printed[committed:], "\n")
	if !strings.Contains(lightPrinted, lightText) {
		t.Errorf("light answer is not tinted with the light palette (%s):\n%q", lightText, lightPrinted)
	}
	if strings.Contains(lightPrinted, darkText) {
		t.Errorf("light answer still carries the dark palette (%s):\n%q", darkText, lightPrinted)
	}
}

// The style config is derived from the palette, so a theme change cannot leave
// markdown rendering in the old scheme.
func TestMarkdownStyleTracksPalette(t *testing.T) {
	for _, th := range []theme{darkTheme(), lightTheme()} {
		cfg := markdownStyle(th)
		if got, want := deref(cfg.Text.Color), hexOf(th.text); got != want {
			t.Errorf("%s text color = %q, want the palette text %q", th.name, got, want)
		}
		// The document stays uncolored: glamour pads to the wrap width in the
		// document style, and a color there costs an escape per padded cell.
		if cfg.Document.Color != nil {
			t.Errorf("%s document color = %q, want it unset", th.name, *cfg.Document.Color)
		}
		if got, want := deref(cfg.Heading.Color), hexOf(th.accent); got != want {
			t.Errorf("%s heading color = %q, want the palette accent %q", th.name, got, want)
		}
		if got, want := deref(cfg.Link.Color), hexOf(th.accent); got != want {
			t.Errorf("%s link color = %q, want the palette accent %q", th.name, got, want)
		}
		// The builtin H1 is a saturated banner block; in a transcript it keeps the
		// accent alone.
		if cfg.H1.BackgroundColor != nil {
			t.Errorf("%s H1 keeps a background block: %q", th.name, *cfg.H1.BackgroundColor)
		}
	}
}

// An answer wraps to the terminal: no committed line renders wider than the
// live region's width, and a long paragraph takes more than one line.
func TestMarkdownWrapsToTerminalWidth(t *testing.T) {
	h := newHarness(t)
	const width = 40
	h.update(tea.WindowSizeMsg{Width: width, Height: 20})
	h.update(EventMsg{Event: sessions.Event{Kind: sessions.KindAssistant, Text: strings.Repeat("word ", 30)}})

	if len(h.printed) < 2 {
		t.Fatalf("a 150-column paragraph committed %d line(s), want it wrapped:\n%q", len(h.printed), h.printed)
	}
	for _, line := range h.printed {
		if w := lipgloss.Width(line); w > width {
			t.Errorf("committed line renders %d columns, want at most %d: %q", w, width, line)
		}
	}
}

func TestTrimLinePadding(t *testing.T) {
	const style = "\x1b[38;2;1;2;3m"
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"padding only", "  " + style + " \x1b[m", ""},
		{"trailing padding", "  " + style + "content\x1b[m" + style + " \x1b[m",
			"  " + style + "content" + sgrReset},
		{"no padding", "  plain text", "  plain text"},
		{"hyperlink then padding", "\x1b]8;;https://x\x07link\x1b]8;;\x07 ",
			"\x1b]8;;https://x\x07link" + sgrReset + hyperlinkReset},
		{"st-terminated hyperlink", "\x1b]8;;https://x\x1b\\link ", "\x1b]8;;https://x\x1b\\link" + sgrReset + hyperlinkReset},
	}
	for _, tc := range tests {
		if got := trimLinePadding(tc.in); got != tc.want {
			t.Errorf("%s: trimLinePadding(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// deref reads a glamour style's optional color string.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// sgrForeground is the truecolor SGR sequence the renderer emits for a palette
// color.
func sgrForeground(c color.Color) string {
	r, g, b, _ := c.RGBA()
	return fmt.Sprintf("38;2;%d;%d;%d", r>>8, g>>8, b>>8)
}
