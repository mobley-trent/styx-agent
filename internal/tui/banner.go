package tui

import "strings"

// bannerWidth is the column width of the STYX AGENT wordmark: its widest glyph
// row is 109 columns. A terminal narrower than this skips the banner entirely
// rather than wrapping or truncating it (art-direction decision, issue #56).
const bannerWidth = 109

// versionGap is the space between the wordmark's right edge and the version
// stamp that rides beside it.
const versionGap = 2

// bannerWordmark is the figlet "STYX AGENT" wordmark shown once at the top of
// the initial transcript and reused as the README logo. It is plain ASCII; the
// TUI tints it through theme.banner at render time (art-direction decision,
// issue #56).
const bannerWordmark = ` .d8888b. 88888888888 Y88b   d88P Y88b   d88P            d8888  .d8888b.  8888888888 888b    888 88888888888 
d88P  Y88b    888      Y88b d88P   Y88b d88P            d88888 d88P  Y88b 888        8888b   888     888     
Y88b.         888       Y88o88P     Y88o88P            d88P888 888    888 888        88888b  888     888     
 "Y888b.      888        Y888P       Y888P            d88P 888 888        8888888    888Y88b 888     888     
    "Y88b.    888         888        d888b           d88P  888 888  88888 888        888 Y88b888     888     
      "888    888         888       d88888b  888888 d88P   888 888    888 888        888  Y88888     888     
Y88b  d88P    888         888      d88P Y88b       d8888888888 Y88b  d88P 888        888   Y8888     888     
 "Y8888P"     888         888     d88P   Y88b     d88P     888  "Y8888P88 8888888888 888    Y888     888     `

// bannerLines returns the wordmark's glyph rows.
func bannerLines() []string {
	return strings.Split(strings.TrimRight(bannerWordmark, "\n"), "\n")
}
