package tui

import "strings"

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
