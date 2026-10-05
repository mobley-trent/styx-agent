// Package naming splits identifiers into lowercase tokens. It is shared by the
// MCP target matcher (tool-parameter names) and the skill packs' MCP server
// classification, so both agree on what a token boundary is.
package naming

import "strings"

// Tokens splits an identifier into lowercase tokens at separators (_, -, .,
// /, space) and camelCase boundaries, including acronym runs:
// "targetHost" → [target host], "IPAddress" → [ip address], "recipient" →
// [recipient].
func Tokens(name string) []string {
	runes := []rune(name)
	var tokens []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			tokens = append(tokens, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	isUpper := func(r rune) bool { return r >= 'A' && r <= 'Z' }
	isLower := func(r rune) bool { return r >= 'a' && r <= 'z' }
	isDigit := func(r rune) bool { return r >= '0' && r <= '9' }

	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.' || r == '/' || r == ' ':
			flush()
			continue
		case isUpper(r):
			prevBoundary := i > 0 && (isLower(runes[i-1]) || isDigit(runes[i-1]))
			acronymEnd := i > 0 && isUpper(runes[i-1]) && i+1 < len(runes) && isLower(runes[i+1])
			if len(cur) > 0 && (prevBoundary || acronymEnd) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return tokens
}
