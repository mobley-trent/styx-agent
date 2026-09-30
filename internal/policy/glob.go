package policy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// MatchParamGlob reports whether a JSON-pointer glob pattern matches a tool
// call's parameters (§6.1: "glob matchers over JSON-pointer parameter
// paths"). Matching is path existence with wildcards, walked segment by
// segment into the decoded parameter object:
//
//   - "*" matches exactly one segment (a key, or an array index);
//   - "**" matches zero or more segments;
//   - any other segment matches literally;
//   - an array element is addressed by its decimal index, per JSON Pointer;
//   - the pattern may be written with or without the leading '/' ("/a/b" and
//     "a/b" are equivalent); "~1" decodes to '/' and "~0" to '~' per RFC 6901.
//
// A pattern matches only paths that exist in the parameter object; wildcards
// never invent absent keys, and there is no negation. An empty pattern
// matches any parameter object. Deny rules therefore deny exactly the calls
// that carry a matching path.
func MatchParamGlob(pattern string, params map[string]any) bool {
	if pattern == "" {
		return true
	}
	return walk(splitPointer(pattern), params)
}

// walk matches the remaining pattern segments against value. It is
// deterministic: a wildcard segment matches iff some concrete key or element
// it can bind to leads down a matching path — map iteration order never
// decides an answer.
func walk(segments []string, value any) bool {
	if len(segments) == 0 {
		return true
	}
	seg, rest := segments[0], segments[1:]

	if seg == "**" {
		if len(rest) == 0 {
			return true // trailing "**" spans everything below
		}
		// "**" matches zero or more segments: continue here, or descend.
		if walk(rest, value) {
			return true
		}
		for _, child := range childrenOf(value) {
			if walk(segments, child) {
				return true
			}
		}
		return false
	}

	switch node := value.(type) {
	case map[string]any:
		if seg != "*" && !strings.Contains(seg, "*") {
			child, ok := node[seg]
			if !ok {
				return false
			}
			return walk(rest, child)
		}
		// Wildcard key: existential over every key it can bind to, so map
		// iteration order never decides an answer.
		for k, child := range node {
			if segmentMatches(seg, k) && walk(rest, child) {
				return true
			}
		}
		return false
	case []any:
		if seg == "*" {
			for _, child := range node {
				if walk(rest, child) {
					return true
				}
			}
			return false
		}
		i, err := strconv.Atoi(seg)
		if err != nil || i < 0 || i >= len(node) {
			return false
		}
		return walk(rest, node[i])
	default:
		// A scalar has no segments below it.
		return false
	}
}

// segmentMatches reports whether one pattern segment matches one literal
// segment (a key or an array index). "*" as the whole segment matches
// anything; '*' inside a segment matches any run of characters within that
// segment ("mcp__*", "*2024*"); everything else is literal.
func segmentMatches(patternSeg, literalSeg string) bool {
	if !strings.Contains(patternSeg, "*") {
		return patternSeg == literalSeg
	}
	return globSegment(patternSeg, literalSeg)
}

// globSegment matches a single segment pattern with '*' wildcards (iterative
// greedy backtracking; '*' never crosses segment boundaries because callers
// pre-split).
func globSegment(pattern, s string) bool {
	p, s2, starP, starS := 0, 0, -1, 0
	for s2 < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			starP, starS = p, s2
			p++
		case p < len(pattern) && pattern[p] == s[s2]:
			p++
			s2++
		case starP >= 0:
			starS++
			s2 = starS
			p = starP + 1
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// childrenOf yields the immediate child values of a node.
func childrenOf(value any) []any {
	switch node := value.(type) {
	case map[string]any:
		out := make([]any, 0, len(node))
		for _, v := range node {
			out = append(out, v)
		}
		return out
	case []any:
		return node
	default:
		return nil
	}
}

// splitPointer splits a JSON-pointer-style pattern into decoded segments.
// The pattern is split on '/' first; then each segment decodes '~1' → '/' and
// '~0' → '~' (RFC 6901 order), so a key containing '/' survives as one
// segment. Decoding after the split is what keeps that correct.
func splitPointer(pattern string) []string {
	p := strings.TrimPrefix(pattern, "/")
	if p == "" {
		return nil
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		s = strings.ReplaceAll(s, "~1", "/")
		s = strings.ReplaceAll(s, "~0", "~")
		segs[i] = s
	}
	return segs
}

// ParseParams decodes a tool call's raw JSON arguments into the parameter
// map the engine evaluates. Empty input is an empty parameter object;
// non-object JSON is an error.
func ParseParams(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var params map[string]any
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, fmt.Errorf("policy: tool-call params must be a JSON object: %w", err)
	}
	return params, nil
}

// globMatch reports whether a tool-name pattern matches a tool name: the
// same glob vocabulary as parameter patterns ('*' matches any run of
// characters within a segment, "**" spans segments, literals otherwise),
// applied to the '/'-split tool string.
func globMatch(pattern, tool string) bool {
	path := []string(nil)
	if tool != "" {
		path = strings.Split(tool, "/")
	}
	return matchSegments(splitPointer(pattern), path)
}

// matchSegments matches pattern segments against a flat path's segments.
func matchSegments(pattern, path []string) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}
	switch pattern[0] {
	case "**":
		for i := 0; i <= len(path); i++ {
			if matchSegments(pattern[1:], path[i:]) {
				return true
			}
		}
		return false
	default:
		if len(path) == 0 || !segmentMatches(pattern[0], path[0]) {
			return false
		}
		return matchSegments(pattern[1:], path[1:])
	}
}
