package apispec

import (
	"fmt"
	"sort"
	"strings"
)

// asMap coerces a decoded YAML/JSON node into a string-keyed map. yaml.v3
// decodes mappings with string keys into map[string]any; the map[any]any arm
// covers a document whose keys the decoder could not treat as strings.
func asMap(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = val
		}
		return out
	}
	return nil
}

// asSlice coerces a decoded node into a slice, nil when it is not one.
func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// asString returns a decoded string, empty for any other scalar.
func asString(v any) string {
	s, _ := v.(string)
	return s
}

// asBool returns a decoded bool, false for anything else.
func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

// getString reads a string member.
func getString(m map[string]any, key string) string { return asString(m[key]) }

// getMap reads a map member.
func getMap(m map[string]any, key string) map[string]any { return asMap(m[key]) }

// getSlice reads a sequence member.
func getSlice(m map[string]any, key string) []any { return asSlice(m[key]) }

// strList reads a sequence of strings, dropping non-strings and blanks.
func strList(v any) []string {
	var out []string
	for _, item := range asSlice(v) {
		if s := strings.TrimSpace(asString(item)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// sortedKeys returns a map's keys in stable order, so an extracted document is
// deterministic whatever the decoder's iteration order.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// collapse renders text on one line with runs of whitespace squashed, so a
// document sample does not wreck an error's shape.
func collapse(text string) string {
	return strings.Join(strings.Fields(text), " ")
}
