package policy

import (
	"encoding/json"
	"testing"
)

// decodeParams decodes a JSON object literal into the engine's parameter
// shape, so test tables can spell parameters as JSON.
func decodeParams(t *testing.T, raw string) map[string]any {
	t.Helper()
	p, err := ParseParams(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("ParseParams(%s): %v", raw, err)
	}
	return p
}

func TestMatchParamGlob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		params  string // JSON object literal
		want    bool
	}{
		// Literal paths.
		{name: "exact key", pattern: "command", params: `{"command":"ls"}`, want: true},
		{name: "exact nested path", pattern: "/options/depth", params: `{"options":{"depth":2}}`, want: true},
		{name: "nested path without leading slash", pattern: "options/depth", params: `{"options":{"depth":2}}`, want: true},
		{name: "missing key", pattern: "command", params: `{"url":"http://x"}`, want: false},
		{name: "missing nested key", pattern: "options/depth", params: `{"options":{"verbose":true}}`, want: false},
		{name: "leaf does not match parent", pattern: "command/sub", params: `{"command":"ls"}`, want: false},
		{name: "scalar has no children", pattern: "command/sub", params: `{"command":"ls"}`, want: false},

		// "*" matches exactly one segment.
		{name: "star matches any single key", pattern: "*", params: `{"command":"ls"}`, want: true},
		{name: "star matches nested key", pattern: "options/*", params: `{"options":{"depth":2}}`, want: true},
		{name: "star spans no more than one segment", pattern: "options/*/inner", params: `{"options":{"depth":{"inner":1}}}`, want: true},
		{name: "star does not match deep path directly", pattern: "options/*/inner", params: `{"options":{"a":{"b":{"inner":1}}}}`, want: false},
		{name: "star does not invent absent keys", pattern: "options/*", params: `{"other":{}}`, want: false},
		{name: "star does not match empty object", pattern: "options/*", params: `{"options":{}}`, want: false},

		// "**" spans segments, including zero.
		{name: "doublestar spans depth", pattern: "**/target", params: `{"a":{"b":{"target":"10.0.0.1"}}}`, want: true},
		{name: "doublestar matches zero segments", pattern: "options/**", params: `{"options":{"depth":2}}`, want: true},
		{name: "trailing doublestar matches any depth", pattern: "**", params: `{"a":{"b":1}}`, want: true},
		{name: "doublestar does not invent absent keys", pattern: "**/target", params: `{"a":{"b":"c"}}`, want: false},
		{name: "doublestar at head", pattern: "**/url", params: `{"fetch":{"retry":{"url":"http://x"}}}`, want: true},

		// Arrays: JSON Pointer decimal indices.
		{name: "array index", pattern: "targets/1", params: `{"targets":["a","b"]}`, want: true},
		{name: "array index out of range", pattern: "targets/5", params: `{"targets":["a","b"]}`, want: false},
		{name: "star over array elements", pattern: "targets/*", params: `{"targets":["a"]}`, want: true},
		{name: "star over empty array", pattern: "targets/*", params: `{"targets":[]}`, want: false},
		{name: "doublestar into array element", pattern: "targets/*/host", params: `{"targets":[{"host":"h1"},{"host":"h2"}]}`, want: true},

		// RFC 6901 escapes: ~1 is '/', ~0 is '~'.
		{name: "tilde-one decodes to slash", pattern: "a~1b", params: `{"a/b":"v"}`, want: true},
		{name: "tilde-zero decodes to tilde", pattern: "a~0b", params: `{"a~b":"v"}`, want: true},

		// Empty pattern matches anything.
		{name: "empty pattern matches any params", pattern: "", params: `{"anything":1}`, want: true},
		{name: "empty pattern matches empty params", pattern: "", params: `{}`, want: true},

		// Absent params.
		{name: "pattern does not match absent params", pattern: "command", params: `{}`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchParamGlob(tt.pattern, decodeParams(t, tt.params))
			if got != tt.want {
				t.Errorf("MatchParamGlob(%q, %s) = %v, want %v", tt.pattern, tt.params, got, tt.want)
			}
		})
	}
}

func TestMatchParamGlobTildeZero(t *testing.T) {
	// "~0" decodes to '~' before splitting: "a~0b" matches key "a~b".
	if got := MatchParamGlob("a~0b", map[string]any{"a~b": 1}); !got {
		t.Errorf("MatchParamGlob(a~0b, {a~b:1}) = false, want true")
	}
	// A pattern segment containing a raw '~' is treated literally in the
	// unescaped spelling most rules will use.
	if got := MatchParamGlob("a~b", map[string]any{"a~b": 1}); !got {
		t.Errorf("MatchParamGlob(a~b, {a~b:1}) = false, want true")
	}
}

func TestParseParams(t *testing.T) {
	if p, err := ParseParams(nil); err != nil || len(p) != 0 {
		t.Errorf("ParseParams(nil) = %v, %v; want empty map, nil", p, err)
	}
	if _, err := ParseParams(json.RawMessage(`[1,2]`)); err == nil {
		t.Errorf("ParseParams(array) = nil error; want error (params must be an object)")
	}
	p, err := ParseParams(json.RawMessage(`{"a":1}`))
	if err != nil || p["a"] != float64(1) {
		t.Errorf("ParseParams(object) = %v, %v; want a=1, nil", p, err)
	}
}
