package mcpclient

import (
	"encoding/json"
	"testing"
)

// TestNormalizeSchemaDefaults pins the fail-safe behavior: a server that
// advertises no schema, or an unparseable one, gets the empty object schema
// rather than an unvalidated tool.
func TestNormalizeSchemaDefaults(t *testing.T) {
	for _, in := range []any{nil, "not a schema", []string{"x"}} {
		got := normalizeSchema(in)
		var obj map[string]any
		if err := json.Unmarshal(got, &obj); err != nil {
			t.Fatalf("normalizeSchema(%v) = %q, not a JSON object", in, got)
		}
		if obj["type"] != "object" {
			t.Errorf("normalizeSchema(%v) type = %v, want object", in, obj["type"])
		}
	}
}
