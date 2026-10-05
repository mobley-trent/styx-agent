package agent

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestBuiltinToolSchemasAreStrictCompliant enforces the provider's strict-mode
// rules for every built-in tool: an object's `required` list must name exactly
// its declared properties, and nested objects are held to the same rule. A
// live run against DeepSeek rejects a schema that violates this, so the
// constraint is pinned here rather than discovered on the wire (§3.3).
func TestBuiltinToolSchemasAreStrictCompliant(t *testing.T) {
	dir := t.TempDir()
	tools := []Tool{
		ReadFileTool(dir),
		WriteFileTool(dir),
		EditFileTool(dir),
		GlobTool(dir),
		GrepTool(dir),
		BashTool(nil),
		CodeExecTool(nil),
		WebFetchTool(nil),
		SSHLogsTool(nil),
		ProposePlanTool(),
	}
	if skillTool, ok := SkillTool(skillCatalog(t, map[string]string{
		"demo": skillDoc("demo", "a demonstration skill", ""),
	})); ok {
		tools = append(tools, skillTool)
	}
	for _, tool := range tools {
		t.Run(tool.Name, func(t *testing.T) {
			var schema map[string]any
			if err := json.Unmarshal(tool.Parameters, &schema); err != nil {
				t.Fatalf("schema is not valid JSON: %v", err)
			}
			checkStrictObject(t, tool.Name, schema)
		})
	}
}

// checkStrictObject walks one schema node, asserting the strict-mode
// required/properties rule on every object and recursing into properties,
// array items, and nested schema fields.
func checkStrictObject(t *testing.T, path string, schema map[string]any) {
	t.Helper()
	props, hasProps := schema["properties"].(map[string]any)
	// The provider rejects a declared object with no properties outright
	// ("An object with no properties is not allowed"), independent of the
	// required/properties match below. A free-form map must be encoded as a
	// JSON string instead.
	if schema["type"] == "object" && (!hasProps || len(props) == 0) {
		t.Errorf("%s: object declares no properties; strict mode rejects it (encode free-form maps as a JSON string)", path)
	}
	if hasProps && len(props) > 0 {
		required, _ := schema["required"].([]any)
		if len(required) != len(props) {
			t.Errorf("%s: %d required entr(ies) for %d properties; strict mode requires them to match", path, len(required), len(props))
		}
		seen := make(map[string]bool, len(required))
		for _, r := range required {
			seen[fmt.Sprint(r)] = true
		}
		for name := range props {
			if !seen[name] {
				t.Errorf("%s: property %q is declared but not required; strict mode requires every property", path, name)
			}
		}
		for name, raw := range props {
			if sub, ok := raw.(map[string]any); ok {
				checkStrictObject(t, path+"."+name, sub)
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		checkStrictObject(t, path+"[]", items)
	}
	for _, key := range []string{"additionalProperties", "allOf", "anyOf", "oneOf"} {
		switch sub := schema[key].(type) {
		case map[string]any:
			checkStrictObject(t, path+"."+key, sub)
		case []any:
			for i, raw := range sub {
				if m, ok := raw.(map[string]any); ok {
					checkStrictObject(t, fmt.Sprintf("%s.%s[%d]", path, key, i), m)
				}
			}
		}
	}
}
