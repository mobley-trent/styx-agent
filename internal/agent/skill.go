package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/skills"
)

// SkillToolName is the built-in tool through which the model invokes a loaded
// agent skill (§5.1, §8.4). The tool returns the skill's workflow content as
// its result; it grants no tools and widens no policy.
const SkillToolName = "skill"

// skillSchema is the skill tool's descriptor (strict mode: every property is
// declared and required, and additionalProperties is false). Free-form
// arguments are carried as a JSON object string (args_json), not a bare
// object: strict mode rejects an object with no properties, so a free-form
// object has no strict-compliant representation. This is the same encoding
// propose_plan uses for params_json.
const skillSchema = `{
  "type": "object",
  "properties": {
    "skill": {
      "type": "string",
      "description": "Skill name (directory/SKILL.md slug)."
    },
    "reason": {
      "type": "string",
      "description": "Why this skill fits the current task."
    },
    "args_json": {
      "type": "string",
      "description": "A JSON object string of arguments for the skill's steps, e.g. {\"env\":\"prod\"}. Use {} when the skill takes none."
    }
  },
  "required": ["skill", "reason", "args_json"],
  "additionalProperties": false
}`

// SkillTool returns the model-invocable skill tool for a catalog. It reports
// false when no discovered skill is model-invocable: there is nothing for the
// model to invoke, so the tool is not exposed at all. The tool is the only
// model path to a skill, and only to skills whose frontmatter carries
// model-invocation metadata (§8.4).
func SkillTool(catalog *skills.Catalog) (Tool, bool) {
	if catalog == nil {
		return Tool{}, false
	}
	invocable := catalog.ModelInvocable()
	if len(invocable) == 0 {
		return Tool{}, false
	}
	return Tool{
		Name:        SkillToolName,
		Description: skillToolDescription(invocable),
		Parameters:  json.RawMessage(skillSchema),
		Handler: func(_ context.Context, args map[string]any) (string, error) {
			name, err := stringArg(args, "skill")
			if err != nil {
				return "", err
			}
			sk, ok := catalog.Lookup(name)
			if !ok {
				return "", fmt.Errorf("unknown skill %q", name)
			}
			if !sk.ModelInvocation {
				return "", fmt.Errorf("skill %q is user-invoked only; the model may not invoke it", name)
			}
			given, err := skillArgs(args)
			if err != nil {
				return "", err
			}
			return sk.Invocation(given), nil
		},
	}, true
}

// skillArgs decodes the skill tool's free-form arguments. Strict mode cannot
// express a free-form object, so the model passes a JSON object string ({} for
// none); a malformed string is a structured error the repair layer can feed
// back to the model.
func skillArgs(args map[string]any) (map[string]any, error) {
	raw, _ := args["args_json"].(string)
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, fmt.Errorf("args_json is not a JSON object: %w", err)
	}
	return decoded, nil
}

// skillToolDescription names the skills the model may actually invoke, so the
// tool's advertised set can never drift from the catalog's.
func skillToolDescription(invocable []skills.Skill) string {
	var b strings.Builder
	b.WriteString("Invoke a loaded agent skill: its workflow steps are returned as this call's result, to execute with your ordinary tools. A skill grants no tools and widens no policy.\nAvailable skills:")
	for _, sk := range invocable {
		b.WriteString("\n- " + sk.Name)
		if sk.Description != "" {
			b.WriteString(": " + sk.Description)
		}
	}
	return b.String()
}
