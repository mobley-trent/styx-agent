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
// declared and required, and additionalProperties is false).
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
    "args": {
      "type": "object",
      "description": "Free-form arguments passed to the skill's steps."
    }
  },
  "required": ["skill", "reason", "args"],
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
			given, _ := args["args"].(map[string]any)
			return sk.Invocation(given), nil
		},
	}, true
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
