package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// PlanToolName is the built-in tool the model calls to propose a multi-step
// plan (§9.2). The loop intercepts it before dispatch: it renders the plan
// block, puts it to the operator, and on approval records turn-scoped
// pre-authorization. Proposal is read-only — it widens nothing by itself.
const PlanToolName = "propose_plan"

const proposePlanSchema = `{
  "type": "object",
  "properties": {
    "summary": {
      "type": "string",
      "description": "One-line description of what the plan accomplishes."
    },
    "steps": {
      "type": "array",
      "description": "The actions to pre-authorize for this turn, in order.",
      "items": {
        "type": "object",
        "properties": {
          "tool": {
            "type": "string",
            "description": "The tool the step calls."
          },
          "params_json": {
            "type": "string",
            "description": "A JSON object of the parameter values the step authorizes, e.g. {\"path\":\"main.go\"}. Use {} to authorize any call to the tool."
          }
        },
        "required": ["tool", "params_json"],
        "additionalProperties": false
      }
    }
  },
  "required": ["summary", "steps"],
  "additionalProperties": false
}`

// ProposePlanTool returns the plan-proposal tool. Its handler is a defensive
// fallback: the loop intercepts propose_plan calls before dispatch, so this
// only runs if the tool is invoked outside a loop.
func ProposePlanTool() Tool {
	return Tool{
		Name:        PlanToolName,
		Description: "Propose a multi-step plan for the current turn. On operator approval the listed actions run without a per-step permission prompt; hard denies, ROE limits, and scope checks still apply. Use this before a multi-step task.",
		Parameters:  json.RawMessage(proposePlanSchema),
		Handler: func(context.Context, map[string]any) (string, error) {
			return "", errors.New("propose_plan is resolved by the agent loop, not dispatched")
		},
	}
}

// parsePlan decodes a propose_plan call's steps into pre-authorization actions.
func parsePlan(params map[string]any) ([]PlanAction, error) {
	raw, ok := params["steps"]
	if !ok {
		return nil, errors.New("a plan requires a steps array")
	}
	steps, ok := raw.([]any)
	if !ok {
		return nil, errors.New("steps must be an array")
	}
	if len(steps) == 0 {
		return nil, errors.New("the plan has no steps")
	}
	out := make([]PlanAction, 0, len(steps))
	for i, step := range steps {
		obj, ok := step.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("step %d must be an object", i+1)
		}
		tool, _ := obj["tool"].(string)
		if tool == "" {
			return nil, fmt.Errorf("step %d: tool is required", i+1)
		}
		var p map[string]any
		if raw, present := obj["params_json"].(string); present && strings.TrimSpace(raw) != "" {
			if err := json.Unmarshal([]byte(raw), &p); err != nil {
				return nil, fmt.Errorf("step %d: params_json is not a JSON object: %w", i+1, err)
			}
		}
		out = append(out, PlanAction{Tool: tool, Params: p})
	}
	return out, nil
}
