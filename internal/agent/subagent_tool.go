package agent

import (
	"context"
	"encoding/json"
	"errors"
)

// DispatchSubagentToolName is the built-in delegation tool (§4.2). The policy
// table prompts for it by default: delegation is consequential.
const DispatchSubagentToolName = "dispatch_subagent"

// DispatchRequest is one dispatch_subagent invocation: which role preset to
// run and the task brief handed to it.
type DispatchRequest struct {
	// Role names the role preset the run is constructed from.
	Role string
	// Task is the brief the subagent run works against.
	Task string
}

// Dispatcher runs an isolated-context subagent role and returns its report
// (§4.2). It is the seam that keeps `agent` unaware of how a subagent run is
// built — the role registry and the nested loop live in the subagent package,
// while the loop only sees a tool that returns text.
type Dispatcher interface {
	// Dispatch runs the role against the task and returns the run's final
	// report, which the loop surfaces as the dispatch tool result.
	Dispatch(ctx context.Context, req DispatchRequest) (string, error)
}

// dispatchSubagentSchema is the `dispatch_subagent` descriptor's JSON Schema
// (strict mode: every property is declared and additionalProperties is false).
const dispatchSubagentSchema = `{
  "type": "object",
  "properties": {
    "role": {
      "type": "string",
      "description": "Role preset to run: coder, recon, exploit-dev, or log-triage."
    },
    "task": {
      "type": "string",
      "description": "The task brief the subagent works against, with all context it needs (it starts with an isolated context)."
    }
  },
  "required": ["role", "task"],
  "additionalProperties": false
}`

// DispatchSubagentTool is the §4.2 delegation tool: it runs a role-preset
// subagent and returns its report as an ordinary tool result. The subagent's
// own tool calls pass the same policy engine and surface their permission
// prompts with attribution; it never receives a copy of this tool, so nesting
// is structurally impossible.
func DispatchSubagentTool(dispatcher Dispatcher) Tool {
	return Tool{
		Name:        DispatchSubagentToolName,
		Description: "Dispatch a scoped subagent to work a task in an isolated context and return its report. The subagent cannot delegate further; its tool calls pass the same policy engine.",
		Parameters:  json.RawMessage(dispatchSubagentSchema),
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			role, err := stringArg(args, "role")
			if err != nil {
				return "", err
			}
			task, err := stringArg(args, "task")
			if err != nil {
				return "", err
			}
			if dispatcher == nil {
				return "", errors.New("no subagent dispatcher is configured")
			}
			return dispatcher.Dispatch(ctx, DispatchRequest{Role: role, Task: task})
		},
	}
}
