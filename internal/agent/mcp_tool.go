package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mobley-trent/styx-agent/internal/policy"
)

// MCPToolSource is one MCP-provided capability in the shape the agent registry
// needs (§5.5). It is deliberately a plain value, not an SDK type: `agent`
// knows only that an external server contributes a named, schema-described
// tool with a call function, never how the server is reached or launched.
type MCPToolSource struct {
	// Name is the tool's registry name, already namespaced by the MCP client
	// (mcp__<server>__<tool>).
	Name string
	// Description is the server's model-facing description.
	Description string
	// Parameters is the server's input schema as raw JSON. The repair layer
	// validates every call against exactly this schema, regardless of any
	// server-side strictness.
	Parameters json.RawMessage
	// Targets derives the call's network destinations for the policy engine's
	// scope check (§5.5, §7.2). Nil uses the default derivation over the
	// call's arguments; tests and unusual servers may override it.
	Targets func(args map[string]any) []policy.Target
	// Call invokes the tool on its server.
	Call func(ctx context.Context, args map[string]any) (string, error)
}

// MCPTool adapts an MCP-provided capability into an ordinary Tool descriptor
// (§5.5). It is a first-class tool: it passes the same schema validation, the
// same policy gate, and the same audit write as any built-in, and its failures
// — a server-side error, a crash, a disconnect — surface as tool-level results
// the model sees, never as a loop crash.
func MCPTool(src MCPToolSource) Tool {
	schema := src.Parameters
	if len(schema) == 0 {
		schema = json.RawMessage(`{"type":"object","properties":{}}`)
	}
	targets := src.Targets
	if targets == nil {
		// An MCP tool passes the same policy gate as a built-in, scope check
		// included (§5.5). Without this the engine would see no targets and
		// resolve every MCP call through the rule table alone.
		targets = mcpScopeTargets
	}
	return Tool{
		Name:        src.Name,
		Description: src.Description,
		Parameters:  schema,
		// The harness validates MCP arguments itself (§5.5): the provider must
		// not enforce a third-party server's schema, which need not satisfy
		// strict-mode constraints.
		Lenient: true,
		// Targets carries the call's network destinations so the policy engine
		// resolves scope for MCP tools exactly as it does for built-ins.
		Targets: targets,
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			if src.Call == nil {
				return "", errors.New("no MCP transport is configured for " + src.Name)
			}
			out, err := src.Call(ctx, args)
			if err != nil {
				return "", fmt.Errorf("%s: %w", src.Name, err)
			}
			return out, nil
		},
	}
}

// MCPTools adapts a set of MCP-provided capabilities, preserving order.
func MCPTools(sources ...MCPToolSource) []Tool {
	out := make([]Tool, 0, len(sources))
	for _, src := range sources {
		out = append(out, MCPTool(src))
	}
	return out
}
