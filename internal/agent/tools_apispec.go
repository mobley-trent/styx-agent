package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/mobley-trent/styx-agent/internal/apispec"
	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// apiSpecSchema is api_spec_load's descriptor (§2.1 of
// docs/api-spec-targets.md): one required `path`, and nothing else. The format
// is sniffed from the document, so there is no format argument for the model to
// guess at and pay a failed call for.
const apiSpecSchema = `{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Workspace-relative path to an OpenAPI, Swagger, or Postman document."
    }
  },
  "required": ["path"],
  "additionalProperties": false
}`

// apiSpecDescription is what the model reads: what a load produces, and the one
// rule that matters — a declaration is checked against the engagement, never
// used to widen it.
const apiSpecDescription = "Load an API declaration (OpenAPI 3.0/3.1, Swagger 2.0, or Postman v2.1) " +
	"from the session workspace into the declared surface. Every server is resolved once and checked " +
	"against the engagement targets: an in-scope server becomes a host tagged `declared`, an out-of-scope " +
	"one is refused by name with the pool it missed. The endpoint inventory is written to " +
	"`.styx/out/api/` — read it with read_file. The receipt carries the counts, auth requirements, and " +
	"refusals; credential values are never returned. A declaration never widens scope: the fix for an " +
	"out-of-scope server is a reviewed line in engagement.yaml."

// APISpecOptions configures the api_spec_load tool.
type APISpecOptions struct {
	// Workspace is the project root the document path is confined to and the
	// inventory artifact is written under.
	Workspace string
	// Store is the engagement-state store the declared hosts are written
	// through.
	Store apispec.Store
	// Scope is the engagement's pinned pool. Nil in safe mode, where the tool
	// is denied; a call there refuses rather than running unchecked.
	Scope apispec.Scope
	// Resolver pins declared hostnames once, at load. Nil means the host
	// resolver.
	Resolver apispec.Resolver
	// Pool is the engagement's targets as declared, for refusal reasons.
	Pool []string
	// Pin records a usable declared server's addresses for the session.
	Pin func(host string, addrs []netip.Addr)
}

// APISpecTool builds the `api_spec_load` tool. Like the parser tools it is
// registered in both modes and gated by the default rule table: safe mode
// denies it (there is no pool to check a declaration against and no store for
// the host), and engagement mode allows it, audited. It carries no scope
// targets of its own — every destination was checked at load
// (docs/api-spec-targets.md §8).
func APISpecTool(opts APISpecOptions) Tool {
	return Tool{
		Name:        apispec.ToolName,
		Description: apiSpecDescription,
		Parameters:  json.RawMessage(apiSpecSchema),
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			path, err := stringArg(args, "path")
			if err != nil {
				return "", err
			}
			abs, err := resolveWithin(opts.Workspace, path)
			if err != nil {
				return "", err
			}
			receipt, err := apispec.Load(ctx, apispec.Request{
				Artifact:  path,
				Path:      abs,
				Workspace: opts.Workspace,
				Store:     opts.Store,
				Scope:     opts.Scope,
				Resolver:  opts.Resolver,
				Pool:      opts.Pool,
				Pin:       opts.Pin,
				Origin:    engagementstate.Origin{Tool: apispec.ToolName, Subagent: subagentOrigin(ctx)},
			})
			if err != nil {
				return "", err
			}
			encoded, err := json.Marshal(receipt)
			if err != nil {
				return "", fmt.Errorf("%s: encode receipt: %w", apispec.ToolName, err)
			}
			return string(encoded), nil
		},
	}
}
