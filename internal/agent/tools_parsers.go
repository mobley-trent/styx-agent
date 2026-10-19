package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
	"github.com/mobley-trent/styx-agent/internal/parsers"
)

// parserSchema is every parser tool's descriptor (§2 of
// docs/parser-tool-contracts.md): one required `path`, and nothing else. There
// is no disambiguator — the target, scanner, and port are all inferred from the
// artifact — and no inline form, because scanner output is large and the
// artifact must survive as the evidence ref anyway.
const parserSchema = `{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Workspace-relative path to the raw tool output to parse."
    }
  },
  "required": ["path"],
  "additionalProperties": false
}`

// parserDescriptions is what the model reads for each parser: which scanner's
// output it takes and what it records.
var parserDescriptions = map[string]string{
	parsers.NmapParse: "Parse nmap XML output (`nmap -oX`, e.g. `.styx/out/nmap-10.0.0.0_24.xml`) into engagement state: " +
		"the hosts it found, their open ports as services, and the scanned range as a segment. Ports are facts, not vulnerabilities, so this writes no findings.",
	parsers.NucleiParse: "Parse nuclei JSON Lines output (`nuclei -jsonl`) into engagement state: " +
		"the matched hosts and services, and one finding per template match with its request/response excerpt as evidence.",
	parsers.SQLMapParse: "Parse a sqlmap log into engagement state: " +
		"one finding per injectable parameter, the password hashes it dumped as credentials, and the database-admin foothold it proves.",
	parsers.GobusterParse: "Parse gobuster output (dir, dns, or vhost mode) into engagement state: " +
		"the target's host and service, the names it discovered, and one finding per host carrying the discovered-path list as evidence.",
	parsers.CMEParse: "Parse CrackMapExec or NetExec output into engagement state: " +
		"the hosts and services it touched, the credentials that worked, the footholds they gave, and its positive module results as findings.",
	parsers.BloodHoundParse: "Parse legacy BloodHound collector JSON (users/computers/groups/domains) into engagement state: " +
		"the computers as hosts, and their sessions and local administrators as footholds.",
}

// parserDescriptionSuffix is appended to every parser description: the two
// things a caller must know about a parser's write.
const parserDescriptionSuffix = " The harness reads the artifact and writes engagement state itself, in one atomic batch, and returns a receipt of what it recorded and what it skipped."

// ParserTools builds the six parser tools (§5.1 of docs/parser-tool-contracts.md),
// in the contract's order. They are registered in both modes, like the state
// tools: the default rule table denies them in safe mode — there is no store to
// write — and allows them, audited, in engagement mode.
//
// A parser's call is `path` only: the model never supplies an op, a target, or
// provenance. Everything a parse writes is harness-derived, which is what makes
// "scanner output reaches state only through its parser" a structural fact
// rather than a rule the model could ignore.
func ParserTools(workspace string, store parsers.Store, tracker *parsers.Tracker) []Tool {
	tools := make([]Tool, 0, len(parsers.Names()))
	for _, name := range parsers.Names() {
		tools = append(tools, parserTool(workspace, name, store, tracker))
	}
	return tools
}

// parserTool builds one parser tool over a store and the engagement's
// pending-parse tracker.
func parserTool(workspace, name string, store parsers.Store, tracker *parsers.Tracker) Tool {
	description := parserDescriptions[name] + parserDescriptionSuffix
	return Tool{
		Name:        name,
		Description: description,
		Parameters:  []byte(parserSchema),
		// Parsing is pure computation over a workspace file: no network, no
		// targets, and nothing destructive. It still rides the normative order
		// (schema validation → verdict → audit → dispatch) like every tool.
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			path, err := stringArg(args, "path")
			if err != nil {
				return "", err
			}
			abs, err := resolveWithin(workspace, path)
			if err != nil {
				return "", err
			}
			receipt, err := parsers.Run(ctx, parsers.Request{
				Tool:     name,
				Artifact: path,
				Path:     abs,
				Store:    store,
				Origin:   engagementstate.Origin{Tool: name, Subagent: subagentOrigin(ctx)},
				Tracker:  tracker,
			})
			if err != nil {
				return "", err
			}
			encoded, err := json.Marshal(receipt)
			if err != nil {
				return "", fmt.Errorf("%s: encode receipt: %w", name, err)
			}
			return string(encoded), nil
		},
	}
}
