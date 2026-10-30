package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/attackpath"
)

// AttackPathToolName is the §5.1 tool the roadmap and the parser contracts
// already reserve: the advisory attack-path computation.
const AttackPathToolName = "attack_path_suggest"

// attackPathSchema is the tool's descriptor: one required property and no
// optionals at all (strict mode). K is fixed at 3, not a parameter — there is
// nothing for the model to tune (docs/attack-paths.md §6).
const attackPathSchema = `{
  "type": "object",
  "properties": {
    "target": {
      "type": "string",
      "description": "Entity id, address, or hostname of the host or service to reach, or a finding id to price exploiting it."
    }
  },
  "required": ["target"],
  "additionalProperties": false
}`

// AttackPathTool is the §5.1 `attack_path_suggest` tool: the cheapest costed
// routes from current access to a target, as text.
//
// exploitAllowed reads the engagement's rules of engagement at call time — the
// one policy input the pure computation cannot derive (docs/attack-paths.md
// §7). A nil read, or a refusal, returns positioning routes with the terminal
// exploit step omitted; it never refuses the whole suggestion.
//
// It is advisory by construction (ADR-0006): it reads a snapshot, computes,
// and returns a suggestion. The harness never schedules, pre-authorizes, or
// executes a suggested step; when the model acts on one it does so through the
// ordinary tools, each re-passing the policy gate and scope checks. It carries
// no scope targets — pure local computation, no network — so the default rule
// table denies it in safe mode (there is no store to read) and allows it,
// audited, in engagement mode, exactly like `state_query` (§6.1).
func AttackPathTool(store StateStore, exploitAllowed func() bool) Tool {
	return Tool{
		Name:        AttackPathToolName,
		Description: "Suggest the cheapest costed attack paths from the access currently held to a target host or service, or price the terminal exploit of a finding target, ranked by an integer cost model. Advisory only: it returns suggested routes as text, and the harness never schedules, pre-authorizes, or executes a step of them.",
		Parameters:  json.RawMessage(attackPathSchema),
		Handler: func(_ context.Context, args map[string]any) (string, error) {
			if store == nil {
				return "", errors.New("no engagement state is available: attack_path_suggest needs an active engagement")
			}
			target, err := stringArg(args, "target")
			if err != nil {
				return "", err
			}
			if strings.TrimSpace(target) == "" {
				return "", errors.New("attack_path_suggest: target is required: name a host, service, or finding")
			}
			allowExploit := exploitAllowed != nil && exploitAllowed()
			result, err := attackpath.Compute(store.Snapshot(), target, attackpath.DefaultK,
				attackpath.Options{AllowExploit: allowExploit})
			if err != nil {
				return "", err
			}
			return result.Text(), nil
		},
	}
}
