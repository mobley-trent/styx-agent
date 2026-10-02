package policy

import "fmt"

// Action is a rule-table action (§6.1). A matched rule's action is the
// candidate verdict; precedence across matching rules is deny > prompt > allow.
type Action = Verdict

// Rule keys a tool call on tool name plus JSON-pointer parameter globs.
//
// Tool is a tool-name glob: '*' inside a segment matches any run of
// characters ("mcp__*"), '**' spans '/' segments, literals otherwise. An
// empty Tool pattern matches nothing (name the tool or use "*").
//
// ParamPtr is a glob over the JSON-pointer form of a parameter path ("the
// pointer minus its leading '/'", e.g. "command" for bash's command): '*'
// matches one path segment, '**' spans segments, an empty pattern matches
// any parameters. See MatchParamGlob for full semantics.
type Rule struct {
	// Tool pattern ("bash", "web_fetch", "mcp__*", "*").
	Tool string
	// ParamPtr is a glob over the JSON-pointer form of a parameter path
	// ("bash.command" style: the pointer minus its leading '/'). Empty means
	// any parameters.
	ParamPtr string
	// Action when both patterns match.
	Action Action
	// Source labels where the rule came from ("default", "project"); used in
	// diagnostics and tests, never consulted by matching.
	Source string
}

// RuleTable is an ordered collection of rules. Resolution is
// precedence-based (deny > prompt > allow) over all matching rules; rule
// order never affects the outcome.
type RuleTable struct {
	Rules []Rule
}

// Len reports the number of rules in the table.
func (t *RuleTable) Len() int { return len(t.Rules) }

// resolve returns the winning action for a call: the highest-precedence
// action among matching rules (deny > prompt > allow; §6.1), or the table's
// default when nothing matches.
func (t *RuleTable) resolve(call Call, def Action) VerdictResult {
	action, matched := matchBest(t.Rules, call)
	if !matched {
		return VerdictResult{def, ReasonDefaultTable}
	}
	return VerdictResult{action, ReasonRuleMatch}
}

// Precedence ranks: higher wins (deny > prompt > allow; §6.1).
const (
	rankAllow = iota
	rankPrompt
	rankDeny
)

func actionRank(a Action) int {
	switch a {
	case VerdictDeny:
		return rankDeny
	case VerdictPrompt:
		return rankPrompt
	case VerdictAllow:
		return rankAllow
	default:
		return -1
	}
}

// Overlay merges project rules over the table and returns the result
// (§6.1: "project rules may narrow defaults and may widen prompts to
// allows"). A project rule with the same key as a base rule — identical
// tool pattern and param pointer — replaces it ("project wins", the same
// overlay semantics as config); any other project rule is appended. The
// merged table then resolves by plain deny > prompt > allow, so:
//
//   - widen: a project {bash, "", allow} replaces the base {bash, "", prompt};
//   - narrow: a project deny on any key out-ranks everything it matches;
//   - ROE hard limits and scope checks live outside the table and can never
//     be weakened by any rule (§6.1).
func (t *RuleTable) Overlay(project []Rule) *RuleTable {
	merged := append([]Rule(nil), t.Rules...)
	for _, pr := range project {
		replaced := false
		for i, br := range merged {
			if br.Tool == pr.Tool && br.ParamPtr == pr.ParamPtr {
				merged[i] = pr
				replaced = true
				break
			}
		}
		if !replaced {
			merged = append(merged, pr)
		}
	}
	return &RuleTable{Rules: merged}
}

// DefaultRules returns the spec-defined default rule table for a mode (§6.1,
// §6.2). Safe mode: permissive reads, guarded writes/exec/network —
// consequential actions prompt. Engagement mode defaults are intentionally
// identical: engagement widens nothing by itself; only scope matches widen.
func DefaultRules(mode Mode) *RuleTable {
	if mode != ModeSafe && mode != ModeEngagement {
		panic(fmt.Sprintf("policy: unknown mode %q", mode))
	}
	rules := []Rule{
		// Permissive reads.
		{Tool: "read_file", Action: VerdictAllow, Source: "default"},
		{Tool: "glob", Action: VerdictAllow, Source: "default"},
		{Tool: "grep", Action: VerdictAllow, Source: "default"},
		// Guarded writes: prompt by default.
		{Tool: "write_file", Action: VerdictPrompt, Source: "default"},
		{Tool: "edit_file", Action: VerdictPrompt, Source: "default"},
		// Guarded exec/network.
		{Tool: "bash", Action: VerdictPrompt, Source: "default"},
		{Tool: "code_exec", Action: VerdictPrompt, Source: "default"},
		{Tool: "web_fetch", Action: VerdictPrompt, Source: "default"},
		{Tool: "ssh_logs", Action: VerdictPrompt, Source: "default"},
		// Delegation is consequential: prompt.
		{Tool: "dispatch_subagent", Action: VerdictPrompt, Source: "default"},
		// Proposing a plan is read-only: it asks the operator for
		// turn-scoped pre-authorization and widens nothing by itself (§9.2).
		{Tool: "propose_plan", Action: VerdictAllow, Source: "default"},
		// Skill invocation returns workflow text only; widens nothing.
		{Tool: "skill", Action: VerdictAllow, Source: "default"},
	}
	return &RuleTable{Rules: rules}
}
