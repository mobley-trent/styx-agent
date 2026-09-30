package policy

import (
	"fmt"
	"time"
)

// Scope decides target membership for the engine. The engagement package
// implements it over the pinned scope set (§7.1); tests supply fakes. It is
// the only hook the engine needs for scope, and it keeps this package pure.
type Scope interface {
	// InScope reports whether the concrete destination is authorized by the
	// active engagement: IP literal, contained CIDR, or pinned hostname/IP.
	InScope(addr string) bool
}

// Engine is the policy decision function's configuration: rule tables, mode,
// scope, ROE, clock. Construct with NewEngine; an Engine is immutable after
// construction and safe for concurrent use.
type Engine struct {
	mode     Mode
	defaults *RuleTable // spec defaults for the mode (§6.1)
	project  []Rule     // project overlay rules (§6.1)
	full     *RuleTable // defaults + project: the safe-mode/no-scope table
	scope    Scope
	roe      *ROE
	now      func() time.Time
}

// Option configures an Engine at construction.
type Option func(*Engine)

// WithScope sets the engagement scope. Nil means no engagement is active.
func WithScope(s Scope) Option { return func(e *Engine) { e.scope = s } }

// WithROE sets the rules-of-engagement limits. Nil means none are active.
func WithROE(r *ROE) Option { return func(e *Engine) { e.roe = r } }

// WithProjectRules sets the project config overlay rules (§6.1). They may
// narrow defaults and widen prompts to allows; they can never weaken ROE
// hard limits or scope checks — the engine enforces that ordering itself.
func WithProjectRules(rules []Rule) Option { return func(e *Engine) { e.project = rules } }

// WithClock sets the clock the engine reads. The injected clock is what makes
// time_window testable (acceptance: "honoring the file's timezone via the
// injected clock"); production passes time.Now.
func WithClock(now func() time.Time) Option { return func(e *Engine) { e.now = now } }

// NewEngine builds an engine for the given mode using the mode's spec
// defaults (§6.1); project overlay rules arrive via WithProjectRules.
func NewEngine(mode Mode, opts ...Option) (*Engine, error) {
	if !mode.Valid() {
		return nil, fmt.Errorf("policy: unknown mode %q", mode)
	}
	e := &Engine{
		mode:     mode,
		defaults: DefaultRules(mode),
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(e)
	}
	e.full = e.defaults.Overlay(e.project)
	return e, nil
}

// Mode reports the engine's operating mode.
func (e *Engine) Mode() Mode { return e.mode }

// Decide resolves one tool call to exactly one verdict (§6.1). It is total:
// every input produces a verdict, never an error. The order below is the
// safety order itself (§6.2):
//
//  1. ROE violation            → deny (hard; never promptable; §6.3)
//  2. engagement, target call:
//     a. project rule denies/prompts → deny/prompt (narrowing; §6.1)
//     b. all targets in scope        → allow (auto-allow, audited; §6.2)
//     c. otherwise                   → prompt (out-of-scope; §6.2)
//  3. otherwise (safe mode, or no engagement scope, or no targets)
//     → rule table (mode defaults + project overlay; §6.1)
//
// Two consequences worth naming:
//   - The mode defaults never veto an in-scope call: they are the baseline
//     engagement scope widens (§6.2). Only project rules narrow.
//   - A project allow never widens a scope check: out-of-scope prompts even
//     under a project allow rule (§6.1).
func (e *Engine) Decide(call Call) VerdictResult {
	// 1. ROE hard limits — standing limits, never negotiable per call (§6.3).
	if err := e.roe.Check(call, e.now()); err != nil {
		return VerdictResult{VerdictDeny, ReasonROE}
	}

	engaged := e.mode == ModeEngagement && e.scope != nil
	if !engaged || len(call.ScopeTargets) == 0 {
		// Not a scope question: resolve through the full rule table (mode
		// defaults + project overlay). Safe mode's floor is prompt.
		return e.full.resolve(call, VerdictPrompt)
	}

	// 2. Engagement mode with targets: project rules may narrow; the mode
	// defaults may not (they are what scope widens).
	if action, matched := matchBest(e.project, call); matched {
		switch action {
		case VerdictDeny:
			return VerdictResult{VerdictDeny, ReasonRuleMatch}
		case VerdictPrompt:
			return VerdictResult{VerdictPrompt, ReasonRuleMatch}
		case VerdictAllow:
			// A project allow cannot weaken a scope check (§6.1): fall
			// through — scope still decides.
		}
	}

	// 3. Scope decides allow vs prompt (§6.2).
	if e.allInScope(call) {
		return VerdictResult{VerdictAllow, ReasonInScope}
	}
	return VerdictResult{VerdictPrompt, ReasonOutOfScope}
}

// allInScope reports whether every concrete target the call intends to touch
// is authorized by the engine's scope. Calls with no targets (pure file
// tools) are not scope questions and pass.
func (e *Engine) allInScope(call Call) bool {
	for _, t := range call.ScopeTargets {
		if !e.scope.InScope(t.Addr) {
			return false
		}
	}
	return true
}

// matchBest resolves a call against an ordered rule slice: the
// highest-precedence action among matching rules (deny > prompt > allow;
// §6.1), or nothing when no rule matches. The one resolver both the rule
// table and the engine's project-rule pass share.
func matchBest(rules []Rule, call Call) (Action, bool) {
	best := -1
	for _, r := range rules {
		if !globMatch(r.Tool, call.Tool) {
			continue
		}
		if !MatchParamGlob(r.ParamPtr, call.Params) {
			continue
		}
		if rank := actionRank(r.Action); rank > best {
			best = rank
		}
	}
	switch best {
	case rankDeny:
		return VerdictDeny, true
	case rankPrompt:
		return VerdictPrompt, true
	case rankAllow:
		return VerdictAllow, true
	default:
		return "", false
	}
}
