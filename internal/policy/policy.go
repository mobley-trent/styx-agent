package policy

// Verdict is the single decision the engine produces for a tool call (§6.1).
type Verdict string

const (
	// VerdictAllow runs the tool call without asking (and is audit-logged).
	VerdictAllow Verdict = "allow"
	// VerdictPrompt requires an inline operator prompt
	// (allow-once / allow-this-session / deny-this-session; §6.4).
	VerdictPrompt Verdict = "prompt"
	// VerdictDeny blocks the call outright.
	VerdictDeny Verdict = "deny"
)

// Reason is why the engine returned its verdict. Reasons are audit-facing
// (§7.5) and stable strings: do not reword them casually.
type Reason string

const (
	// ReasonDefaultTable is the reason when no rule matched: the mode's
	// default verdict applies.
	ReasonDefaultTable Reason = "default-table"
	// ReasonRuleMatch is the reason when a rule table (default or project
	// overlay) matched the call.
	ReasonRuleMatch Reason = "rule-match"
	// ReasonInScope is the reason when engagement is active and every target
	// is in scope: auto-allow.
	ReasonInScope Reason = "in-scope"
	// ReasonOutOfScope is the reason when engagement is active but a target
	// is out of scope: prompt.
	ReasonOutOfScope Reason = "out-of-scope"
	// ReasonDestructive is the reason when an in-scope engagement call is
	// destructive-tagged: prompt, never auto-allow (§8.3: sample detonation is
	// always an explicit operator decision).
	ReasonDestructive Reason = "destructive"
	// ReasonROE is the reason when a rules-of-engagement limit hard-denied
	// the call.
	ReasonROE Reason = "roe"
	// ReasonExploitApproval is the reason when an in-scope, non-destructive
	// exploit-class call is held for the operator because the engagement's
	// exploitation autonomy level is prompt (docs/exploitation-phase.md §2).
	// It is a prompt, never a new verdict.
	ReasonExploitApproval Reason = "exploit-approval"
	// ReasonNoOperator is the reason when a promptable call was resolved with
	// no operator attached: a non-interactive run denies what it cannot ask
	// about, and the audit record says which silence refused it
	// (docs/headless-ci.md §3).
	ReasonNoOperator Reason = "no-operator"
)

// VerdictResult is a verdict plus its justification. The verdict is the
// decision; the reason is the audit trail (§6.5, §7.5).
type VerdictResult struct {
	Verdict Verdict
	Reason  Reason
}
