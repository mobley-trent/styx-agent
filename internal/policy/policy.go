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
	// ReasonROE is the reason when a rules-of-engagement limit hard-denied
	// the call.
	ReasonROE Reason = "roe"
)

// VerdictResult is a verdict plus its justification. The verdict is the
// decision; the reason is the audit trail (§6.5, §7.5).
type VerdictResult struct {
	Verdict Verdict
	Reason  Reason
}
