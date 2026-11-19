package app

import (
	"fmt"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/diffscope"
)

// ScopeModeDiff is the only --scope-mode this build accepts: a run narrowed to
// the targets the change declares (docs/headless-ci.md §11.2). Any other value
// is a usage error, never a silently ignored flag.
const ScopeModeDiff = "diff"

// checkScopeOptions validates the diff-scope flags. They are CI-shaped
// (docs/headless-ci.md §2.2): without -n they are usage errors, because the
// operator believes a run is scoped while a human is still at the prompt. The
// mode needs an engagement to narrow — with no engagement file there is no pool
// to intersect — and an explicit base, because a guessed base draws
// authorization from a branch nobody named.
func checkScopeOptions(opts Options) error {
	mode := strings.TrimSpace(opts.ScopeMode)
	base := strings.TrimSpace(opts.DiffBase)
	nonInteractive := opts.NonInteractive

	if base != "" && !nonInteractive {
		return UsageError{Message: "styx: --diff-base needs a non-interactive run (-n)"}
	}
	if mode == "" {
		if base != "" {
			return UsageError{Message: "styx: --diff-base needs --scope-mode diff"}
		}
		return nil
	}
	if mode != ScopeModeDiff {
		return UsageError{Message: fmt.Sprintf("styx: --scope-mode %q: want diff", mode)}
	}
	if !nonInteractive {
		return UsageError{Message: "styx: --scope-mode needs a non-interactive run (-n)"}
	}
	if strings.TrimSpace(opts.Engagement) == "" {
		return UsageError{Message: "styx: --scope-mode diff needs --engagement: with no engagement file there is no scope to narrow to"}
	}
	if base == "" {
		return UsageError{Message: "styx: --scope-mode diff needs --diff-base <ref>"}
	}
	return nil
}

// auditDiffScope records the effective pool a diff-scoped run narrowed to
// (docs/headless-ci.md §11.2): the base ref and its commit, the targets kept,
// the documents that declared them, and what contributed nothing. A scope
// narrower than the operator believes is the failure the record exists to
// prevent, so an unlogged narrowing refuses the run.
func (h *Harness) auditDiffScope(result diffscope.Result) error {
	if h.audit == nil {
		return nil
	}
	targets := result.TargetNames()
	if targets == nil {
		targets = []string{}
	}
	documents := result.Documents
	if documents == nil {
		documents = []string{}
	}
	notes := result.Notes
	if notes == nil {
		notes = []string{}
	}
	return h.audit.Append(audit.Record{
		Mode: audit.ModeEngagement,
		Tool: "diff_scope",
		Params: map[string]any{
			"base":        result.Base,
			"base_commit": result.BaseCommit,
			"targets":     targets,
			"documents":   documents,
			"notes":       notes,
		},
		Verdict: audit.VerdictAllow,
		Reason:  "diff-scope",
	})
}
