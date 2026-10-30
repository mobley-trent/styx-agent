package attackpath

import (
	"fmt"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// Text renders a result as text for the model: the routes cheapest first, or
// the named negative outcome with its bounded diagnostic. The tool returns
// text only — a suggestion, never a scheduled step (ADR-0006).
func (r Result) Text() string {
	var b strings.Builder
	switch r.Outcome {
	case OutcomeNoFootholds:
		fmt.Fprintf(&b, "no attack paths: %s is not reachable because the engagement has no active access (foothold) to start from",
			describeNode(r.Target))
		return b.String()
	case OutcomeAlreadyExploited:
		fmt.Fprintf(&b, "already exploited: %s\n  %s\n", describeNode(r.Target), r.Note)
		return strings.TrimRight(b.String(), "\n")
	case OutcomeIneligible:
		fmt.Fprintf(&b, "not exploitable: %s\n  %s\n", describeNode(r.Target), r.Note)
		return strings.TrimRight(b.String(), "\n")
	case OutcomeUnreachable:
		fmt.Fprintf(&b, "unreachable from current access: %s\n", describeNode(r.Target))
		if len(r.Closest) == 0 {
			b.WriteString("  no node reachable from current access leads toward the target")
		} else {
			for _, closest := range r.Closest {
				fmt.Fprintf(&b, "  closest: %s is %s from %s\n",
					describeNode(closest.Node), missingPhrase(closest.Missing), describeNode(r.Target))
			}
		}
		if len(r.Opportunities) > 0 {
			b.WriteString("  exploit opportunities (unrun findings on nodes you can already reach):\n")
			for _, opportunity := range r.Opportunities {
				fmt.Fprintf(&b, "    %s on %s · %s · confidence=%s\n",
					describeNode(opportunity.Finding), describeNode(opportunity.Node),
					opportunity.Verification, opportunity.Confidence)
			}
		}
		if r.Note != "" {
			fmt.Fprintf(&b, "  note: %s\n", r.Note)
		}
		return strings.TrimRight(b.String(), "\n")
	}

	fmt.Fprintf(&b, "attack paths to %s: %d route(s), cheapest first\n",
		describeNode(r.Target), len(r.Paths))
	if r.Finding != nil {
		// Severity, verification, and confidence are labels beside the price,
		// and the exploit's yield is never derived from severity (§3.1).
		fmt.Fprintf(&b, "  finding: severity=%s · verification=%s · confidence=%s · yield=%s\n",
			severityLabel(r.Finding.Severity), r.Finding.Verification, r.Finding.Confidence, ExploitYield)
	}
	for i, path := range r.Paths {
		if r.Finding != nil {
			fmt.Fprintf(&b, "%d. positioning %d", i+1, path.Positioning)
			if r.Finding.ExploitAllowed {
				fmt.Fprintf(&b, " · exploit %d", path.Exploit)
			}
			fmt.Fprintf(&b, " · total %d", path.TotalCost)
			if path.Landing.ID != "" {
				fmt.Fprintf(&b, " · lands on %s", describeNode(path.Landing))
			}
		} else {
			fmt.Fprintf(&b, "%d. cost %d", i+1, path.TotalCost)
		}
		if path.Level != "" {
			fmt.Fprintf(&b, " · arrives at %s", path.Level)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "   route: %s\n", path.Rationale)
		if len(path.Steps) == 0 {
			fmt.Fprintf(&b, "   - no steps needed: %s\n", describeNode(r.Target))
			continue
		}
		for _, step := range path.Steps {
			fmt.Fprintf(&b, "   - %s · %s → %s · confidence=%s · cost=%d\n", step.Kind,
				describeNode(step.From), describeNode(step.To), step.Confidence, step.Cost)
			fmt.Fprintf(&b, "     basis: %s\n", describeBasis(step.Basis))
		}
	}
	if r.Note != "" {
		fmt.Fprintf(&b, "note: %s", r.Note)
	}
	return strings.TrimRight(b.String(), "\n")
}

// describeNode renders a node as its id, with its human label when it has one.
func describeNode(node Node) string {
	if node.Label == "" || node.Label == node.ID {
		return node.ID
	}
	return node.ID + " (" + node.Label + ")"
}

// describeBasis names the stored record a step derives from: an edge, or the
// finding record itself for the terminal exploit step.
func describeBasis(basis Basis) string {
	if basis.Node != "" {
		return "finding " + basis.Node
	}
	return fmt.Sprintf("edge %s %s → %s", basis.EdgeType, basis.EdgeFrom, basis.EdgeTo)
}

// severityLabel renders a severity for the result line, with a name for the
// empty severity an unset record carries: a label is never invented.
func severityLabel(severity engagementstate.Severity) string {
	if severity == "" {
		return "unset"
	}
	return string(severity)
}

// missingPhrase renders the step an unreachable diagnostic says is missing.
func missingPhrase(kind StepKind) string {
	switch kind {
	case HarvestCredential:
		return "one credential away"
	case UseCredential:
		return "one credential use away"
	case AdminVia:
		return "one admin step away"
	case Pivot:
		return "one pivot away"
	}
	return "one step away"
}
