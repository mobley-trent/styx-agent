package attackpath

import (
	"fmt"
	"strings"
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
		if r.Note != "" {
			fmt.Fprintf(&b, "  note: %s\n", r.Note)
		}
		return strings.TrimRight(b.String(), "\n")
	}

	fmt.Fprintf(&b, "attack paths to %s: %d route(s), cheapest first\n",
		describeNode(r.Target), len(r.Paths))
	for i, path := range r.Paths {
		fmt.Fprintf(&b, "%d. cost %d", i+1, path.TotalCost)
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
			fmt.Fprintf(&b, "   - %s · %s → %s · confidence=%s", step.Kind,
				describeNode(step.From), describeNode(step.To), step.Confidence)
			if step.Verification != "" {
				fmt.Fprintf(&b, " · verification=%s", step.Verification)
			}
			fmt.Fprintf(&b, " · cost=%d\n", step.Cost)
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

// describeBasis names the stored record a step derives from.
func describeBasis(basis Basis) string {
	if basis.FindingID != "" {
		line := fmt.Sprintf("finding %s %q", basis.FindingID, basis.FindingTitle)
		if basis.Verification != "" {
			line += " (" + string(basis.Verification) + ")"
		}
		return line
	}
	return fmt.Sprintf("edge %s %s → %s", basis.EdgeType, basis.EdgeFrom, basis.EdgeTo)
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
	case Exploit:
		return "one exploit away"
	}
	return "one step away"
}
