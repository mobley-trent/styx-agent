package app

import (
	"errors"
	"fmt"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
	"github.com/mobley-trent/styx-agent/internal/findingsexport"
)

// GateFailure is a finished run whose severity gate failed
// (docs/headless-ci.md §8.5). It carries the verdict's inputs rather than a
// number: cmd/styx maps it into §8.1's exit-code space, and the runner has
// already printed §8.7's line.
type GateFailure struct {
	// Threshold is the severity --fail-on named.
	Threshold engagementstate.Severity
	// Failing is the number of gated findings at or above Threshold.
	Failing int
	// Unverified is how many of those are unverified (§8.7's disclosure).
	Unverified int
}

// Error renders the §8.7 line, without its `! ` prefix.
func (e *GateFailure) Error() string {
	msg := fmt.Sprintf("gate failed: %d %s at or above %s",
		e.Failing, plural(e.Failing, "finding", "findings"), e.Threshold)
	if e.Unverified > 0 {
		msg += fmt.Sprintf(" (%d unverified)", e.Unverified)
	}
	return msg
}

// NotClean is a finished run that denied at least one prompt with no operator
// attached (§3). The turn succeeded and its answer is on stdout, so it is not a
// broken run: §8.1 gives it its own code.
type NotClean struct {
	// Denied is the number of prompts the run denied no-operator.
	Denied int
}

// Error renders the summary's wording, so the two never disagree.
func (e *NotClean) Error() string {
	return fmt.Sprintf("denied %d %s (run not clean)",
		e.Denied, plural(e.Denied, "prompt", "prompts"))
}

// VerdictCode maps a finished run's error into §8.1's codes when the run
// produced a verdict rather than breaking: a failed gate is 3, and a run that
// denied a prompt with the gate passing is 4. The runner already printed the
// line that explains it (§8.7, §6.3), so the CLI prints nothing further. ok is
// false for every other error, which stays a broken run (1).
func VerdictCode(err error) (code int, ok bool) {
	var gate *GateFailure
	if errors.As(err, &gate) {
		return 3, true
	}
	var notClean *NotClean
	if errors.As(err, &notClean) {
		return 4, true
	}
	return 0, false
}

// evaluateSeverityGate applies --fail-on to the same snapshot the export
// renders, after any export write has succeeded and before teardown (§8.5).
// No threshold means no gate. The one line it prints is §8.7's, and nothing per
// finding: the export is the record.
func (h *Harness) evaluateSeverityGate(printer *headlessPrinter) error {
	if h.failOn == "" {
		return nil
	}
	snapshot, _ := h.findingsSnapshot()
	failing, unverified := findingsexport.GatedFindings(snapshot, h.failOn)
	if failing == 0 {
		return nil
	}
	failure := &GateFailure{Threshold: h.failOn, Failing: failing, Unverified: unverified}
	printer.refusal(failure.Error())
	return failure
}
