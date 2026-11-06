package app

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
)

// gatedFindingOps records one high, unverified finding through the typed op
// set, so state — not a fixture file — is what the gate reads.
const gatedFindingOps = `{"ops_json":"[` +
	`{\"op\":\"upsert_finding\",\"title\":\"Weak TLS\",\"severity\":\"high\",\"confidence\":\"medium\"}` +
	`]"}`

// TestHeadlessSeverityGateFails covers §8.5/§8.7: a gated finding at or above
// the threshold fails the run, the one line names the count and the unverified
// share, and the end summary still prints.
func TestHeadlessSeverityGateFails(t *testing.T) {
	dir := t.TempDir()
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "state_update", gatedFindingOps)),
		fakemodel.Text("recorded"),
	))
	var out, errOut strings.Builder
	opts := headlessOptions(t, dir, fake, "find something", &out, &errOut)
	opts.Engagement = engagementFixture
	opts.FailOn = "high"

	err := Run(context.Background(), opts)
	var gate *GateFailure
	if !errors.As(err, &gate) {
		t.Fatalf("Run() = %v, want *GateFailure", err)
	}
	if gate.Threshold != engagementstate.SeverityHigh || gate.Failing != 1 || gate.Unverified != 1 {
		t.Errorf("gate = %+v, want high with 1 failing and 1 unverified", gate)
	}
	if code, ok := VerdictCode(err); !ok || code != 3 {
		t.Errorf("VerdictCode() = %d, %v; want 3, true", code, ok)
	}

	transcript := errOut.String()
	for _, want := range []string{
		"! gate failed: 1 finding at or above high (1 unverified)",
		"styx: done —",
		"styx: session ",
	} {
		if !strings.Contains(transcript, want) {
			t.Errorf("stderr does not contain %q:\n%s", want, transcript)
		}
	}
	if strings.Index(transcript, "! gate failed:") > strings.Index(transcript, "styx: done —") {
		t.Errorf("the gate line should come before the end summary:\n%s", transcript)
	}
	// stdout stays the answer alone, verdict or not (§6.1).
	if got := strings.TrimSpace(out.String()); got != "recorded" {
		t.Errorf("stdout = %q, want the answer alone", out.String())
	}
}

// TestHeadlessSeverityGateThresholdIsInclusive covers §8.4: at-or-above is
// inclusive, so a threshold one step above the finding passes it silently.
func TestHeadlessSeverityGateThresholdIsInclusive(t *testing.T) {
	dir := t.TempDir()
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "state_update", gatedFindingOps)),
		fakemodel.Text("recorded"),
	))
	var out, errOut strings.Builder
	opts := headlessOptions(t, dir, fake, "find something", &out, &errOut)
	opts.Engagement = engagementFixture
	opts.FailOn = "critical"

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() = %v, want a passing gate", err)
	}
	if strings.Contains(errOut.String(), "gate failed") {
		t.Errorf("stderr reports a gate failure below the threshold:\n%s", errOut.String())
	}
}

// TestHeadlessSeverityGatePassesOnEmptyStore covers §8.4's safe-mode case: an
// empty scan is not a finding, so the gate passes.
func TestHeadlessSeverityGatePassesOnEmptyStore(t *testing.T) {
	dir := t.TempDir()
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("nothing found")))
	var out, errOut strings.Builder
	opts := headlessOptions(t, dir, fake, "look around", &out, &errOut)
	opts.FailOn = "info"

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() = %v, want a passing gate on an empty store", err)
	}
	if strings.Contains(errOut.String(), "gate failed") {
		t.Errorf("stderr reports a gate failure for an empty store:\n%s", errOut.String())
	}
}

// TestHeadlessSeverityGateSkipsFailedExport covers §8.5: a failed export write
// is a broken run, and the gate never runs, so no verdict can describe an
// artifact that is not there.
func TestHeadlessSeverityGateSkipsFailedExport(t *testing.T) {
	dir := t.TempDir()
	// A file where the directory should be makes the write impossible.
	writeFile(t, dir, "reports", "not a directory\n")
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "state_update", gatedFindingOps)),
		fakemodel.Text("recorded"),
	))
	var out, errOut strings.Builder
	opts := headlessOptions(t, dir, fake, "find something", &out, &errOut)
	opts.Engagement = engagementFixture
	opts.OutDir = filepath.Join(dir, "reports")
	opts.FailOn = "high"

	err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "findings export") {
		t.Fatalf("Run() = %v, want the export write failure", err)
	}
	if _, ok := VerdictCode(err); ok {
		t.Errorf("a failed export is a broken run, not a verdict: %v", err)
	}
	if strings.Contains(errOut.String(), "! gate failed:") {
		t.Errorf("the gate should not run after a failed export:\n%s", errOut.String())
	}
}
