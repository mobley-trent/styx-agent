package attackpath

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// testOptions prices the terminal exploit step, the ordinary case: the
// engagement's rules of engagement permit exploitation.
var testOptions = Options{AllowExploit: true}

// TestComputePricesTheTerminalExploit is the worked example in
// docs/attack-paths.md §3.1: finding-cccc is medium and unverified, so the
// exploit is 3 × 3 × 3 × 4 = 108 on top of the 20-cost pivot that positions the
// engagement for it.
func TestComputePricesTheTerminalExploit(t *testing.T) {
	result, err := Compute(costModelState(), "finding-cccc", DefaultK, testOptions)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if result.Outcome != OutcomePaths {
		t.Fatalf("outcome = %q, want paths", result.Outcome)
	}
	if result.Finding == nil || result.Finding.Node.ID != "finding-cccc" {
		t.Fatalf("finding = %+v, want finding-cccc", result.Finding)
	}
	if !result.Finding.ExploitAllowed {
		t.Error("the result says exploitation was refused; the ROE allowed it")
	}
	if len(result.Paths) != 1 {
		t.Fatalf("paths = %+v, want the one positioning route", result.Paths)
	}

	path := result.Paths[0]
	if path.Positioning != 20 || path.Exploit != 108 || path.TotalCost != 128 {
		t.Errorf("prices = positioning %d · exploit %d · total %d, want 20 · 108 · 128",
			path.Positioning, path.Exploit, path.TotalCost)
	}
	if path.TotalCost != path.Positioning+path.Exploit {
		t.Errorf("total %d is not positioning + exploit", path.TotalCost)
	}
	if path.Landing.ID != "host-3333" {
		t.Errorf("landing = %q, want host-3333", path.Landing.ID)
	}
	// The exploit claims no foothold: the arrival level is the positioning
	// route's user-level pivot, and the yield is unknown.
	if path.Level != engagementstate.LevelUser {
		t.Errorf("level = %q, want the positioning route's user level", path.Level)
	}
	last := path.Steps[len(path.Steps)-1]
	if last.Kind != Exploit {
		t.Fatalf("last step = %q, want the terminal exploit", last.Kind)
	}
	if last.Basis.Node != "finding-cccc" || last.Basis.EdgeType != "" {
		t.Errorf("basis = %+v, want the finding record rather than an edge", last.Basis)
	}
	if last.Cost != 108 {
		t.Errorf("exploit step cost = %d, want 108", last.Cost)
	}

	text := result.Text()
	for _, want := range []string{
		"attack paths to finding-cccc (SMB signing disabled)",
		"severity=medium · verification=unverified · confidence=medium · yield=unknown",
		"positioning 20 · exploit 108 · total 128",
		"lands on host-3333 (web02 10.0.0.33)",
		"basis: finding finding-cccc",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text should contain %q:\n%s", want, text)
		}
	}
}

// TestComputeExploitVerificationPricesTheStep pins the one multiplier that
// ranks two findings against each other: a verified exploit is a third of an
// unverified one, and severity never enters the price.
func TestComputeExploitVerificationPricesTheStep(t *testing.T) {
	verified := costModelState()
	verified.Findings[0].Verification = engagementstate.VerificationVerified
	verified.Findings[0].Severity = engagementstate.SeverityCritical

	result, err := Compute(verified, "finding-cccc", DefaultK, testOptions)
	if err != nil {
		t.Fatalf("Compute(verified) = %v", err)
	}
	if got := result.Paths[0].Exploit; got != 36 {
		t.Errorf("verified exploit cost = %d, want 3 × 3 × 1 × 4 = 36", got)
	}
	if !strings.Contains(result.Text(), "severity=critical") {
		t.Errorf("text = %q, want the severity reported as a label", result.Text())
	}
}

// TestComputeEligibility pins §5's one predicate on both surfaces of a finding
// target: a finding that is inactive, closed, or refuted is refused before
// pricing, and an exploited one is named as already run rather than priced.
func TestComputeEligibility(t *testing.T) {
	alreadyExploited := func(s *engagementstate.Snapshot) {
		s.Entities = append(s.Entities, engagementstate.Entity{
			ID: "access-9f9f", Kind: engagementstate.KindAccess, Active: true,
			Target: "host-4444", Level: engagementstate.LevelAdmin, Principal: `ACME\svc`,
		})
		s.Edges = append(s.Edges,
			edgeOf(engagementstate.EdgeExploitedVia, "finding-cccc", "access-9f9f", engagementstate.ConfidenceHigh))
	}

	cases := []struct {
		name   string
		mutate func(*engagementstate.Snapshot)
		want   Outcome
		text   string
	}{
		{
			name:   "inactive",
			mutate: func(s *engagementstate.Snapshot) { s.Findings[0].Active = false },
			want:   OutcomeIneligible,
			text:   "the finding is inactive",
		},
		{
			name:   "false positive",
			mutate: func(s *engagementstate.Snapshot) { s.Findings[0].Status = engagementstate.StatusFalsePositive },
			want:   OutcomeIneligible,
			text:   "false_positive",
		},
		{
			name:   "fixed",
			mutate: func(s *engagementstate.Snapshot) { s.Findings[0].Status = engagementstate.StatusFixed },
			want:   OutcomeIneligible,
			text:   "status is fixed",
		},
		{
			name:   "refuted",
			mutate: func(s *engagementstate.Snapshot) { s.Findings[0].Verification = engagementstate.VerificationRefuted },
			want:   OutcomeIneligible,
			text:   "verification is refuted",
		},
		{
			name:   "already exploited",
			mutate: alreadyExploited,
			want:   OutcomeAlreadyExploited,
			text:   "access-9f9f",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := costModelState()
			tc.mutate(&snapshot)
			result, err := Compute(snapshot, "finding-cccc", DefaultK, testOptions)
			if err != nil {
				t.Fatalf("Compute() = %v", err)
			}
			if result.Outcome != tc.want {
				t.Fatalf("outcome = %q, want %q: %+v", result.Outcome, tc.want, result)
			}
			if len(result.Paths) != 0 {
				t.Errorf("an ineligible finding was still priced: %+v", result.Paths)
			}
			if !strings.Contains(result.Text(), tc.text) {
				t.Errorf("text should contain %q:\n%s", tc.text, result.Text())
			}
			if result.Finding == nil {
				t.Error("the result dropped the finding's labels")
			}
		})
	}
}

// TestComputeFindingTargetRanksEachAffectedNode pins §4's multi-affected rule:
// one route per reachable affected node, ranked together by total cost and
// naming the node each lands on.
func TestComputeFindingTargetRanksEachAffectedNode(t *testing.T) {
	snapshot := costModelState()
	snapshot.Findings[0].Affected = []string{"host-3333", "host-4444", "host-2222", "host-5555"}
	snapshot.Entities = append(snapshot.Entities, hostEntity("host-5555", "10.0.0.55", "isolated"))

	result, err := Compute(snapshot, "finding-cccc", DefaultK, testOptions)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if result.Outcome != OutcomePaths {
		t.Fatalf("outcome = %q, want paths", result.Outcome)
	}
	wantLandings := []string{"host-2222", "host-3333", "host-4444"}
	wantPositioning := []int{20, 20, 26}
	if len(result.Paths) != len(wantLandings) {
		t.Fatalf("paths = %+v, want one per reachable affected node", result.Paths)
	}
	for i, path := range result.Paths {
		if path.Landing.ID != wantLandings[i] {
			t.Errorf("path %d lands on %q, want %q", i+1, path.Landing.ID, wantLandings[i])
		}
		if path.Positioning != wantPositioning[i] {
			t.Errorf("path %d positioning = %d, want %d", i+1, path.Positioning, wantPositioning[i])
		}
		if path.TotalCost != wantPositioning[i]+path.Exploit {
			t.Errorf("path %d total = %d, want positioning + exploit", i+1, path.TotalCost)
		}
	}
	// The unreachable affected node is dropped, never invented.
	if strings.Contains(result.Text(), "host-5555") {
		t.Errorf("an unreachable affected node appears in the routes:\n%s", result.Text())
	}
}

// TestComputeFindingTargetWithoutExploitation pins §8's ROE refusal: the
// positioning answer is still true and useful, so the routes come back with the
// exploit step omitted and a note saying why.
func TestComputeFindingTargetWithoutExploitation(t *testing.T) {
	result, err := Compute(costModelState(), "finding-cccc", DefaultK, Options{})
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if result.Outcome != OutcomePaths {
		t.Fatalf("outcome = %q, want paths", result.Outcome)
	}
	if result.Finding.ExploitAllowed {
		t.Error("the result claims exploitation was permitted")
	}
	path := result.Paths[0]
	if path.Exploit != 0 || path.Positioning != 20 || path.TotalCost != 20 {
		t.Errorf("prices = positioning %d · exploit %d · total %d, want 20 · 0 · 20",
			path.Positioning, path.Exploit, path.TotalCost)
	}
	for _, step := range path.Steps {
		if step.Kind == Exploit {
			t.Errorf("an exploit step was priced despite the ROE refusal: %+v", step)
		}
	}
	text := result.Text()
	if !strings.Contains(text, "exploit_allowed") {
		t.Errorf("text should say the ROE refused exploitation:\n%s", text)
	}
	if strings.Contains(text, "· exploit ") {
		t.Errorf("text should omit the exploit price:\n%s", text)
	}
}

// TestComputeOpportunitiesHonorTheEligibilityPredicate pins the gap #99 closes:
// a finding that is closed or dismissed is neither priced as a target nor
// hinted at as an opportunity, because one predicate decides both.
func TestComputeOpportunitiesHonorTheEligibilityPredicate(t *testing.T) {
	for _, status := range []engagementstate.Status{
		engagementstate.StatusFixed,
		engagementstate.StatusFalsePositive,
	} {
		t.Run(string(status), func(t *testing.T) {
			snapshot := unreachableState()
			snapshot.Findings[0].Status = status

			result, err := Compute(snapshot, "host-5555", DefaultK, Options{})
			if err != nil {
				t.Fatalf("Compute() = %v", err)
			}
			if len(result.Opportunities) != 0 {
				t.Errorf("a %s finding is offered as an opportunity: %+v", status, result.Opportunities)
			}

			target, err := Compute(snapshot, "finding-cccc", DefaultK, testOptions)
			if err != nil {
				t.Fatalf("Compute(finding target) = %v", err)
			}
			if target.Outcome != OutcomeIneligible {
				t.Errorf("a %s finding is still priceable as a target: %+v", status, target)
			}
		})
	}
}

// TestComputeFindingTargetIsDeterministic keeps the finding branch held to §5's
// determinism: the same state in another record order renders identically.
func TestComputeFindingTargetIsDeterministic(t *testing.T) {
	first, err := Compute(costModelState(), "finding-cccc", DefaultK, testOptions)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	shuffled := costModelState()
	slices.Reverse(shuffled.Entities)
	slices.Reverse(shuffled.Findings)
	slices.Reverse(shuffled.Edges)
	second, err := Compute(shuffled, "finding-cccc", DefaultK, testOptions)
	if err != nil {
		t.Fatalf("Compute(shuffled) = %v", err)
	}
	if first.Text() != second.Text() {
		t.Errorf("output depends on record order:\n%s\n---\n%s", first.Text(), second.Text())
	}
}

// TestComputeFindingTargetResolution pins §4's resolution discipline for
// findings: by id, never by title.
func TestComputeFindingTargetResolution(t *testing.T) {
	if _, err := Compute(costModelState(), "SMB signing disabled", DefaultK, testOptions); !errors.Is(err, ErrTarget) {
		t.Errorf("Compute(title) = %v, want ErrTarget: a finding resolves by id only", err)
	}

	// An address or hostname still wins over a finding id, because a finding
	// resolves last in the order.
	snapshot := costModelState()
	snapshot.Entities = append(snapshot.Entities, hostEntity("host-7777", "10.0.0.77", "finding-cccc"))
	result, err := Compute(snapshot, "finding-cccc", DefaultK, testOptions)
	if err != nil {
		t.Fatalf("Compute(finding id as a hostname) = %v", err)
	}
	if result.Finding != nil || result.Target.ID != "host-7777" {
		t.Errorf("target = %+v, want the host whose hostname matches", result.Target)
	}
}
