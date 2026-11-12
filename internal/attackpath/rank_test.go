package attackpath

import (
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// TestRankPricesMatchCompute is the design's central invariant (§11): for every
// finding, a row's positioning, exploit, and total equal the numbers
// attack_path_suggest returns for that same finding id, byte for byte.
func TestRankPricesMatchCompute(t *testing.T) {
	snapshot := costModelState()
	ranking, err := Rank(snapshot, testOptions)
	if err != nil {
		t.Fatalf("Rank() = %v", err)
	}
	if ranking.Outcome != OutcomeCandidates {
		t.Fatalf("outcome = %q, want candidates", ranking.Outcome)
	}
	if len(ranking.Candidates) != 1 {
		t.Fatalf("candidates = %d, want the one eligible finding", len(ranking.Candidates))
	}

	row := ranking.Candidates[0]
	result, err := Compute(snapshot, row.Finding.ID, DefaultK, testOptions)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	path := result.Paths[0]
	if row.Positioning != path.Positioning || row.Exploit != path.Exploit || row.Total != path.TotalCost {
		t.Errorf("rank prices = %d/%d/%d, compute prices = %d/%d/%d",
			row.Positioning, row.Exploit, row.Total, path.Positioning, path.Exploit, path.TotalCost)
	}
	if row.Landing.ID != path.Landing.ID {
		t.Errorf("rank landing = %q, compute landing = %q", row.Landing.ID, path.Landing.ID)
	}
	if row.Level != path.Level {
		t.Errorf("rank level = %q, compute level = %q", row.Level, path.Level)
	}
	if row.Positioning != 20 || row.Exploit != 108 || row.Total != 128 {
		t.Errorf("prices = 20/108/128, want the worked example's 20 · 108 · 128")
	}
}

// TestRankOrdersByTotalThenFindingID pins the order rule: price-only, with the
// finding id breaking ties, so identical state produces byte-identical output.
func TestRankOrdersByTotalThenFindingID(t *testing.T) {
	snapshot := costModelState()
	// The same finding twice over different prices, plus a cheaper one, and a
	// last one whose equal total is broken by id.
	snapshot.Findings = []engagementstate.Finding{
		findingRecord("finding-zzzz", "unverified admin", engagementstate.SeverityHigh,
			engagementstate.ConfidenceHigh, engagementstate.VerificationUnverified, "host-4444"),
		findingRecord("finding-aaaa", "critical but unverified", engagementstate.SeverityCritical,
			engagementstate.ConfidenceHigh, engagementstate.VerificationUnverified, "host-2222"),
		findingRecord("finding-bbbb", "verified admin", engagementstate.SeverityLow,
			engagementstate.ConfidenceHigh, engagementstate.VerificationVerified, "host-2222"),
		findingRecord("finding-cccc", "SMB signing disabled", engagementstate.SeverityMedium,
			engagementstate.ConfidenceMedium, engagementstate.VerificationUnverified, "host-3333"),
	}

	ranking, err := Rank(snapshot, testOptions)
	if err != nil {
		t.Fatalf("Rank() = %v", err)
	}
	if ranking.Eligible != 4 {
		t.Fatalf("eligible = %d, want 4", ranking.Eligible)
	}
	for i := 1; i < len(ranking.Candidates); i++ {
		prev, next := ranking.Candidates[i-1], ranking.Candidates[i]
		if prev.Total > next.Total {
			t.Fatalf("row %d (%d) is dearer than row %d (%d)", i, prev.Total, i+1, next.Total)
		}
		if prev.Total == next.Total && prev.Finding.ID > next.Finding.ID {
			t.Errorf("equal totals (%d) ordered %q before %q; want the id to break the tie",
				prev.Total, prev.Finding.ID, next.Finding.ID)
		}
	}

	// Determinism: the same snapshot ranks identically, and an added unrelated
	// finding never reorders the rows above it.
	again, err := Rank(snapshot, testOptions)
	if err != nil {
		t.Fatalf("Rank() again = %v", err)
	}
	if again.Text() != ranking.Text() {
		t.Errorf("identical state produced different plans:\n%s\n---\n%s", ranking.Text(), again.Text())
	}
	before := make([]string, 0, len(ranking.Candidates))
	for _, row := range ranking.Candidates {
		before = append(before, row.Finding.ID)
	}
	snapshot.Findings = append(snapshot.Findings,
		findingRecord("finding-9999", "unrelated", engagementstate.SeverityInfo,
			engagementstate.ConfidenceHigh, engagementstate.VerificationVerified, "host-2222"))
	after, err := Rank(snapshot, testOptions)
	if err != nil {
		t.Fatalf("Rank() with the extra finding = %v", err)
	}
	// The new finding may be cheaper and rank above them; what it may never do
	// is reorder the rows that were already ranked relative to each other.
	kept := make([]string, 0, len(before))
	for _, row := range after.Candidates {
		for _, id := range before {
			if row.Finding.ID == id {
				kept = append(kept, id)
			}
		}
	}
	if len(kept) != len(before) {
		t.Fatalf("rows after = %v, want every earlier row still ranked", kept)
	}
	for i := range before {
		if kept[i] != before[i] {
			t.Errorf("row %q moved to position %d, want %d", kept[i], i+1, i+1)
		}
	}
}

// TestRankSharesTheEligibilityPredicate asserts a fixed finding is neither
// ranked nor hinted, the one predicate all three consumers share (§11).
func TestRankSharesTheEligibilityPredicate(t *testing.T) {
	snapshot := costModelState()
	snapshot.Findings[0].Status = engagementstate.StatusFixed

	ranking, err := Rank(snapshot, testOptions)
	if err != nil {
		t.Fatalf("Rank() = %v", err)
	}
	if ranking.Outcome != OutcomeNoCandidates {
		t.Fatalf("outcome = %q, want no-candidates for a fixed finding", ranking.Outcome)
	}
	if len(ranking.Candidates) != 0 {
		t.Errorf("candidates = %+v, want none", ranking.Candidates)
	}
	// The hint path must agree: a fixed finding is not exploitable either.
	result, err := Compute(snapshot, "host-4444", DefaultK, testOptions)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	for _, opportunity := range result.Opportunities {
		if opportunity.Finding.ID == "finding-cccc" {
			t.Error("a fixed finding was hinted at as an exploit opportunity")
		}
	}
}

// TestRankOutcomesAreNamed pins every negative branch: no footholds, nothing
// eligible, and eligible-but-unreachable are all named rather than empty.
func TestRankOutcomesAreNamed(t *testing.T) {
	noFootholds := costModelState()
	noFootholds.Entities = nil
	noFootholds.Edges = nil

	unreachable := costModelState()
	unreachable.Findings = []engagementstate.Finding{
		findingRecord("finding-dddd", "isolated segment", engagementstate.SeverityHigh,
			engagementstate.ConfidenceHigh, engagementstate.VerificationVerified, "host-5555"),
	}
	unreachable.Entities = append(unreachable.Entities, hostEntity("host-5555", "10.0.0.55", "isolated"))

	cases := []struct {
		name     string
		snapshot engagementstate.Snapshot
		want     Outcome
		contains string
	}{
		{"no footholds", noFootholds, OutcomeNoFootholds, "no active access"},
		{"nothing eligible", exploitedState(), OutcomeNoCandidates, "no finding in the record is eligible"},
		{"unreachable", unreachable, OutcomeUnreachable, "none reachable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ranking, err := Rank(tc.snapshot, testOptions)
			if err != nil {
				t.Fatalf("Rank() = %v", err)
			}
			if ranking.Outcome != tc.want {
				t.Fatalf("outcome = %q, want %q", ranking.Outcome, tc.want)
			}
			text := ranking.Text()
			if !strings.Contains(text, tc.contains) {
				t.Errorf("text %q should contain %q", text, tc.contains)
			}
		})
	}

	ranking, err := Rank(unreachable, testOptions)
	if err != nil {
		t.Fatalf("Rank() = %v", err)
	}
	if ranking.UnreachableCount != 1 || len(ranking.Unreachable) != 1 {
		t.Fatalf("unreachable = %d named of %d, want 1 of 1", len(ranking.Unreachable), ranking.UnreachableCount)
	}
	if ranking.Unreachable[0].Finding.ID != "finding-dddd" || ranking.Unreachable[0].Node.ID != "host-5555" {
		t.Errorf("unreachable row = %+v, want finding-dddd on host-5555", ranking.Unreachable[0])
	}
}

// TestRankIsLevelIndependent pins that the ranking has no way to observe the
// autonomy level: Options carries policy only, and the same snapshot with
// exploitation refused returns positioning-only rows.
func TestRankIsLevelIndependent(t *testing.T) {
	ranking, err := Rank(costModelState(), Options{})
	if err != nil {
		t.Fatalf("Rank() = %v", err)
	}
	if ranking.ExploitAllowed {
		t.Error("the ranking claims exploitation was permitted")
	}
	if len(ranking.Candidates) != 1 {
		t.Fatalf("candidates = %d, want the positioning-only row", len(ranking.Candidates))
	}
	row := ranking.Candidates[0]
	if row.Exploit != 0 || row.Total != row.Positioning {
		t.Errorf("prices = exploit %d, total %d, want positioning only", row.Exploit, row.Total)
	}
	if !strings.Contains(ranking.Text(), "positioning only") {
		t.Errorf("text %q should name the ROE refusal", ranking.Text())
	}
}

// TestRankCapsCandidates pins MaxCandidates and the truthful tail count.
func TestRankCapsCandidates(t *testing.T) {
	snapshot := costModelState()
	snapshot.Findings = nil
	for _, id := range []string{"finding-0001", "finding-0002", "finding-0003", "finding-0004", "finding-0005", "finding-0006", "finding-0007"} {
		snapshot.Findings = append(snapshot.Findings, findingRecord(id, "finding "+id,
			engagementstate.SeverityHigh, engagementstate.ConfidenceHigh,
			engagementstate.VerificationVerified, "host-2222"))
	}

	ranking, err := Rank(snapshot, testOptions)
	if err != nil {
		t.Fatalf("Rank() = %v", err)
	}
	if ranking.Eligible != 7 {
		t.Errorf("eligible = %d, want 7", ranking.Eligible)
	}
	if len(ranking.Candidates) != MaxCandidates {
		t.Fatalf("candidates = %d, want the %d cap", len(ranking.Candidates), MaxCandidates)
	}
	if !strings.Contains(ranking.Text(), "2 more candidate(s) not ranked") {
		t.Errorf("text %q should name the two candidates the cap left out", ranking.Text())
	}
}
