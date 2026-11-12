package attackpath

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// MaxCandidates is the most rows a Ranking carries (docs/exploitation-phase.md
// §3). It is fixed, not a parameter: there is nothing for the model to tune,
// and the eligible total rides the result so the tail line stays truthful.
const MaxCandidates = 5

const (
	// OutcomeCandidates is a ranking carrying one or more priced candidate
	// rows, cheapest first.
	OutcomeCandidates Outcome = "candidates"
	// OutcomeNoCandidates is an engagement whose record holds no eligible
	// finding: there is nothing to exploit, and the result names that rather
	// than returning an empty list a reader has to interpret.
	OutcomeNoCandidates Outcome = "no-candidates"
)

// Candidate is one eligible finding and its best route: the cheapest of its
// positioning routes across affected nodes, ending in the terminal exploit
// step when the rules of engagement permit it. Its prices are the numbers
// attack_path_suggest returns for the same finding id, byte for byte.
type Candidate struct {
	// Finding is the finding record the route would exploit.
	Finding Node
	// Severity is a label, never a price (§3.1).
	Severity engagementstate.Severity
	// Verification and Confidence are the finding's own labels.
	Verification engagementstate.Verification
	Confidence   engagementstate.Confidence
	// Landing is the affected host or service the exploit would run against.
	Landing Node
	// Positioning, Exploit, and Total are the route's prices. Exploit is zero
	// when the rules of engagement refuse exploitation (§8).
	Positioning int
	Exploit     int
	Total       int
	// Level is the positioning route's arrival level. An exploit's own yield is
	// never claimed (§3.1).
	Level string
}

// UnreachableCandidate names one eligible finding no route reaches, with the
// bounded "closest we got" line the unreachable diagnostic already produces.
// "You cannot get there yet" is information; an omission is not.
type UnreachableCandidate struct {
	// Finding is the eligible finding that could not be ranked.
	Finding Node
	// Node is the affected node the engagement cannot reach.
	Node Node
	// Closest is the nearest reachable node and the mechanism missing from it.
	// The zero value means no reachable node leads toward the target at all.
	Closest Closest
}

// Ranking is Rank's answer: a named outcome, at most MaxCandidates priced rows,
// the eligible total, and up to three named unreachable findings.
//
// It is advisory text (ADR-0006): nothing here is scheduled, pre-authorized, or
// pinned as the next step. Acting on a row means calling the ordinary tools,
// each re-passing the policy gate and the scope checks independently.
type Ranking struct {
	// Outcome names the result's shape.
	Outcome Outcome
	// Candidates are the priced rows, cheapest first, at most MaxCandidates.
	Candidates []Candidate
	// Eligible is every eligible finding in the record, ranked or not.
	Eligible int
	// Unreachable names up to three unreachable findings; UnreachableCount is
	// all of them.
	Unreachable      []UnreachableCandidate
	UnreachableCount int
	// ExploitAllowed reports whether the rules of engagement permitted the
	// exploit step to be priced. When false, rows are positioning only.
	ExploitAllowed bool
	// Note is an ordinary caveat: the ROE refusal, or a truncated search.
	Note string
}

// Rank answers the engagement's exploitation candidates: one row per eligible
// finding, its cheapest positioned route, ordered by (total, finding id)
// (docs/exploitation-phase.md §3).
//
// It re-prices nothing. Each finding is run through the same finding-target
// computation Compute uses, so a row's positioning, exploit, and total are the
// numbers attack_path_suggest returns for that finding. Options carries the
// only policy input, exactly as for Compute: the autonomy level is not one of
// them, so the ranking is level-independent by construction.
func Rank(snapshot engagementstate.Snapshot, opts Options) (Ranking, error) {
	if snapshot.Truncated {
		return Ranking{}, errors.New("attackpath: the state snapshot is truncated; an exploitation plan needs the full record")
	}
	graph, err := project(snapshot)
	if err != nil {
		return Ranking{}, err
	}

	sources := make([]string, 0)
	for _, e := range snapshot.Entities {
		if e.Kind == engagementstate.KindAccess && e.Active {
			sources = append(sources, e.ID)
		}
	}
	sort.Strings(sources)
	if len(sources) == 0 {
		return Ranking{Outcome: OutcomeNoFootholds}, nil
	}

	// One eligibility predicate, shared: a finding can never be priced, hinted
	// at, and ranked under different rules (§5 of docs/attack-paths.md).
	exploited := exploitedFindings(snapshot)
	findings := make([]engagementstate.Finding, 0, len(snapshot.Findings))
	for _, finding := range snapshot.Findings {
		if exploitable(finding, exploited) {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	if len(findings) == 0 {
		return Ranking{Outcome: OutcomeNoCandidates}, nil
	}

	ranking := Ranking{Eligible: len(findings), ExploitAllowed: opts.AllowExploit}
	if !opts.AllowExploit {
		ranking.Note = "the rules of engagement do not permit exploitation (exploit_allowed: false): positioning only, the exploit step is omitted"
	}

	for _, finding := range findings {
		finding := finding
		result := graph.findingTarget(snapshot, sources,
			targetRef{node: graph.nodes[finding.ID], finding: &finding}, opts)
		if result.Outcome == OutcomeUnreachable && strings.Contains(result.Note, "truncated") {
			ranking.Note = lengthCapNote(true, ranking.Note)
		}
		switch result.Outcome {
		case OutcomePaths:
			best := result.Paths[0]
			ranking.Candidates = append(ranking.Candidates, Candidate{
				Finding:      graph.nodes[finding.ID],
				Severity:     finding.Severity,
				Verification: defaultVerification(finding.Verification),
				Confidence:   defaultConfidence(finding.Confidence),
				Landing:      best.Landing,
				Positioning:  best.Positioning,
				Exploit:      best.Exploit,
				Total:        best.TotalCost,
				Level:        best.Level,
			})
		case OutcomeUnreachable:
			ranking.UnreachableCount++
			if len(ranking.Unreachable) < 3 {
				ranking.Unreachable = append(ranking.Unreachable, graph.unreachableCandidate(sources, finding))
			}
		}
	}

	// Order is (total, finding id): price-only, so identical state produces
	// byte-identical output and adding an unrelated finding never reorders the
	// rows above it.
	sort.SliceStable(ranking.Candidates, func(i, j int) bool {
		if ranking.Candidates[i].Total != ranking.Candidates[j].Total {
			return ranking.Candidates[i].Total < ranking.Candidates[j].Total
		}
		return ranking.Candidates[i].Finding.ID < ranking.Candidates[j].Finding.ID
	})
	if len(ranking.Candidates) > MaxCandidates {
		ranking.Candidates = ranking.Candidates[:MaxCandidates]
	}

	ranking.Outcome = OutcomeCandidates
	if len(ranking.Candidates) == 0 {
		ranking.Outcome = OutcomeUnreachable
	}
	return ranking, nil
}

// unreachableCandidate builds one named unreachable finding: the affected node
// the engagement cannot reach, plus the nearest reachable node and the
// mechanism missing from it.
func (g *graph) unreachableCandidate(sources []string, finding engagementstate.Finding) UnreachableCandidate {
	out := UnreachableCandidate{Finding: g.nodes[finding.ID]}
	for _, affected := range g.affectedNodes(finding) {
		if out.Node.ID == "" {
			out.Node = g.nodes[affected]
		}
		if closest := g.closest(sources, affected); len(closest) > 0 {
			out.Node = g.nodes[affected]
			out.Closest = closest[0]
			return out
		}
	}
	return out
}

// Text renders a ranking as text for the model: the priced rows cheapest first,
// or the named negative outcome with its diagnostics. It is advice only — the
// harness never pins the first row, queues it, or pre-authorizes it (ADR-0006).
func (r Ranking) Text() string {
	var b strings.Builder
	switch r.Outcome {
	case OutcomeNoFootholds:
		return "no exploitation candidates: the engagement has no active access (foothold) to start from"
	case OutcomeNoCandidates:
		return "no exploitation candidates: no finding in the record is eligible for exploitation"
	case OutcomeUnreachable:
		fmt.Fprintf(&b, "exploitation plan: %d eligible finding(s), none reachable from current access\n",
			r.Eligible)
		for _, candidate := range r.Unreachable {
			fmt.Fprintf(&b, "  unreachable: %s on %s%s\n",
				describeNode(candidate.Finding), describeNode(candidate.Node), closestPhrase(candidate.Closest))
		}
		if r.Note != "" {
			fmt.Fprintf(&b, "  note: %s\n", r.Note)
		}
		return strings.TrimRight(b.String(), "\n")
	}

	fmt.Fprintf(&b, "exploitation plan: %d eligible finding(s), %d ranked by positioning + exploit, cheapest first\n",
		r.Eligible, len(r.Candidates))
	for i, candidate := range r.Candidates {
		fmt.Fprintf(&b, "%d. %s  %s · %s · confidence=%s  on %s  positioning %d",
			i+1, describeNode(candidate.Finding), severityLabel(candidate.Severity),
			candidate.Verification, candidate.Confidence, describeNode(candidate.Landing), candidate.Positioning)
		if r.ExploitAllowed {
			fmt.Fprintf(&b, " · exploit %d", candidate.Exploit)
		}
		fmt.Fprintf(&b, " · total %d\n", candidate.Total)
		fmt.Fprintf(&b, "   %s · yield %s\n", arrivalPhrase(candidate), ExploitYield)
	}
	if omitted := r.Eligible - len(r.Candidates) - r.UnreachableCount; omitted > 0 {
		fmt.Fprintf(&b, "%d more candidate(s) not ranked: the plan shows at most %d\n", omitted, MaxCandidates)
	}
	if r.UnreachableCount > 0 {
		fmt.Fprintf(&b, "%d eligible finding(s) are unreachable from current access:\n", r.UnreachableCount)
		for _, candidate := range r.Unreachable {
			fmt.Fprintf(&b, "  unreachable: %s on %s%s\n",
				describeNode(candidate.Finding), describeNode(candidate.Node), closestPhrase(candidate.Closest))
		}
	}
	if r.Note != "" {
		fmt.Fprintf(&b, "note: %s\n", r.Note)
	}
	return strings.TrimRight(b.String(), "\n")
}

// arrivalPhrase renders where a candidate's positioning route lands: a held
// node positions for free, and an exploit claims no level of its own.
func arrivalPhrase(candidate Candidate) string {
	// A held node positions for free, so the exploit is what is left to do
	// there — the design's own line for a zero-cost row.
	if candidate.Positioning == 0 {
		return "already held"
	}
	if candidate.Level == "" {
		return "no arrival level claimed"
	}
	return "arrive " + candidate.Level
}

// closestPhrase renders an unreachable candidate's bounded diagnostic, or says
// plainly that nothing reachable leads toward it.
func closestPhrase(closest Closest) string {
	if closest.Node.ID == "" {
		return ": no node reachable from current access leads toward it"
	}
	return fmt.Sprintf(": closest is %s, %s", describeNode(closest.Node), missingPhrase(closest.Missing))
}
