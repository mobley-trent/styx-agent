package attackpath

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// Fixture builders: the store's read shape, hand-built so the tests exercise
// the pure computation with no store or clock.

func hostEntity(id, address, hostname string) engagementstate.Entity {
	return engagementstate.Entity{ID: id, Kind: engagementstate.KindHost, Active: true, Addresses: []string{address}, Hostname: hostname}
}

func serviceEntity(id, host string, port int) engagementstate.Entity {
	return engagementstate.Entity{
		ID: id, Kind: engagementstate.KindService, Active: true, Host: host,
		Port: port, Proto: engagementstate.ProtoTCP, Product: "smb", State: engagementstate.StateOpen,
	}
}

func credEntity(id, principal, kind string) engagementstate.Entity {
	return engagementstate.Entity{ID: id, Kind: engagementstate.KindCredential, Active: true, Type: kind, Principal: principal}
}

func accessEntity(id, target, level string) engagementstate.Entity {
	return engagementstate.Entity{ID: id, Kind: engagementstate.KindAccess, Active: true, Target: target, Level: level}
}

func findingRecord(id, title string, confidence engagementstate.Confidence, verification engagementstate.Verification, affected ...string) engagementstate.Finding {
	return engagementstate.Finding{
		ID: id, Active: true, Title: title, Confidence: confidence, Verification: verification, Affected: affected,
	}
}

func edgeOf(kind engagementstate.EdgeType, from, to string, confidence engagementstate.Confidence) engagementstate.Edge {
	return engagementstate.Edge{Type: kind, From: from, To: to, Confidence: confidence}
}

// costModelState is the state from docs/attack-paths.md §3 before the exploit
// has run: one foothold, two credentials, and a vulnerable host. Its two
// cheapest routes are 26 (admin via cred-aaaa) and 42 (cred-bbbb).
func costModelState() engagementstate.Snapshot {
	return engagementstate.Snapshot{
		SchemaVersion: engagementstate.SchemaVersion,
		Entities: []engagementstate.Entity{
			hostEntity("host-1111", "10.0.0.11", "jump01"),
			hostEntity("host-2222", "10.0.0.22", "web01"),
			hostEntity("host-3333", "10.0.0.33", "web02"),
			hostEntity("host-4444", "10.0.0.44", "dc01"),
			accessEntity("access-1a2b", "host-1111", engagementstate.LevelUser),
			credEntity("cred-aaaa", `ACME\svc`, engagementstate.CredentialToken),
			credEntity("cred-bbbb", `ACME\bob`, engagementstate.CredentialPassword),
		},
		Findings: []engagementstate.Finding{
			findingRecord("finding-cccc", "SMB signing disabled", engagementstate.ConfidenceMedium,
				engagementstate.VerificationUnverified, "host-3333"),
		},
		Edges: []engagementstate.Edge{
			edgeOf(engagementstate.EdgePivotTo, "access-1a2b", "host-2222", engagementstate.ConfidenceHigh),
			edgeOf(engagementstate.EdgePivotTo, "access-1a2b", "host-3333", engagementstate.ConfidenceHigh),
			edgeOf(engagementstate.EdgeCredentialFrom, "cred-aaaa", "host-2222", engagementstate.ConfidenceHigh),
			edgeOf(engagementstate.EdgeAdminOf, "cred-aaaa", "host-4444", engagementstate.ConfidenceHigh),
			edgeOf(engagementstate.EdgeCredentialFrom, "cred-bbbb", "host-2222", engagementstate.ConfidenceHigh),
			edgeOf(engagementstate.EdgeValidFor, "cred-bbbb", "host-4444", engagementstate.ConfidenceMedium),
		},
	}
}

// exploitedState is costModelState once finding-cccc has produced a foothold
// on the target — the full state of the design doc's worked example.
func exploitedState() engagementstate.Snapshot {
	snapshot := costModelState()
	snapshot.Entities = append(snapshot.Entities, accessEntity("access-9f9f", "host-4444", engagementstate.LevelAdmin))
	snapshot.Edges = append(snapshot.Edges,
		edgeOf(engagementstate.EdgeExploitedVia, "finding-cccc", "access-9f9f", engagementstate.ConfidenceHigh),
		edgeOf(engagementstate.EdgeAdminOf, "access-9f9f", "host-4444", engagementstate.ConfidenceHigh),
		// A user-level route on the same pair must be subsumed by the admin
		// step: privileged routes do not pay twice (§2).
		edgeOf(engagementstate.EdgeValidFor, "cred-aaaa", "host-4444", engagementstate.ConfidenceHigh),
	)
	return snapshot
}

func TestComputeCheapestRoutes(t *testing.T) {
	result, err := Compute(costModelState(), "host-4444", DefaultK)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if result.Outcome != OutcomePaths {
		t.Fatalf("outcome = %q, want paths", result.Outcome)
	}
	wantCosts := []int{26, 42}
	wantLevels := []string{engagementstate.LevelAdmin, engagementstate.LevelUser}
	wantKinds := [][]StepKind{
		{Pivot, HarvestCredential, AdminVia},
		{Pivot, HarvestCredential, UseCredential},
	}
	wantStepCosts := [][]int{{20, 4, 2}, {20, 4, 18}}

	if len(result.Paths) != len(wantCosts) {
		t.Fatalf("paths = %d, want %d: %+v", len(result.Paths), len(wantCosts), result.Paths)
	}
	for i, path := range result.Paths {
		if path.TotalCost != wantCosts[i] {
			t.Errorf("path %d cost = %d, want %d", i+1, path.TotalCost, wantCosts[i])
		}
		if path.Level != wantLevels[i] {
			t.Errorf("path %d level = %q, want %q", i+1, path.Level, wantLevels[i])
		}
		if len(path.Steps) != len(wantKinds[i]) {
			t.Fatalf("path %d has %d steps, want %d", i+1, len(path.Steps), len(wantKinds[i]))
		}
		for j, step := range path.Steps {
			if step.Kind != wantKinds[i][j] {
				t.Errorf("path %d step %d = %q, want %q", i+1, j+1, step.Kind, wantKinds[i][j])
			}
			if step.Cost != wantStepCosts[i][j] {
				t.Errorf("path %d step %d cost = %d, want %d", i+1, j+1, step.Cost, wantStepCosts[i][j])
			}
		}
		if path.TotalCost != sumCosts(path.Steps) {
			t.Errorf("path %d total %d is not the sum of its steps", i+1, path.TotalCost)
		}
	}
	if !strings.Contains(result.Note, "no further distinct routes") {
		t.Errorf("note = %q, want the fewer-than-K caveat", result.Note)
	}

	text := result.Text()
	for _, want := range []string{
		"attack paths to host-4444 (dc01 10.0.0.44): 2 route(s), cheapest first",
		"1. cost 26 · arrives at admin",
		"basis: edge PIVOT_TO access-1a2b → host-2222",
		"basis: edge ADMIN_OF cred-aaaa → host-4444",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text should contain %q:\n%s", want, text)
		}
	}
}

// TestProjectionPinsTheCostModel checks every mechanism's arithmetic from
// docs/attack-paths.md §3, including the exploit's 8 × 3 × 3 × 4 = 288 and its
// verified 8 × 3 × 1 × 4 = 96.
func TestProjectionPinsTheCostModel(t *testing.T) {
	graph, err := project(exploitedState())
	if err != nil {
		t.Fatalf("project() = %v", err)
	}

	cases := []struct {
		from string
		kind StepKind
		to   string
		want int
	}{
		{"access-1a2b", Pivot, "host-2222", 20},
		{"host-2222", HarvestCredential, "cred-aaaa", 4},
		{"cred-aaaa", AdminVia, "host-4444", 2},
		{"cred-bbbb", UseCredential, "host-4444", 18},
		{"host-3333", Exploit, "access-9f9f", 288},
	}
	for _, tc := range cases {
		step, ok := findStep(graph, tc.from, tc.kind, tc.to)
		if !ok {
			t.Errorf("missing %s step %s → %s", tc.kind, tc.from, tc.to)
			continue
		}
		if step.Cost != tc.want {
			t.Errorf("%s %s → %s cost = %d, want %d", tc.kind, tc.from, tc.to, step.Cost, tc.want)
		}
	}
	if _, ok := findStep(graph, "cred-aaaa", UseCredential, "host-4444"); ok {
		t.Error("a credential with ADMIN_OF the target still yields a use_credential step; it must be subsumed")
	}

	verified := exploitedState()
	verified.Findings[0].Verification = engagementstate.VerificationVerified
	verified.Findings[0].Evidence = []engagementstate.Evidence{{Kind: engagementstate.EvidenceCLIOutput, Ref: "cli.txt"}}
	graph, err = project(verified)
	if err != nil {
		t.Fatalf("project(verified) = %v", err)
	}
	step, ok := findStep(graph, "host-3333", Exploit, "access-9f9f")
	if !ok {
		t.Fatal("missing the exploit step of a verified finding")
	}
	if step.Cost != 96 {
		t.Errorf("verified exploit cost = %d, want 96", step.Cost)
	}
}

func TestProjectionExcludesRefutedFindingsAndInactiveNodes(t *testing.T) {
	refuted := exploitedState()
	refuted.Findings[0].Verification = engagementstate.VerificationRefuted
	graph, err := project(refuted)
	if err != nil {
		t.Fatalf("project(refuted) = %v", err)
	}
	if _, ok := findStep(graph, "host-3333", Exploit, "access-9f9f"); ok {
		t.Error("a refuted finding produced an exploit step")
	}

	inactiveHost := exploitedState()
	for i := range inactiveHost.Entities {
		if inactiveHost.Entities[i].ID == "host-3333" {
			inactiveHost.Entities[i].Active = false
		}
	}
	graph, err = project(inactiveHost)
	if err != nil {
		t.Fatalf("project(inactive host) = %v", err)
	}
	if _, ok := findStep(graph, "host-3333", Exploit, "access-9f9f"); ok {
		t.Error("an inactive host produced an exploit step")
	}

	inactiveCred := exploitedState()
	for i := range inactiveCred.Entities {
		if inactiveCred.Entities[i].ID == "cred-bbbb" {
			inactiveCred.Entities[i].Active = false
		}
	}
	graph, err = project(inactiveCred)
	if err != nil {
		t.Fatalf("project(inactive credential) = %v", err)
	}
	for _, step := range graph.adj["cred-bbbb"] {
		t.Errorf("an inactive credential produced a step: %+v", step)
	}
	for _, step := range graph.adj["host-2222"] {
		if step.To.ID == "cred-bbbb" {
			t.Errorf("a step targets an inactive credential: %+v", step)
		}
	}

	attributes := costModelState()
	attributes.Entities = append(attributes.Entities, hostEntity("host-5555", "10.0.0.55", "alias"))
	attributes.Edges = append(attributes.Edges,
		edgeOf(engagementstate.EdgeResolvesTo, "host-5555", "host-4444", engagementstate.ConfidenceHigh),
	)
	graph, err = project(attributes)
	if err != nil {
		t.Fatalf("project(attribute edge) = %v", err)
	}
	for _, step := range graph.adj["host-5555"] {
		t.Errorf("an attribute edge produced a step: %+v", step)
	}
}

// TestComputeExploitDerivedFootholdIsHeld pins the consequence of §4's source
// rule: an access recorded from an exploit is current access, so a write-up
// that treats it as a future foothold (§3's third route) is a planning
// fiction. The target is held, and the zero-step result wins.
func TestComputeExploitDerivedFootholdIsHeld(t *testing.T) {
	result, err := Compute(exploitedState(), "host-4444", DefaultK)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if result.Outcome != OutcomePaths || len(result.Paths) != 1 {
		t.Fatalf("result = %+v, want one zero-step path", result)
	}
	path := result.Paths[0]
	if path.TotalCost != 0 || len(path.Steps) != 0 {
		t.Errorf("path = %+v, want a zero-step path", path)
	}
	if path.Level != engagementstate.LevelAdmin {
		t.Errorf("arrival level = %q, want admin", path.Level)
	}
	if !strings.Contains(result.Text(), "already have access") {
		t.Errorf("text = %q, want the already-held note", result.Text())
	}
}

func TestComputeIsDeterministic(t *testing.T) {
	first, err := Compute(costModelState(), "host-4444", DefaultK)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}

	// The same state in a different insertion order must produce the same
	// output: determinism is what makes golden tests possible (§5).
	shuffled := costModelState()
	slices.Reverse(shuffled.Entities)
	slices.Reverse(shuffled.Findings)
	slices.Reverse(shuffled.Edges)
	second, err := Compute(shuffled, "host-4444", DefaultK)
	if err != nil {
		t.Fatalf("Compute(shuffled) = %v", err)
	}
	if first.Text() != second.Text() {
		t.Errorf("output depends on record order:\n%s\n---\n%s", first.Text(), second.Text())
	}
}

func TestComputeNoFootholds(t *testing.T) {
	snapshot := costModelState()
	for i := range snapshot.Entities {
		if snapshot.Entities[i].Kind == engagementstate.KindAccess {
			snapshot.Entities[i].Active = false
		}
	}
	result, err := Compute(snapshot, "host-4444", DefaultK)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if result.Outcome != OutcomeNoFootholds {
		t.Fatalf("outcome = %q, want no-footholds", result.Outcome)
	}
	if len(result.Paths) != 0 {
		t.Errorf("no-footholds result carries paths: %+v", result.Paths)
	}
	if !strings.Contains(result.Text(), "no active access") {
		t.Errorf("text = %q, want the no-footholds explanation", result.Text())
	}
}

func TestComputeAlreadyHaveAccess(t *testing.T) {
	result, err := Compute(costModelState(), "host-1111", DefaultK)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if result.Outcome != OutcomePaths || len(result.Paths) != 1 {
		t.Fatalf("result = %+v, want one zero-step path", result)
	}
	if got := result.Paths[0]; got.TotalCost != 0 || len(got.Steps) != 0 || got.Level != engagementstate.LevelUser {
		t.Errorf("path = %+v, want a zero-step user-level path", got)
	}
}

func TestComputeTargetResolution(t *testing.T) {
	snapshot := costModelState()
	snapshot.Entities = append(snapshot.Entities, serviceEntity("service-7777", "host-4444", 445))

	for _, target := range []string{"host-4444", "10.0.0.44", "DC01", "dc01.", "service-7777"} {
		t.Run(target, func(t *testing.T) {
			result, err := Compute(snapshot, target, DefaultK)
			if err != nil {
				t.Fatalf("Compute(%q) = %v", target, err)
			}
			if result.Target.ID == "" {
				t.Errorf("Compute(%q) resolved no target", target)
			}
		})
	}

	ambiguous := costModelState()
	ambiguous.Entities = append(ambiguous.Entities,
		hostEntity("host-8888", "10.0.9.9", "shared"),
		hostEntity("host-9999", "10.0.9.9", "shared2"),
	)
	_, err := Compute(ambiguous, "10.0.9.9", DefaultK)
	if !errors.Is(err, ErrTarget) {
		t.Fatalf("Compute(ambiguous address) = %v, want ErrTarget", err)
	}
	for _, id := range []string{"host-8888", "host-9999"} {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("ambiguous error %q should name candidate %s", err, id)
		}
	}

	for _, target := range []string{"10.9.9.9", "nope.example"} {
		if _, err := Compute(snapshot, target, DefaultK); !errors.Is(err, ErrTarget) {
			t.Errorf("Compute(%q) = %v, want ErrTarget", target, err)
		}
	}
	if _, err := Compute(snapshot, "cred-aaaa", DefaultK); !errors.Is(err, ErrTarget) {
		t.Errorf("Compute(credential id) = %v, want ErrTarget", err)
	}
}

func TestComputeUnreachable(t *testing.T) {
	snapshot := costModelState()
	snapshot.Entities = append(snapshot.Entities, hostEntity("host-5555", "10.0.0.55", "isolated"))

	result, err := Compute(snapshot, "host-5555", DefaultK)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if result.Outcome != OutcomeUnreachable {
		t.Fatalf("outcome = %q, want unreachable", result.Outcome)
	}
	if len(result.Paths) != 0 {
		t.Errorf("unreachable result carries paths: %+v", result.Paths)
	}
	if !strings.Contains(result.Text(), "unreachable from current access") {
		t.Errorf("text = %q, want the unreachable diagnostic", result.Text())
	}
	if !strings.Contains(result.Text(), "no node reachable from current access leads toward the target") {
		t.Errorf("text = %q, want the empty-closest explanation", result.Text())
	}
}

// TestComputePathCap makes the cheapest route 14 steps long: beyond the
// 12-step per-path cap, so the outcome is unreachable and the diagnostic names
// the nodes closest to the target.
func TestComputePathCap(t *testing.T) {
	snapshot := engagementstate.Snapshot{SchemaVersion: engagementstate.SchemaVersion}
	snapshot.Entities = append(snapshot.Entities, accessEntity("access-0001", "host-0000", engagementstate.LevelUser))
	const hops = 7
	for i := 0; i < hops; i++ {
		snapshot.Entities = append(snapshot.Entities,
			hostEntity(fmt.Sprintf("host-%04d", i), fmt.Sprintf("10.1.0.%d", i), ""),
			credEntity(fmt.Sprintf("cred-%04d", i), fmt.Sprintf(`DOM\u%d`, i), engagementstate.CredentialPassword))
		snapshot.Edges = append(snapshot.Edges,
			edgeOf(engagementstate.EdgeCredentialFrom, fmt.Sprintf("cred-%04d", i), fmt.Sprintf("host-%04d", i), engagementstate.ConfidenceHigh),
			edgeOf(engagementstate.EdgeValidFor, fmt.Sprintf("cred-%04d", i), fmt.Sprintf("host-%04d", i+1), engagementstate.ConfidenceHigh),
		)
	}
	snapshot.Entities = append(snapshot.Entities, hostEntity(fmt.Sprintf("host-%04d", hops), "10.1.0.7", "far"))
	// A foothold reaches a host through a pivot step; the access node itself
	// is only the cost-0 start.
	snapshot.Edges = append(snapshot.Edges,
		edgeOf(engagementstate.EdgePivotTo, "access-0001", "host-0000", engagementstate.ConfidenceHigh))

	result, err := Compute(snapshot, "host-0007", DefaultK)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if result.Outcome != OutcomeUnreachable {
		t.Fatalf("outcome = %q, want unreachable past the step cap", result.Outcome)
	}
	if !strings.Contains(result.Note, "12-step-per-path cap") {
		t.Errorf("note = %q, want the cap named", result.Note)
	}
	if len(result.Closest) == 0 {
		t.Errorf("closest = none, want the nodes nearest the target")
	} else if !strings.Contains(result.Text(), "closest:") {
		t.Errorf("text = %q, want a closest line", result.Text())
	}
}

func TestComputeCapsRefuse(t *testing.T) {
	tooManyNodes := costModelState()
	for i := 0; i <= MaxNodes; i++ {
		tooManyNodes.Entities = append(tooManyNodes.Entities, hostEntity(fmt.Sprintf("host-%05d", i), "", ""))
	}
	if _, err := Compute(tooManyNodes, "host-4444", DefaultK); !errors.Is(err, ErrCap) {
		t.Errorf("node cap = %v, want ErrCap", err)
	}

	tooManySteps := engagementstate.Snapshot{
		SchemaVersion: engagementstate.SchemaVersion,
		Entities: []engagementstate.Entity{
			accessEntity("access-0001", "host-0001", engagementstate.LevelUser),
			hostEntity("host-0001", "10.2.0.1", ""),
			credEntity("cred-0001", "user", engagementstate.CredentialPassword),
		},
	}
	for i := 0; i <= MaxSteps; i++ {
		tooManySteps.Edges = append(tooManySteps.Edges,
			edgeOf(engagementstate.EdgeValidFor, "cred-0001", "host-0001", engagementstate.ConfidenceHigh))
	}
	if _, err := Compute(tooManySteps, "host-0001", DefaultK); !errors.Is(err, ErrCap) {
		t.Errorf("step cap = %v, want ErrCap", err)
	}
}

func TestComputeRefusesATruncatedSnapshot(t *testing.T) {
	snapshot := costModelState()
	snapshot.Truncated = true
	if _, err := Compute(snapshot, "host-4444", DefaultK); err == nil {
		t.Fatal("Compute(truncated) = nil error, want a refusal")
	}
}

func TestComputeFewerThanKAndLoopless(t *testing.T) {
	snapshot := engagementstate.Snapshot{
		SchemaVersion: engagementstate.SchemaVersion,
		Entities: []engagementstate.Entity{
			accessEntity("access-0001", "host-0001", engagementstate.LevelUser),
			hostEntity("host-0001", "10.3.0.1", "start"),
			hostEntity("host-0002", "10.3.0.2", "next"),
			hostEntity("host-0003", "10.3.0.3", "goal"),
		},
		Edges: []engagementstate.Edge{
			edgeOf(engagementstate.EdgePivotTo, "access-0001", "host-0002", engagementstate.ConfidenceHigh),
			edgeOf(engagementstate.EdgePivotTo, "access-0001", "host-0003", engagementstate.ConfidenceHigh),
		},
	}
	result, err := Compute(snapshot, "host-0003", DefaultK)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if len(result.Paths) != 1 {
		t.Fatalf("paths = %d, want the one route that exists: %+v", len(result.Paths), result.Paths)
	}
	if !strings.Contains(result.Note, "no further distinct routes") {
		t.Errorf("note = %q, want the fewer-than-K caveat", result.Note)
	}
	for _, path := range result.Paths {
		seen := map[string]bool{}
		for _, step := range path.Steps {
			for _, id := range []string{step.From.ID, step.To.ID} {
				if seen[id] {
					t.Errorf("path revisits %s: %+v", id, path.Steps)
				}
				seen[id] = true
			}
		}
	}
}

func TestComputeAddingAStepNeverRaisesAnExistingCost(t *testing.T) {
	before, err := Compute(costModelState(), "host-4444", DefaultK)
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if before.Paths[0].TotalCost != 26 {
		t.Fatalf("baseline cheapest cost = %d, want 26", before.Paths[0].TotalCost)
	}

	more := costModelState()
	more.Entities = append(more.Entities, credEntity("cred-zzzz", `ACME\extra`, engagementstate.CredentialKey))
	more.Edges = append(more.Edges,
		edgeOf(engagementstate.EdgeCredentialFrom, "cred-zzzz", "host-2222", engagementstate.ConfidenceLow),
		edgeOf(engagementstate.EdgeValidFor, "cred-zzzz", "host-4444", engagementstate.ConfidenceLow),
	)
	after, err := Compute(more, "host-4444", DefaultK)
	if err != nil {
		t.Fatalf("Compute(more) = %v", err)
	}
	if len(after.Paths) == 0 || after.Paths[0].TotalCost > before.Paths[0].TotalCost {
		t.Errorf("cheapest cost rose from %d to %+v after adding a step",
			before.Paths[0].TotalCost, after.Paths)
	}
}

// findStep returns the projection's step between two nodes by mechanism.
func findStep(graph *graph, from string, kind StepKind, to string) (Step, bool) {
	for _, step := range graph.adj[from] {
		if step.Kind == kind && step.To.ID == to {
			return step, true
		}
	}
	return Step{}, false
}
