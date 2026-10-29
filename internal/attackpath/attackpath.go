package attackpath

import (
	"container/heap"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// DefaultK is the number of distinct routes Compute returns (docs/attack-paths.md
// §5). It is fixed at the roadmap's K = 3 and is not a tool parameter: there is
// nothing for the model to tune.
const DefaultK = 3

// Bounds (docs/attack-paths.md §5). v1 engagements are small; the caps exist so
// a pathological graph cannot wedge the harness. Exceeding a node or step cap
// refuses the computation with a message naming the cap; the per-path cap
// truncates the search and is reported on the result.
const (
	// MaxNodes is the largest relationship graph the computation reasons over.
	MaxNodes = 5000
	// MaxSteps is the largest capability projection the computation builds.
	MaxSteps = 20000
	// MaxPathSteps is the largest number of steps one route may contain.
	MaxPathSteps = 12
)

// Refusals. Every rejection wraps one of these, so callers branch on the kind
// of refusal rather than on message text.
var (
	// ErrTarget is a target that resolves to nothing, or that resolves
	// ambiguously. It is never guessed.
	ErrTarget = errors.New("attackpath: target")
	// ErrCap is a refusal because the graph exceeds a bound.
	ErrCap = errors.New("attackpath: cap exceeded")
)

// StepKind is one capability step's mechanism (docs/attack-paths.md §2). The
// set is closed: a new mechanism is a design-doc change.
type StepKind string

// The capability step set, one per traversable stored edge type.
const (
	// HarvestCredential is CREDENTIAL_FROM reversed: reaching the node the
	// secret came from makes the secret obtainable.
	HarvestCredential StepKind = "harvest_credential"
	// UseCredential is VALID_FOR: the secret authenticates as a user-level
	// principal.
	//
	//nolint:gosec // the value names a capability step, not credential material.
	UseCredential StepKind = "use_credential"
	// AdminVia is ADMIN_OF: privileged over the target.
	AdminVia StepKind = "admin_via"
	// Pivot is PIVOT_TO: this foothold reaches that host.
	Pivot StepKind = "pivot"
)

// The step set carries no exploit mechanism. A finding's EXPLOITED_VIA edge is
// retrospective — it records the foothold an exploit already produced, which is
// an active access and therefore a cost-0 source (docs/attack-paths.md §2).
// Unexploited findings reach the model as opportunities beside an unreachable
// result, never as priced steps.

// Outcome is a result's shape. Every branch is named: the computation never
// returns an empty result to mean "nothing".
type Outcome string

const (
	// OutcomePaths is a result carrying one or more routes.
	OutcomePaths Outcome = "paths"
	// OutcomeNoFootholds is an engagement with no active access: there is no
	// start, so no route is invented.
	OutcomeNoFootholds Outcome = "no-footholds"
	// OutcomeUnreachable is a structured negative result: no route leads to
	// the target from the access currently held.
	OutcomeUnreachable Outcome = "unreachable"
)

// Node is one graph node, identified by its harness id and labelled for the
// reader.
type Node struct {
	// ID is the entity or finding id.
	ID string
	// Kind is the entity kind, or "finding".
	Kind engagementstate.Kind
	// Label is a short human label derived from the record.
	Label string
}

// Basis names the stored edge a step derives from (docs/attack-paths.md §5).
type Basis struct {
	// EdgeType, EdgeFrom, and EdgeTo identify the stored edge.
	EdgeType engagementstate.EdgeType
	EdgeFrom string
	EdgeTo   string
}

// Step is one capability step in a route.
type Step struct {
	// From and To are the step's endpoints.
	From Node
	To   Node
	// Kind is the mechanism.
	Kind StepKind
	// Confidence is the stored edge's confidence.
	Confidence engagementstate.Confidence
	// Cost is the integer price of the step (docs/attack-paths.md §3).
	Cost int
	// Basis is the stored record the step derives from.
	Basis Basis
}

// Path is one suggested route, cheapest first in a Result.
type Path struct {
	// TotalCost is the sum of the steps' costs.
	TotalCost int
	// Level is the arrival level: the privilege the final step lands at.
	Level string
	// Rationale is the one-line mechanism summary.
	Rationale string
	// Steps are the ordered capability steps.
	Steps []Step
}

// Opportunity is one unexploited finding on a node current access can already
// reach: a hint beside an unreachable result, never a priced step
// (docs/attack-paths.md §5).
type Opportunity struct {
	// Finding is the unexploited finding.
	Finding Node
	// Node is the finding's affected host or service, reachable from current
	// access.
	Node Node
	// Confidence is the finding's confidence.
	Confidence engagementstate.Confidence
	// Verification is the finding's verification state.
	Verification engagementstate.Verification
}

// Closest is one bounded diagnostic line for an unreachable target: a node
// reachable from current access that has a route toward the target, and the
// mechanism of the step it is missing.
type Closest struct {
	// Node is the reachable node.
	Node Node
	// Missing is the mechanism of the futhest-reaching step from it.
	Missing StepKind
	// Distance is that route's cost.
	Distance int
}

// Result is Compute's answer: a named outcome, the resolved target, and
// whichever of routes, diagnostics, or a note applies.
type Result struct {
	// Outcome names the result's shape.
	Outcome Outcome
	// Target is the resolved target node.
	Target Node
	// Paths are the routes, cheapest first. Only OutcomePaths carries any.
	Paths []Path
	// Closest is the bounded unreachable diagnostic. Only OutcomeUnreachable
	// carries any.
	Closest []Closest
	// Opportunities are unexploited findings on nodes current access can
	// already reach: hints, never steps. Only OutcomeUnreachable carries any.
	Opportunities []Opportunity
	// Note is an ordinary caveat: fewer than K routes, or a truncated search.
	Note string
}

// Compute answers the cheapest routes from the engagement's current access to
// a target (docs/attack-paths.md §4–§5). k is the number of distinct routes;
// k <= 0 uses DefaultK.
//
// It reads the snapshot only: no step is scheduled, pre-authorized, or
// executed (ADR-0006).
func Compute(snapshot engagementstate.Snapshot, target string, k int) (Result, error) {
	if snapshot.Truncated {
		return Result{}, errors.New("attackpath: the state snapshot is truncated; attack paths need the full record")
	}
	if strings.TrimSpace(target) == "" {
		return Result{}, fmt.Errorf("%w: a target host or service is required", ErrTarget)
	}
	if k <= 0 {
		k = DefaultK
	}

	resolved, err := resolveTarget(snapshot, target)
	if err != nil {
		return Result{}, err
	}
	graph, err := project(snapshot)
	if err != nil {
		return Result{}, err
	}

	sources := make([]string, 0)
	for _, e := range snapshot.Entities {
		if e.Kind == engagementstate.KindAccess && e.Active {
			sources = append(sources, e.ID)
		}
	}
	sort.Strings(sources)
	if len(sources) == 0 {
		return Result{Outcome: OutcomeNoFootholds, Target: resolved}, nil
	}

	if held, ok := holdingAccess(snapshot, resolved.ID); ok {
		return Result{
			Outcome: OutcomePaths,
			Target:  resolved,
			Paths: []Path{{
				TotalCost: 0,
				Level:     held.Level,
				Rationale: "already have access",
				Steps:     []Step{},
			}},
			Note: "the target is already held; no route is needed",
		}, nil
	}

	records, capped := graph.paths(sources, resolved.ID, k)
	if len(records) == 0 {
		return Result{
			Outcome:       OutcomeUnreachable,
			Target:        resolved,
			Closest:       graph.closest(sources, resolved.ID),
			Opportunities: graph.opportunities(snapshot, sources),
			Note:          lengthCapNote(capped, ""),
		}, nil
	}

	paths := make([]Path, 0, len(records))
	for _, record := range records {
		paths = append(paths, graph.path(record))
	}
	result := Result{Outcome: OutcomePaths, Target: resolved, Paths: paths}
	if len(paths) < k {
		result.Note = fmt.Sprintf("%d route(s) exist; no further distinct routes were found", len(paths))
	}
	result.Note = lengthCapNote(capped, result.Note)
	return result, nil
}

// pathRecord is one candidate route inside the search: its steps, total cost,
// and canonical signature.
type pathRecord struct {
	steps []Step
	cost  int
	sig   string
}

// graph is the capability projection (docs/attack-paths.md §2): a pure,
// derived step set over the snapshot's nodes. Nothing here is persisted.
type graph struct {
	nodes  map[string]Node
	live   map[string]bool
	adj    map[string][]Step
	rev    map[string][]Step
	levels map[string]string
	steps  int
}

// project derives the capability step set from the snapshot's stored edges
// (docs/attack-paths.md §2). Attribute edges are never traversed, inactive
// endpoints produce no steps, and a finding never produces one: EXPLOITED_VIA
// is provenance on the foothold an exploit already produced.
func project(snapshot engagementstate.Snapshot) (*graph, error) {
	if len(snapshot.Entities)+len(snapshot.Findings) > MaxNodes {
		return nil, fmt.Errorf("%w: the relationship graph has %d nodes; the cap is %d",
			ErrCap, len(snapshot.Entities)+len(snapshot.Findings), MaxNodes)
	}
	nodes := buildNodes(snapshot)
	g := &graph{
		nodes:  nodes,
		live:   make(map[string]bool, len(nodes)),
		adj:    map[string][]Step{},
		rev:    map[string][]Step{},
		levels: map[string]string{},
	}
	for _, e := range snapshot.Entities {
		g.live[e.ID] = e.Active
		if e.Kind == engagementstate.KindAccess {
			g.levels[e.ID] = e.Level
		}
	}
	for _, f := range snapshot.Findings {
		g.live[f.ID] = f.Active
	}

	admins := make(map[string]bool, len(snapshot.Edges))
	for _, edge := range snapshot.Edges {
		if edge.Type == engagementstate.EdgeAdminOf {
			admins[edge.From+"|"+edge.To] = true
		}
	}

	add := func(step Step) {
		g.adj[step.From.ID] = append(g.adj[step.From.ID], step)
		g.rev[step.To.ID] = append(g.rev[step.To.ID], step)
		g.steps++
	}

	for _, edge := range snapshot.Edges {
		if !g.live[edge.From] || !g.live[edge.To] {
			continue
		}
		confidence := defaultConfidence(edge.Confidence)
		switch edge.Type {
		case engagementstate.EdgeCredentialFrom:
			// Reversed: reaching where the secret came from makes it
			// obtainable.
			add(g.step(edge.To, edge.From, HarvestCredential, confidence, Basis{
				EdgeType: edge.Type, EdgeFrom: edge.From, EdgeTo: edge.To,
			}))
		case engagementstate.EdgeValidFor:
			if admins[edge.From+"|"+edge.To] {
				// Subsumption (§2): a credential with ADMIN_OF the target
				// yields one admin_via step, never a user-level step plus an
				// escalation for the same pair.
				continue
			}
			add(g.step(edge.From, edge.To, UseCredential, confidence, Basis{
				EdgeType: edge.Type, EdgeFrom: edge.From, EdgeTo: edge.To,
			}))
		case engagementstate.EdgeAdminOf:
			add(g.step(edge.From, edge.To, AdminVia, confidence, Basis{
				EdgeType: edge.Type, EdgeFrom: edge.From, EdgeTo: edge.To,
			}))
		case engagementstate.EdgePivotTo:
			add(g.step(edge.From, edge.To, Pivot, confidence, Basis{
				EdgeType: edge.Type, EdgeFrom: edge.From, EdgeTo: edge.To,
			}))
		}
		if g.steps > MaxSteps {
			return nil, fmt.Errorf("%w: the capability projection has more than %d steps", ErrCap, MaxSteps)
		}
	}

	for id := range g.adj {
		sort.Slice(g.adj[id], func(i, j int) bool { return stepOrder(g.adj[id][i], g.adj[id][j]) })
	}
	for id := range g.rev {
		sort.Slice(g.rev[id], func(i, j int) bool { return stepOrder(g.rev[id][i], g.rev[id][j]) })
	}
	return g, nil
}

// step builds one step with its priced cost and the record it derives from.
func (g *graph) step(from, to string, kind StepKind, confidence engagementstate.Confidence, basis Basis) Step {
	return Step{
		From:       g.nodes[from],
		To:         g.nodes[to],
		Kind:       kind,
		Confidence: confidence,
		Cost:       stepCost(kind, confidence),
		Basis:      basis,
	}
}

// stepOrder is the deterministic order of a node's outgoing steps.
func stepOrder(a, b Step) bool {
	if a.To.ID != b.To.ID {
		return a.To.ID < b.To.ID
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.From.ID < b.From.ID
}

// baseCost is the per-mechanism base price (§3). Ranking intent: a route
// already holding the credential beats lateral movement, which beats
// exploitation.
var baseCost = map[StepKind]int{
	HarvestCredential: 2,
	AdminVia:          2,
	UseCredential:     3,
	Pivot:             5,
}

// noiseFactor is the static per-mechanism OPSEC multiplier (§3): a login is
// quiet, reading files and authenticating are visible, pivoting is noisy.
// Per-instance detectability needs a schema change and is not v1.
var noiseFactor = map[StepKind]int{
	HarvestCredential: 2,
	AdminVia:          1,
	UseCredential:     2,
	Pivot:             4,
}

// stepCost prices one step: base × confidence × noise, all integers (§3).
// Nothing is priced by a finding, so verification does not enter the cost
// model: a refuted finding is excluded from the diagnostics instead.
func stepCost(kind StepKind, confidence engagementstate.Confidence) int {
	return baseCost[kind] * confidenceFactor(confidence) * noiseFactor[kind]
}

// confidenceFactor maps the enum to its multiplier. An empty confidence is the
// store's default (low).
func confidenceFactor(c engagementstate.Confidence) int {
	switch c {
	case engagementstate.ConfidenceHigh:
		return 1
	case engagementstate.ConfidenceMedium:
		return 3
	default:
		return 9
	}
}

// defaultVerification replaces an empty verification with the store's default.
func defaultVerification(v engagementstate.Verification) engagementstate.Verification {
	if v == "" {
		return engagementstate.VerificationUnverified
	}
	return v
}

// defaultConfidence replaces an empty edge confidence with the store's default.
func defaultConfidence(c engagementstate.Confidence) engagementstate.Confidence {
	if c == "" {
		return engagementstate.ConfidenceLow
	}
	return c
}

// stepKey identifies one capability step of the multigraph: two steps between
// the same nodes by the same mechanism are the same edge for Yen's removal.
func stepKey(step Step) string {
	return step.From.ID + "|" + string(step.Kind) + "|" + step.To.ID
}

// signature renders a route's canonical signature: the ordered tuple of
// (from, mechanism, to), the search's tie-break (§5).
func signature(steps []Step) string {
	parts := make([]string, 0, len(steps))
	for _, step := range steps {
		parts = append(parts, stepKey(step))
	}
	return strings.Join(parts, ">")
}

// sumCosts is a route's total cost: the sum of its steps' (§3).
func sumCosts(steps []Step) int {
	total := 0
	for _, step := range steps {
		total += step.Cost
	}
	return total
}

// path renders one found route: its cost, arrival level, and rationale.
func (g *graph) path(record pathRecord) Path {
	return Path{
		TotalCost: sumCosts(record.steps),
		Level:     g.arrivalLevel(record.steps),
		Rationale: rationale(record.steps),
		Steps:     record.steps,
	}
}

// arrivalLevel reports the privilege the final step lands at. An arrival level
// is reported, never persisted (§4): writing an implied access entity would
// make the computation a state mutation, and it is not one.
func (g *graph) arrivalLevel(steps []Step) string {
	if len(steps) == 0 {
		return ""
	}
	last := steps[len(steps)-1]
	switch last.Kind {
	case AdminVia:
		return engagementstate.LevelAdmin
	case UseCredential:
		return engagementstate.LevelUser
	case Pivot:
		return g.levels[last.From.ID]
	}
	return ""
}

// rationale is the one-line mechanism summary.
func rationale(steps []Step) string {
	if len(steps) == 0 {
		return "already have access"
	}
	words := make([]string, 0, len(steps))
	for _, step := range steps {
		words = append(words, mechanismWords(step.Kind))
	}
	return strings.Join(words, " → ")
}

// mechanismWords renders a mechanism for the rationale.
func mechanismWords(kind StepKind) string {
	switch kind {
	case HarvestCredential:
		return "harvest a credential"
	case UseCredential:
		return "use a credential"
	case AdminVia:
		return "admin access"
	case Pivot:
		return "pivot"
	}
	return string(kind)
}

// paths computes up to k distinct loopless routes with Dijkstra + Yen's
// algorithm (§5). The second return reports that the search was truncated at
// the per-path step cap.
func (g *graph) paths(sources []string, target string, k int) ([]pathRecord, bool) {
	first, capped := g.shortest(sources, target, nil, nil, MaxPathSteps)
	if len(first) == 0 {
		return nil, capped
	}
	found := []pathRecord{{steps: first, cost: sumCosts(first), sig: signature(first)}}
	candidates := &recordQueue{}

	for len(found) < k {
		previous := found[len(found)-1]
		for i := 0; i < len(previous.steps); i++ {
			if i >= MaxPathSteps {
				continue
			}
			spur := previous.steps[i].From.ID
			root := previous.steps[:i]

			blockedEdges := map[string]bool{}
			for _, earlier := range found {
				if len(earlier.steps) > i && samePrefix(earlier.steps, root) {
					blockedEdges[stepKey(earlier.steps[i])] = true
				}
			}
			blockedNodes := map[string]bool{}
			for _, step := range root {
				blockedNodes[step.From.ID] = true
			}

			spurSteps, spurCapped := g.shortest([]string{spur}, target, blockedNodes, blockedEdges, MaxPathSteps-i)
			capped = capped || spurCapped
			if len(spurSteps) == 0 {
				continue
			}
			total := make([]Step, 0, i+len(spurSteps))
			total = append(total, root...)
			total = append(total, spurSteps...)
			sig := signature(total)
			if containsSignature(found, sig) || candidates.has(sig) {
				continue
			}
			heap.Push(candidates, &pathRecord{steps: total, cost: sumCosts(total), sig: sig})
		}
		if candidates.Len() == 0 {
			break
		}
		next := heap.Pop(candidates).(*pathRecord)
		found = append(found, *next)
	}
	return found, capped
}

// samePrefix reports whether a route begins with the same steps as a root.
func samePrefix(steps, root []Step) bool {
	if len(root) > len(steps) {
		return false
	}
	for i := range root {
		if stepKey(steps[i]) != stepKey(root[i]) {
			return false
		}
	}
	return true
}

// containsSignature reports whether a route with a signature is already found.
func containsSignature(records []pathRecord, sig string) bool {
	for _, record := range records {
		if record.sig == sig {
			return true
		}
	}
	return false
}

// shortest runs one Dijkstra search from a set of sources to a target, over
// the projection minus any blocked nodes or edges. It returns the steps of the
// cheapest route (empty when none exists) and reports whether the per-path
// step cap cut the search.
//
// Ties break on (cost, step signature): identical state produces byte-identical
// output, which is what makes golden tests possible (§5).
func (g *graph) shortest(sources []string, target string, blockedNodes, blockedEdges map[string]bool, maxSteps int) ([]Step, bool) {
	type state struct {
		cost int
		sig  string
	}
	best := make(map[string]state, len(g.nodes))
	queue := &stepQueue{}
	capped := false

	for _, source := range sources {
		if blockedNodes[source] {
			continue
		}
		heap.Push(queue, &stepItem{cost: 0, node: source})
	}

	for queue.Len() > 0 {
		current := heap.Pop(queue).(*stepItem)
		if known, ok := best[current.node]; ok &&
			(current.cost > known.cost || current.cost == known.cost && current.sig >= known.sig) {
			continue
		}
		best[current.node] = state{cost: current.cost, sig: current.sig}
		if current.node == target {
			return current.steps, capped
		}
		if len(current.steps) >= maxSteps {
			if len(g.adj[current.node]) > 0 {
				capped = true
			}
			continue
		}
		for _, step := range g.adj[current.node] {
			if blockedEdges[stepKey(step)] || blockedNodes[step.To.ID] {
				continue
			}
			next := &stepItem{
				cost:  current.cost + step.Cost,
				sig:   joinSignature(current.sig, step),
				node:  step.To.ID,
				steps: appendStep(current.steps, step),
			}
			if known, ok := best[next.node]; ok &&
				(next.cost > known.cost || next.cost == known.cost && next.sig >= known.sig) {
				continue
			}
			heap.Push(queue, next)
		}
	}
	return nil, capped
}

// joinSignature appends one step's key to a route signature.
func joinSignature(sig string, step Step) string {
	if sig == "" {
		return stepKey(step)
	}
	return sig + ">" + stepKey(step)
}

// appendStep returns a route with one step appended, never aliasing the
// route it came from.
func appendStep(steps []Step, step Step) []Step {
	next := make([]Step, len(steps)+1)
	copy(next, steps)
	next[len(steps)] = step
	return next
}

// closest builds the bounded unreachable diagnostic (§5): a reverse Dijkstra
// from the target intersected with the forward-reachable set, keeping up to
// three "closest we got" nodes and the mechanism of the step each is missing.
func (g *graph) closest(sources []string, target string) []Closest {
	forward := g.reachable(sources)
	distance, missing := g.distanceTo(target)

	out := make([]Closest, 0, 3)
	for id := range forward {
		if id == target {
			continue
		}
		cost, ok := distance[id]
		if !ok {
			continue
		}
		out = append(out, Closest{Node: g.nodes[id], Missing: missing[id], Distance: cost})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Distance != out[j].Distance {
			return out[i].Distance < out[j].Distance
		}
		return out[i].Node.ID < out[j].Node.ID
	})
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

// opportunities lists up to three unexploited findings on nodes current access
// can already reach (§5). They are hints, not steps: nothing is priced, and
// nothing claims what foothold an exploit that has not run would yield.
func (g *graph) opportunities(snapshot engagementstate.Snapshot, sources []string) []Opportunity {
	reachable := g.reachable(sources)
	exploited := make(map[string]bool, len(snapshot.Edges))
	for _, edge := range snapshot.Edges {
		if edge.Type == engagementstate.EdgeExploitedVia {
			exploited[edge.From] = true
		}
	}

	out := make([]Opportunity, 0, 3)
	for _, finding := range snapshot.Findings {
		if !finding.Active || exploited[finding.ID] ||
			finding.Verification == engagementstate.VerificationRefuted {
			continue
		}
		for _, affected := range finding.Affected {
			if !g.live[affected] || !reachable[affected] {
				continue
			}
			out = append(out, Opportunity{
				Finding:      g.nodes[finding.ID],
				Node:         g.nodes[affected],
				Confidence:   defaultConfidence(finding.Confidence),
				Verification: defaultVerification(finding.Verification),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Node.ID != out[j].Node.ID {
			return out[i].Node.ID < out[j].Node.ID
		}
		return out[i].Finding.ID < out[j].Finding.ID
	})
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

// reachable is the set of nodes reachable from the sources over the
// projection, ignoring cost and the per-path step cap: this is reachability,
// not a route.
func (g *graph) reachable(sources []string) map[string]bool {
	seen := make(map[string]bool, len(g.nodes))
	queue := append([]string(nil), sources...)
	for _, source := range sources {
		seen[source] = true
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for _, step := range g.adj[node] {
			if seen[step.To.ID] {
				continue
			}
			seen[step.To.ID] = true
			queue = append(queue, step.To.ID)
		}
	}
	return seen
}

// distanceTo is a reverse Dijkstra from the target: for every node, the cost
// of its cheapest route toward the target and the mechanism of its first step
// there.
func (g *graph) distanceTo(target string) (map[string]int, map[string]StepKind) {
	distance := map[string]int{target: 0}
	missing := map[string]StepKind{}
	queue := &costQueue{}
	heap.Push(queue, &costItem{node: target, cost: 0})

	for queue.Len() > 0 {
		current := heap.Pop(queue).(*costItem)
		if known, ok := distance[current.node]; ok && current.cost > known {
			continue
		}
		for _, step := range g.rev[current.node] {
			next := current.cost + step.Cost
			if known, ok := distance[step.From.ID]; ok && next >= known {
				continue
			}
			distance[step.From.ID] = next
			missing[step.From.ID] = step.Kind
			heap.Push(queue, &costItem{node: step.From.ID, cost: next})
		}
	}
	return distance, missing
}

// lengthCapNote appends the per-path cap caveat to a result's note.
func lengthCapNote(capped bool, note string) string {
	if !capped {
		return note
	}
	line := fmt.Sprintf("search truncated at the %d-step-per-path cap", MaxPathSteps)
	if note == "" {
		return line
	}
	return note + "; " + line
}

// holdingAccess reports the strongest active access entity on a target.
func holdingAccess(snapshot engagementstate.Snapshot, target string) (engagementstate.Entity, bool) {
	var best engagementstate.Entity
	found := false
	for _, e := range snapshot.Entities {
		if e.Kind != engagementstate.KindAccess || !e.Active || e.Target != target {
			continue
		}
		if !found || levelRank(e.Level) > levelRank(best.Level) ||
			levelRank(e.Level) == levelRank(best.Level) && e.ID < best.ID {
			best = e
			found = true
		}
	}
	return best, found
}

// levelRank orders access levels for picking the strongest held foothold.
func levelRank(level string) int {
	switch level {
	case engagementstate.LevelSystem:
		return 3
	case engagementstate.LevelAdmin:
		return 2
	case engagementstate.LevelUser:
		return 1
	}
	return 0
}

// resolveTarget resolves the target string to exactly one host or service
// (§4): entity id first, then address, then hostname. An ambiguous or
// unmatched target is a hard error naming what was found, never a guess.
func resolveTarget(snapshot engagementstate.Snapshot, raw string) (Node, error) {
	want := strings.TrimSpace(raw)
	nodes := buildNodes(snapshot)

	if e, ok := snapshot.Entity(want); ok {
		if e.Kind != engagementstate.KindHost && e.Kind != engagementstate.KindService {
			return Node{}, fmt.Errorf("%w: %q names a %s; want a host or service", ErrTarget, raw, e.Kind)
		}
		return nodes[e.ID], nil
	}
	if _, ok := snapshot.Finding(want); ok {
		return Node{}, fmt.Errorf("%w: %q names a finding; want a host or service", ErrTarget, raw)
	}

	for _, match := range []struct {
		by   string
		look func(engagementstate.Entity) bool
	}{
		{"address", func(e engagementstate.Entity) bool { return hasAddress(e, want) }},
		{"hostname", func(e engagementstate.Entity) bool { return hasHostname(e, want) }},
	} {
		var matches []engagementstate.Entity
		for _, e := range snapshot.Entities {
			if e.Kind == engagementstate.KindHost && match.look(e) {
				matches = append(matches, e)
			}
		}
		switch len(matches) {
		case 0:
			continue
		case 1:
			return nodes[matches[0].ID], nil
		default:
			sort.Slice(matches, func(i, j int) bool { return matches[i].ID < matches[j].ID })
			ids := make([]string, 0, len(matches))
			for _, e := range matches {
				ids = append(ids, e.ID)
			}
			return Node{}, fmt.Errorf("%w: %q matches %d hosts by %s (%s); name the id",
				ErrTarget, raw, len(matches), match.by, strings.Join(ids, ", "))
		}
	}
	return Node{}, fmt.Errorf("%w: %q matches no host or service by id, address, or hostname", ErrTarget, raw)
}

// hasAddress reports whether a host records an address.
func hasAddress(e engagementstate.Entity, want string) bool {
	for _, address := range e.Addresses {
		if normalizeAddress(address) == normalizeAddress(want) {
			return true
		}
	}
	return false
}

// hasHostname reports whether a host records a hostname.
func hasHostname(e engagementstate.Entity, want string) bool {
	return e.Hostname != "" && normalizeAddress(e.Hostname) == normalizeAddress(want)
}

// normalizeAddress canonicalizes an address for comparison: an IP literal in
// its unmapped form, or a lowercased hostname without a trailing root dot.
func normalizeAddress(raw string) string {
	s := strings.TrimSpace(raw)
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// buildNodes labels every entity and finding for the reader.
func buildNodes(snapshot engagementstate.Snapshot) map[string]Node {
	entities := make(map[string]engagementstate.Entity, len(snapshot.Entities))
	for _, e := range snapshot.Entities {
		entities[e.ID] = e
	}
	var label func(string) string
	label = func(id string) string {
		entity, ok := entities[id]
		if !ok {
			if finding, ok := snapshot.Finding(id); ok {
				return finding.Title
			}
			return id
		}
		switch entity.Kind {
		case engagementstate.KindHost:
			var parts []string
			if entity.Hostname != "" {
				parts = append(parts, entity.Hostname)
			}
			if len(entity.Addresses) > 0 {
				parts = append(parts, entity.Addresses[0])
			}
			if len(parts) == 0 {
				return id
			}
			return strings.Join(parts, " ")
		case engagementstate.KindService:
			name := fmt.Sprintf("%d/%s", entity.Port, entity.Proto)
			if entity.Product != "" {
				name = entity.Product + " " + name
			}
			if entity.Host != "" {
				name += " on " + label(entity.Host)
			}
			return name
		case engagementstate.KindCredential:
			if entity.Principal != "" {
				return entity.Type + " " + entity.Principal
			}
			return entity.Type
		case engagementstate.KindAccess:
			parts := []string{entity.Principal + " as " + entity.Level}
			if entity.Target != "" {
				parts = append(parts, "on "+label(entity.Target))
			}
			return strings.Join(parts, " ")
		case engagementstate.KindSegment:
			if len(entity.CIDRs) > 0 {
				return entity.Label + " " + strings.Join(entity.CIDRs, ",")
			}
			return entity.Label
		}
		return id
	}

	nodes := make(map[string]Node, len(snapshot.Entities)+len(snapshot.Findings))
	for _, e := range snapshot.Entities {
		nodes[e.ID] = Node{ID: e.ID, Kind: e.Kind, Label: label(e.ID)}
	}
	for _, f := range snapshot.Findings {
		nodes[f.ID] = Node{ID: f.ID, Kind: engagementstate.KindFinding, Label: label(f.ID)}
	}
	return nodes
}

// stepItem is one priority-queue entry in a Dijkstra search: a partial route.
type stepItem struct {
	cost  int
	sig   string
	node  string
	steps []Step
}

// stepQueue orders partial routes by (cost, signature, node).
type stepQueue []*stepItem

func (q stepQueue) Len() int { return len(q) }

func (q stepQueue) Less(i, j int) bool {
	if q[i].cost != q[j].cost {
		return q[i].cost < q[j].cost
	}
	if q[i].sig != q[j].sig {
		return q[i].sig < q[j].sig
	}
	return q[i].node < q[j].node
}

func (q stepQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }

func (q *stepQueue) Push(x any) { *q = append(*q, x.(*stepItem)) }

func (q *stepQueue) Pop() any {
	old := *q
	last := old[len(old)-1]
	*q = old[:len(old)-1]
	return last
}

// costItem is one priority-queue entry in a single-cost search: a node and the
// cost to reach it.
type costItem struct {
	node string
	cost int
}

// costQueue orders nodes by (cost, id).
type costQueue []*costItem

func (q costQueue) Len() int { return len(q) }

func (q costQueue) Less(i, j int) bool {
	if q[i].cost != q[j].cost {
		return q[i].cost < q[j].cost
	}
	return q[i].node < q[j].node
}

func (q costQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }

func (q *costQueue) Push(x any) { *q = append(*q, x.(*costItem)) }

func (q *costQueue) Pop() any {
	old := *q
	last := old[len(old)-1]
	*q = old[:len(old)-1]
	return last
}

// recordQueue is Yen's candidate heap, ordered by (cost, signature).
type recordQueue []*pathRecord

func (q recordQueue) Len() int { return len(q) }

func (q recordQueue) Less(i, j int) bool {
	if q[i].cost != q[j].cost {
		return q[i].cost < q[j].cost
	}
	return q[i].sig < q[j].sig
}

func (q recordQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }

func (q *recordQueue) Push(x any) { *q = append(*q, x.(*pathRecord)) }

func (q *recordQueue) Pop() any {
	old := *q
	last := old[len(old)-1]
	*q = old[:len(old)-1]
	return last
}

// has reports whether a candidate with a signature is already queued.
func (q *recordQueue) has(sig string) bool {
	for _, record := range *q {
		if record.sig == sig {
			return true
		}
	}
	return false
}
