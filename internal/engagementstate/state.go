// Package engagementstate implements the per-engagement state document: the
// structured record of what an engagement observed — hosts, services,
// credentials, access, segments, and findings — and the typed relationship
// graph over them.
//
// Boundary rule: the store records observations only. Authorization never
// enters it (scope and ROE live in the engagement file and the policy engine,
// §2 of docs/engagement-state.md), and no model output reaches it except
// through the schema-validated, harness-stamped ops this package defines. The
// document lives outside the conversation, so compaction cannot reach it and
// the prompt sees only a derived digest.
package engagementstate

import (
	"net/netip"
	"slices"
	"strings"
	"time"
)

// SchemaVersion is the document schema this build writes (§1). A document
// declaring a different major refuses to load, loudly, naming the file; v1 has
// no automatic migration.
const SchemaVersion = 1

// Kind is an engagement-state entity kind (§3). v1 has six; AD-specific
// directory kinds are deferred.
type Kind string

const (
	// KindHost is a discovered host: addresses, hostname, OS, tags.
	KindHost Kind = "host"
	// KindService is an offered service: host ref, port, proto, product,
	// version, state.
	KindService Kind = "service"
	// KindCredential is a captured secret: type, principal, secret, tags.
	KindCredential Kind = "credential"
	// KindAccess is a foothold: principal on a target at a level.
	KindAccess Kind = "access"
	// KindSegment is a labeled network range.
	KindSegment Kind = "segment"
	// KindFinding is a vulnerability or observation. It is a selection kind
	// for queries only: findings have their own record (§5) and their own op.
	KindFinding Kind = "finding"
)

// EntityKinds are the kinds `upsert_entity` accepts, in stable order. A
// finding is never an entity: it is written through `upsert_finding` (§5, §6).
func EntityKinds() []Kind {
	return []Kind{KindHost, KindService, KindCredential, KindAccess, KindSegment}
}

// QueryKinds are the kinds a `state_query` filter may name, in stable order.
func QueryKinds() []Kind {
	return []Kind{KindHost, KindService, KindCredential, KindAccess, KindSegment, KindFinding}
}

// valid reports whether a kind is one of the six v1 kinds.
func (k Kind) valid() bool {
	switch k {
	case KindHost, KindService, KindCredential, KindAccess, KindSegment, KindFinding:
		return true
	}
	return false
}

// isEntity reports whether a kind is an entity kind (a finding is not).
func (k Kind) isEntity() bool {
	return k.valid() && k != KindFinding
}

// kindList renders the valid kinds for an error message.
func kindList(kinds []Kind) string {
	names := make([]string, 0, len(kinds))
	for _, k := range kinds {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}

// Service states, credential types, access levels, protocols, and evidence
// kinds are closed sets: an unknown value is refused at the store, never
// stored as a free-form string (§3, §5).
const (
	// ProtoTCP and ProtoUDP are the service protocols.
	ProtoTCP = "tcp"
	ProtoUDP = "udp"

	// StateOpen, StateClosed, and StateFiltered are service states.
	StateOpen     = "open"
	StateClosed   = "closed"
	StateFiltered = "filtered"

	// CredentialPassword, CredentialHash, CredentialKey, and CredentialToken
	// are credential types.
	CredentialPassword = "password"
	CredentialHash     = "hash"
	CredentialKey      = "key"
	CredentialToken    = "token"

	// LevelUser, LevelAdmin, and LevelSystem are access levels.
	LevelUser   = "user"
	LevelAdmin  = "admin"
	LevelSystem = "system"
)

// Severity is a finding's qualitative severity (CVSS qualitative, §5).
type Severity string

// The severity set, in increasing order: a finding carries one of these, never
// a number.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severities is the closed severity set, in increasing order.
var severities = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// Status is a finding's lifecycle state (§5). The store validates every
// transition; anything else is refused.
type Status string

// The finding status lifecycle (§5):
//
//	detected ↔ confirmed → false_positive
//	                    → fixed        (fixed → confirmed reopens)
//	                    → risk_accepted
const (
	StatusDetected      Status = "detected"
	StatusConfirmed     Status = "confirmed"
	StatusFalsePositive Status = "false_positive"
	StatusFixed         Status = "fixed"
	StatusRiskAccepted  Status = "risk_accepted"
)

// statusTransitions is the lifecycle as an adjacency set. A status with no
// entry is terminal.
var statusTransitions = map[Status][]Status{
	StatusDetected:      {StatusConfirmed},
	StatusConfirmed:     {StatusDetected, StatusFalsePositive, StatusFixed, StatusRiskAccepted},
	StatusFixed:         {StatusConfirmed},
	StatusFalsePositive: nil,
	StatusRiskAccepted:  nil,
}

// transitionsFrom lists the statuses a status may move to, for errors.
func transitionsFrom(from Status) string {
	next := statusTransitions[from]
	if len(next) == 0 {
		return "none (terminal)"
	}
	names := make([]string, 0, len(next))
	for _, s := range next {
		names = append(names, string(s))
	}
	return strings.Join(names, ", ")
}

// valid reports whether a status is one of the lifecycle's five.
func (s Status) valid() bool {
	_, ok := statusTransitions[s]
	return ok
}

// IsOpen reports whether a finding in this status is still open: detected or
// confirmed. Closed and dismissed statuses are not.
func (s Status) IsOpen() bool { return s == StatusDetected || s == StatusConfirmed }

// Confidence is a finding's or edge's qualitative confidence (§5). Enums,
// never numbers: a model cannot calibrate 0.73, and the path cost model maps
// the enum to modifiers.
type Confidence string

// The confidence set.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Verification is a finding's verification state (§5). `verified` and
// `refuted` require evidence; `unverified` is where every finding starts.
type Verification string

// The verification set.
const (
	VerificationUnverified Verification = "unverified"
	VerificationVerified   Verification = "verified"
	VerificationRefuted    Verification = "refuted"
)

// EvidenceKind is the form of a finding's evidence item (§5).
type EvidenceKind string

const (
	// EvidenceCLIOutput is captured command output.
	EvidenceCLIOutput EvidenceKind = "cli-output"
	// EvidenceHTTPResponse is a captured request/response pair.
	EvidenceHTTPResponse EvidenceKind = "http-response"
	// EvidenceArtifact is a preserved file (a scanner's raw output).
	EvidenceArtifact EvidenceKind = "artifact"
	// EvidenceScreenshot is a captured image.
	EvidenceScreenshot EvidenceKind = "screenshot"
	// EvidenceNote is the operator's or model's own note.
	EvidenceNote EvidenceKind = "note"
)

// evidenceKinds is the closed evidence-kind set, in stable order.
var evidenceKinds = []EvidenceKind{
	EvidenceCLIOutput, EvidenceHTTPResponse, EvidenceArtifact, EvidenceScreenshot, EvidenceNote,
}

// EdgeType is a relationship-graph edge type (§4). The set is closed: a new
// edge type is a design-doc change, never a free-form string.
type EdgeType string

const (
	// EdgeResolvesTo is a hostname resolving to an address (host → host).
	EdgeResolvesTo EdgeType = "RESOLVES_TO"
	// EdgeRunsOn is a service offered by a host (service → host).
	EdgeRunsOn EdgeType = "RUNS_ON"
	// EdgeInSegment is a host belonging to a segment (host → segment).
	EdgeInSegment EdgeType = "IN_SEGMENT"
	// EdgeCredentialFrom is where a secret came from
	// (credential → host | service | finding).
	//
	//nolint:gosec // the value names a graph edge, not credential material.
	EdgeCredentialFrom EdgeType = "CREDENTIAL_FROM"
	// EdgeValidFor is a secret working on a target (credential → host | service).
	EdgeValidFor EdgeType = "VALID_FOR"
	// EdgeAdminOf is privilege over a target
	// (credential | access → host | service).
	EdgeAdminOf EdgeType = "ADMIN_OF"
	// EdgePivotTo is a foothold reaching a host (access → host).
	EdgePivotTo EdgeType = "PIVOT_TO"
	// EdgeExploitedVia is a finding producing a foothold (finding → access).
	EdgeExploitedVia EdgeType = "EXPLOITED_VIA"
)

// EdgeTypes lists the closed edge enum, in stable order.
func EdgeTypes() []EdgeType {
	return []EdgeType{
		EdgeResolvesTo, EdgeRunsOn, EdgeInSegment, EdgeCredentialFrom,
		EdgeValidFor, EdgeAdminOf, EdgePivotTo, EdgeExploitedVia,
	}
}

// endpoints is the per-edge endpoint table (§4): which kinds an edge's `from`
// and `to` may name. Validation is per edge type, never free-form.
var endpoints = map[EdgeType]struct{ from, to []Kind }{
	EdgeResolvesTo:     {[]Kind{KindHost}, []Kind{KindHost}},
	EdgeRunsOn:         {[]Kind{KindService}, []Kind{KindHost}},
	EdgeInSegment:      {[]Kind{KindHost}, []Kind{KindSegment}},
	EdgeCredentialFrom: {[]Kind{KindCredential}, []Kind{KindHost, KindService, KindFinding}},
	EdgeValidFor:       {[]Kind{KindCredential}, []Kind{KindHost, KindService}},
	EdgeAdminOf:        {[]Kind{KindCredential, KindAccess}, []Kind{KindHost, KindService}},
	EdgePivotTo:        {[]Kind{KindAccess}, []Kind{KindHost}},
	EdgeExploitedVia:   {[]Kind{KindFinding}, []Kind{KindAccess}},
}

// valid reports whether an edge type is in the closed enum.
func (e EdgeType) valid() bool {
	_, ok := endpoints[e]
	return ok
}

// Provenance is the harness-stamped origin of a mutation (§6): the tool that
// wrote it (or "model"), the subagent run it came from, the session, and the
// time. It is never model-supplied — the op protocol has no field for it.
type Provenance struct {
	// Source is the writing tool's name, or "model" for a model-driven write.
	Source string `json:"source"`
	// Subagent is the role of the subagent run that wrote, empty for the main
	// loop.
	Subagent string `json:"subagent,omitempty"`
	// Session is the session id the write happened in.
	Session string `json:"session,omitempty"`
	// At is when the harness applied the write.
	At time.Time `json:"at"`
}

// Origin is the caller-side half of a mutation's provenance: which harness
// tool is writing and, inside a subagent, which run. The store stamps the
// session and the time, so neither can be forged from the call's arguments.
type Origin struct {
	// Tool is the writing tool's name.
	Tool string
	// Subagent is the writing run's role, empty for the main loop.
	Subagent string
}

// Entity is one engagement-state entity: a common envelope (§3) plus the
// attributes its kind declares. One flat record keeps the on-disk document
// readable and the JSON protocol direct; the kind decides which attributes are
// meaningful, and the store validates them.
type Entity struct {
	// ID is the harness-assigned stable identifier ("host-1a2b").
	ID string `json:"id"`
	// Kind discriminates the entity.
	Kind Kind `json:"kind"`
	// Active is false for a deactivated entity (v1 has no deletes, §3).
	Active bool `json:"active"`
	// CreatedAt and UpdatedAt bound the entity's life.
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Provenance is the last write's harness stamp.
	Provenance Provenance `json:"provenance"`

	// Addresses are a host's known addresses; the first is its natural key.
	Addresses []string `json:"addresses,omitempty"`
	// Hostname is a host's name.
	Hostname string `json:"hostname,omitempty"`
	// OS is a host's operating system, as observed.
	OS string `json:"os,omitempty"`
	// Tags are free-form labels (host, credential).
	Tags []string `json:"tags,omitempty"`

	// Host is a service's host reference.
	Host string `json:"host,omitempty"`
	// Port and Proto are a service's port and protocol.
	Port  int    `json:"port,omitempty"`
	Proto string `json:"proto,omitempty"`
	// Product and Version are a service's observed banner identity.
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	// State is a service's state (open / closed / filtered).
	State string `json:"state,omitempty"`

	// Type is a credential's type (password / hash / key / token).
	Type string `json:"type,omitempty"`
	// Principal is a credential's principal, or an access's principal
	// (a credential ref or an account name).
	Principal string `json:"principal,omitempty"`
	// Secret is a credential's secret material.
	Secret string `json:"secret,omitempty"`

	// Target is an access's target reference (a host or service).
	Target string `json:"target,omitempty"`
	// Level is an access's level (user / admin / system).
	Level string `json:"level,omitempty"`
	// Via is an access's single-hop mirror of its EXPLOITED_VIA edge — a
	// convenience field the store keeps in step with the canonical edge (§4).
	Via string `json:"via,omitempty"`

	// Label is a segment's label.
	Label string `json:"label,omitempty"`
	// CIDRs are a segment's ranges.
	CIDRs []string `json:"cidrs,omitempty"`
}

// Evidence is one verification record attached to a finding (§5). Its
// provenance is stamped by the harness on attach, never passed in.
type Evidence struct {
	// Kind is the evidence form.
	Kind EvidenceKind `json:"kind"`
	// Ref is an artifact path or an inline excerpt.
	Ref string `json:"ref"`
	// Provenance is the harness stamp of the attach.
	Provenance Provenance `json:"provenance"`
}

// Finding is the §5 finding record. A finding without evidence is unvalidated:
// verification can never advance past `unverified` until an evidence item
// exists.
type Finding struct {
	// ID is the harness-assigned stable identifier ("finding-3c4d").
	ID string `json:"id"`
	// Active is false for a deactivated finding.
	Active bool `json:"active"`
	// Title is the short human label; with Affected it is the natural key.
	Title string `json:"title"`
	// Severity is the qualitative severity.
	Severity Severity `json:"severity"`
	// CVSSVector is the optional CVSS vector backing the severity.
	CVSSVector string `json:"cvss_vector,omitempty"`
	// Status is the lifecycle state.
	Status Status `json:"status"`
	// Confidence is the qualitative confidence.
	Confidence Confidence `json:"confidence"`
	// Verification is the verification state.
	Verification Verification `json:"verification"`
	// Evidence is the attached evidence, oldest first.
	Evidence []Evidence `json:"evidence,omitempty"`
	// Affected are the host/service refs the finding concerns.
	Affected []string `json:"affected,omitempty"`
	// FirstSeen and LastSeen bound when the finding was observed.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// CreatedAt and UpdatedAt bound the record's life.
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Provenance is the last write's harness stamp.
	Provenance Provenance `json:"provenance"`
}

// EvidenceCount reports how many evidence items the finding carries, for
// callers that only need to know whether it is validated at all.
func (f Finding) EvidenceCount() int { return len(f.Evidence) }

// Edge is one relationship-graph edge (§4): a closed-enum type, two validated
// endpoints, a confidence, and the provenance of its last write.
type Edge struct {
	// Type is the edge type.
	Type EdgeType `json:"type"`
	// From and To are the endpoints' entity ids.
	From string `json:"from"`
	To   string `json:"to"`
	// Confidence is the qualitative confidence the edge holds.
	Confidence Confidence `json:"confidence"`
	// CreatedAt and UpdatedAt bound the edge's life.
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Provenance is the last write's harness stamp.
	Provenance Provenance `json:"provenance"`
}

// Key is the edge's identity: type plus endpoints.
func (e Edge) Key() string { return string(e.Type) + "|" + e.From + "|" + e.To }

// Snapshot is the state's read shape: everything a consumer needs to reason
// over the record without holding the store. It is what `state_query` serves
// and what the attack-path computation consumes, so both readers share one
// projection.
type Snapshot struct {
	// SchemaVersion and Revision identify the document the snapshot came from.
	SchemaVersion int
	Revision      int
	// Entities, Findings, and Edges are deep copies: mutating a snapshot never
	// reaches the store.
	Entities []Entity
	Findings []Finding
	Edges    []Edge
	// Truncated reports that a query's limit cut the result. A truncated
	// snapshot is a view for a reader, never complete enough to reason over
	// paths: the path computation takes a full snapshot.
	Truncated bool
}

// Entity returns the snapshot's entity with an id.
func (s Snapshot) Entity(id string) (Entity, bool) {
	for _, e := range s.Entities {
		if e.ID == id {
			return e, true
		}
	}
	return Entity{}, false
}

// Finding returns the snapshot's finding with an id.
func (s Snapshot) Finding(id string) (Finding, bool) {
	for _, f := range s.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

// Query is a `state_query` read (§6): structured filters over kinds and
// attributes, listing, and 1–2-hop neighborhood reads over the graph. There is
// no query language in v1.
type Query struct {
	// Kind selects one kind, or every kind when empty.
	Kind Kind
	// ID selects exactly one entity or finding by its harness id.
	ID string
	// Where filters by attribute equality, ANDed. Keys are the declared
	// attribute names (see attributeFilters); an unknown key is refused rather
	// than silently matching nothing.
	Where map[string]string
	// Hops expands the result to the neighborhood within this many graph hops
	// of the selection: 0, 1, or 2. Hops requires a seed (ID, or a Kind/Where
	// selection).
	Hops int
	// IncludeInactive includes deactivated entities and findings, which a
	// listing hides by default.
	IncludeInactive bool
	// Limit caps the number of entities and findings reported; 0 means the
	// default cap.
	Limit int
}

// document is the on-disk schema (§1): one JSON document per engagement.
// Unknown keys are tolerated by design — the same-major compatibility contract
// session JSONL and config share.
type document struct {
	SchemaVersion int       `json:"schema_version"`
	Engagement    string    `json:"engagement"`
	Project       string    `json:"project,omitempty"`
	Revision      int       `json:"revision"`
	UpdatedAt     time.Time `json:"updated_at"`
	Entities      []Entity  `json:"entities"`
	Findings      []Finding `json:"findings"`
	Edges         []Edge    `json:"edges"`
}

// newDocument is the empty document a fresh engagement starts from.
func newDocument(project, engagement string) *document {
	return &document{
		SchemaVersion: SchemaVersion,
		Engagement:    engagement,
		Project:       project,
		Entities:      []Entity{},
		Findings:      []Finding{},
		Edges:         []Edge{},
	}
}

// snapshot projects the document as the read shape, deep-copying every record
// so a reader can never alias store state.
func (d *document) snapshot() Snapshot {
	snap := Snapshot{
		SchemaVersion: d.SchemaVersion,
		Revision:      d.Revision,
		Entities:      make([]Entity, 0, len(d.Entities)),
		Findings:      make([]Finding, 0, len(d.Findings)),
		Edges:         make([]Edge, 0, len(d.Edges)),
	}
	for _, e := range d.Entities {
		e.Addresses = append([]string(nil), e.Addresses...)
		e.Tags = append([]string(nil), e.Tags...)
		e.CIDRs = append([]string(nil), e.CIDRs...)
		snap.Entities = append(snap.Entities, e)
	}
	for _, f := range d.Findings {
		f.Evidence = append([]Evidence(nil), f.Evidence...)
		f.Affected = append([]string(nil), f.Affected...)
		snap.Findings = append(snap.Findings, f)
	}
	snap.Edges = append(snap.Edges, d.Edges...)
	return snap
}

// findEntity returns the index of the entity with an id.
func (d *document) findEntity(id string) int {
	for i, e := range d.Entities {
		if e.ID == id {
			return i
		}
	}
	return -1
}

// findFinding returns the index of the finding with an id.
func (d *document) findFinding(id string) int {
	for i, f := range d.Findings {
		if f.ID == id {
			return i
		}
	}
	return -1
}

// findEdge returns the index of an edge by its key.
func (d *document) findEdge(key string) int {
	for i, e := range d.Edges {
		if e.Key() == key {
			return i
		}
	}
	return -1
}

// nodeKind reports the kind of the entity or finding an id names.
func (d *document) nodeKind(id string) (Kind, bool) {
	if i := d.findEntity(id); i >= 0 {
		return d.Entities[i].Kind, true
	}
	if d.findFinding(id) >= 0 {
		return KindFinding, true
	}
	return "", false
}

// active reports whether the node an id names exists and is active.
func (d *document) nodeActive(id string) bool {
	if i := d.findEntity(id); i >= 0 {
		return d.Entities[i].Active
	}
	if i := d.findFinding(id); i >= 0 {
		return d.Findings[i].Active
	}
	return false
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

// validAddress reports whether a value is usable as a host address: an IP
// literal or a syntactically plausible hostname.
func validAddress(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '-' || r == '_'
		if !ok {
			return false
		}
	}
	return !strings.HasPrefix(s, ".") && !strings.Contains(s, "..")
}

// validCIDR reports whether a value is a CIDR block.
func validCIDR(raw string) bool {
	_, err := netip.ParsePrefix(strings.TrimSpace(raw))
	return err == nil
}

// dedupeStrings returns the values with duplicates removed, in first-seen
// order, skipping blanks.
func dedupeStrings(values []string) []string {
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if slices.Contains(out, v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

// severityRank orders severities for "top findings" reporting: the higher the
// rank, the more severe, so a descending sort lists the most severe first.
func severityRank(s Severity) int {
	for i, candidate := range severities {
		if candidate == s {
			return i + 1
		}
	}
	return 0
}
