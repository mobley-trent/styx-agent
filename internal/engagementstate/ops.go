package engagementstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// OpName is one typed write operation (§6). The set is closed: there are no
// delete ops in v1 — entities and findings go `active: false`, and edges may
// be removed without dangling anything.
type OpName string

const (
	// OpUpsertEntity writes one host, service, credential, access, or
	// segment, reusing the existing id when the natural key matches.
	OpUpsertEntity OpName = "upsert_entity"
	// OpUpsertFinding writes one finding record.
	OpUpsertFinding OpName = "upsert_finding"
	// OpSetStatus advances a finding's status along the lifecycle.
	OpSetStatus OpName = "set_status"
	// OpAttachEvidence attaches one evidence item, harness-stamped.
	OpAttachEvidence OpName = "attach_evidence"
	// OpSetVerification sets a finding's verification state.
	OpSetVerification OpName = "set_verification"
	// OpAddEdge adds one relationship-graph edge, or updates its confidence.
	OpAddEdge OpName = "add_edge"
	// OpRemoveEdge removes one relationship-graph edge.
	OpRemoveEdge OpName = "remove_edge"
)

// OpNames lists the closed op set, in stable order.
func OpNames() []OpName {
	return []OpName{
		OpUpsertEntity, OpUpsertFinding, OpSetStatus, OpAttachEvidence,
		OpSetVerification, OpAddEdge, OpRemoveEdge,
	}
}

// Op is one typed write operation. It is deliberately flat — the same shape as
// a session event — because the op protocol is a wire format: the model sends
// it as JSON, parsers build it in Go, and the store validates it field by
// field. There is no field for provenance (source, session, subagent, time):
// the harness stamps those, so model-supplied provenance is not merely
// rejected, it is unrepresentable.
type Op struct {
	// Op names the operation.
	Op OpName `json:"op"`

	// Kind is an upsert_entity's entity kind.
	Kind Kind `json:"kind,omitempty"`
	// ID is the record's harness id. An upsert may supply one — that is how a
	// harness-side batch references the records it writes in the same batch
	// (docs/parser-tool-contracts.md §5) — and must otherwise leave it empty
	// for the store to mint. A supplied id carries its own kind prefix and
	// must be free; a natural-key match keeps the existing record's id.
	ID string `json:"id,omitempty"`
	// Active deactivates (false) or reactivates (true) an entity or finding.
	// Absent keeps the record's current value; a new record starts active.
	Active *bool `json:"active,omitempty"`

	// Addresses, Hostname, OS, and Tags are host attributes.
	Addresses []string `json:"addresses,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	OS        string   `json:"os,omitempty"`
	Tags      []string `json:"tags,omitempty"`

	// Host, Port, Proto, Product, Version, and State are service attributes.
	Host    string `json:"host,omitempty"`
	Port    int    `json:"port,omitempty"`
	Proto   string `json:"proto,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	State   string `json:"state,omitempty"`

	// Type is a credential's type in an upsert_entity op, and the edge type in
	// an add_edge / remove_edge op. The op name disambiguates it.
	Type string `json:"type,omitempty"`
	// Principal, Secret, Target, Level, Via, Label, and CIDRs are the
	// credential, access, and segment attributes.
	Principal string   `json:"principal,omitempty"`
	Secret    string   `json:"secret,omitempty"`
	Target    string   `json:"target,omitempty"`
	Level     string   `json:"level,omitempty"`
	Via       string   `json:"via,omitempty"`
	Label     string   `json:"label,omitempty"`
	CIDRs     []string `json:"cidrs,omitempty"`

	// Title, Severity, CVSSVector, Status, Confidence, Verification, and
	// Affected are the finding attributes. An absent Status or Verification
	// leaves an existing finding's value alone; a new finding starts detected
	// and unverified.
	Title        string       `json:"title,omitempty"`
	Severity     Severity     `json:"severity,omitempty"`
	CVSSVector   string       `json:"cvss_vector,omitempty"`
	Status       Status       `json:"status,omitempty"`
	Confidence   Confidence   `json:"confidence,omitempty"`
	Verification Verification `json:"verification,omitempty"`
	Affected     []string     `json:"affected,omitempty"`

	// Finding names the finding a set_status, set_verification, or
	// attach_evidence op acts on.
	Finding string `json:"finding,omitempty"`
	// EvidenceKind and Ref are an attach_evidence op's evidence item.
	EvidenceKind EvidenceKind `json:"evidence_kind,omitempty"`
	Ref          string       `json:"ref,omitempty"`

	// From and To are an add_edge / remove_edge op's endpoints (entity ids, or
	// an address or hostname that resolves to a host).
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// Effect is one op's outcome: what it wrote and whether it created or updated
// the record.
type Effect struct {
	// Op is the operation that produced the effect.
	Op OpName `json:"op"`
	// Kind is the record kind: an entity kind, "finding", or "edge".
	Kind string `json:"kind"`
	// ID is the record's id (an edge effect carries its key).
	ID string `json:"id"`
	// Created is true when the op created a new record.
	Created bool `json:"created"`
	// Removed is true when the op removed a record.
	Removed bool `json:"removed,omitempty"`
}

// Receipt is the outcome of one atomic batch (§6, and the parser contract's
// commit shape): the document revision the batch produced and one effect per
// op, in op order.
type Receipt struct {
	// Revision is the document revision after the batch.
	Revision int `json:"revision"`
	// Effects are the per-op outcomes, in order.
	Effects []Effect `json:"effects"`
}

// DecodeOps parses a `state_update` call's ops payload. Unknown fields are
// refused, which is what makes harness-stamped provenance structural: a call
// that tries to supply `source`, `session`, or `time` fails to decode rather
// than having the extra field quietly ignored.
func DecodeOps(raw string) ([]Op, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: ops_json: at least one operation is required", ErrOp)
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.DisallowUnknownFields()

	var ops []Op
	if err := dec.Decode(&ops); err != nil {
		return nil, fmt.Errorf("%w: ops_json: %w", ErrOp, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: ops_json: expected exactly one JSON array of operations", ErrOp)
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("%w: ops_json: at least one operation is required", ErrOp)
	}
	for i, op := range ops {
		if strings.TrimSpace(string(op.Op)) == "" {
			return nil, fmt.Errorf("%w: ops_json[%d]: op is required (%s)", ErrOp, i+1, opNameList())
		}
	}
	return ops, nil
}

// opNameList renders the closed op set for an error message.
func opNameList() string {
	names := make([]string, 0, len(OpNames()))
	for _, name := range OpNames() {
		names = append(names, string(name))
	}
	return strings.Join(names, ", ")
}

// applyOp validates and applies one op to a working copy of the document. It
// is the whole write API: the model, operators, and the parser tools all reach
// state through it, which is what makes "never model-invented" enforceable
// rather than aspirational (§6).
func (s *Store) applyOp(d *document, op Op, prov Provenance) (Effect, error) {
	switch op.Op {
	case OpUpsertEntity:
		return s.upsertEntity(d, op, prov)
	case OpUpsertFinding:
		return s.upsertFinding(d, op, prov, prov.At)
	case OpSetStatus:
		return s.setStatus(d, op, prov)
	case OpAttachEvidence:
		return s.attachEvidence(d, op, prov)
	case OpSetVerification:
		return s.setVerification(d, op, prov)
	case OpAddEdge:
		return s.addEdge(d, op, prov)
	case OpRemoveEdge:
		return s.removeEdge(d, op, prov)
	}
	return Effect{}, fmt.Errorf("%w: unknown op %q (want %s)", ErrOp, op.Op, opNameList())
}

// upsertEntity writes one entity, creating it or reusing the existing id its
// natural key matches (§3).
func (s *Store) upsertEntity(d *document, op Op, prov Provenance) (Effect, error) {
	if !op.Kind.isEntity() {
		if op.Kind == KindFinding {
			return Effect{}, fmt.Errorf("%w: kind finding: findings are written with upsert_finding, not upsert_entity", ErrOp)
		}
		return Effect{}, fmt.Errorf("%w: kind %q: want one of %s", ErrOp, op.Kind, kindList(EntityKinds()))
	}
	now := prov.At
	switch op.Kind {
	case KindHost:
		return s.upsertHost(d, op, prov, now)
	case KindService:
		return s.upsertService(d, op, prov, now)
	case KindCredential:
		return s.upsertCredential(d, op, prov, now)
	case KindAccess:
		return s.upsertAccess(d, op, prov, now)
	case KindSegment:
		return s.upsertSegment(d, op, prov, now)
	}
	return Effect{}, fmt.Errorf("%w: kind %q", ErrOp, op.Kind)
}

// upsertHost writes a host. Its natural key is its primary address — the first
// address declared — and a matching host keeps its id, accumulating any new
// addresses and tags.
func (s *Store) upsertHost(d *document, op Op, prov Provenance, now time.Time) (Effect, error) {
	addrs := dedupeStrings(op.Addresses)
	if len(addrs) == 0 {
		return Effect{}, fmt.Errorf("%w: kind host: addresses: at least one is required (the first is the natural key)", ErrOp)
	}
	for _, addr := range addrs {
		if !validAddress(addr) {
			return Effect{}, fmt.Errorf("%w: kind host: address %q: want an IP literal or a hostname", ErrOp, addr)
		}
	}

	primary := normalizeAddress(addrs[0])
	for i := range d.Entities {
		e := &d.Entities[i]
		if e.Kind != KindHost || len(e.Addresses) == 0 || normalizeAddress(e.Addresses[0]) != primary {
			continue
		}
		e.Addresses = dedupeStrings(append(e.Addresses, addrs...))
		if strings.TrimSpace(op.Hostname) != "" {
			e.Hostname = strings.TrimSpace(op.Hostname)
		}
		if strings.TrimSpace(op.OS) != "" {
			e.OS = strings.TrimSpace(op.OS)
		}
		e.Tags = dedupeStrings(append(e.Tags, op.Tags...))
		applyActive(&e.Active, op.Active)
		e.UpdatedAt, e.Provenance = now, prov
		return Effect{Op: op.Op, Kind: string(KindHost), ID: e.ID}, nil
	}

	id, err := s.recordID(d, KindHost, op.ID)
	if err != nil {
		return Effect{}, err
	}
	e := Entity{
		ID:         id,
		Kind:       KindHost,
		Active:     true,
		CreatedAt:  now,
		UpdatedAt:  now,
		Provenance: prov,
		Addresses:  addrs,
		Hostname:   strings.TrimSpace(op.Hostname),
		OS:         strings.TrimSpace(op.OS),
		Tags:       dedupeStrings(op.Tags),
	}
	applyActive(&e.Active, op.Active)
	d.Entities = append(d.Entities, e)
	return Effect{Op: op.Op, Kind: string(KindHost), ID: e.ID, Created: true}, nil
}

// upsertService writes a service. Its natural key is its host, port, and
// protocol; the host reference must resolve to a recorded host, so a service
// never dangles.
func (s *Store) upsertService(d *document, op Op, prov Provenance, now time.Time) (Effect, error) {
	hostID, err := d.resolveRef(op.Host, []Kind{KindHost}, "host")
	if err != nil {
		return Effect{}, err
	}
	if op.Port <= 0 || op.Port > 65535 {
		return Effect{}, fmt.Errorf("%w: kind service: port %d: want 1-65535", ErrOp, op.Port)
	}
	proto := strings.ToLower(strings.TrimSpace(op.Proto))
	if proto != ProtoTCP && proto != ProtoUDP {
		return Effect{}, fmt.Errorf("%w: kind service: proto %q: want %s or %s", ErrOp, op.Proto, ProtoTCP, ProtoUDP)
	}
	state := strings.ToLower(strings.TrimSpace(op.State))
	if state == "" {
		state = StateOpen
	}
	if state != StateOpen && state != StateClosed && state != StateFiltered {
		return Effect{}, fmt.Errorf("%w: kind service: state %q: want %s, %s, or %s", ErrOp, op.State, StateOpen, StateClosed, StateFiltered)
	}

	for i := range d.Entities {
		e := &d.Entities[i]
		if e.Kind != KindService || e.Host != hostID || e.Port != op.Port || e.Proto != proto {
			continue
		}
		if product := strings.TrimSpace(op.Product); product != "" {
			e.Product = product
		}
		if version := strings.TrimSpace(op.Version); version != "" {
			e.Version = version
		}
		e.State = state
		e.Tags = dedupeStrings(append(e.Tags, op.Tags...))
		applyActive(&e.Active, op.Active)
		e.UpdatedAt, e.Provenance = now, prov
		return Effect{Op: op.Op, Kind: string(KindService), ID: e.ID}, nil
	}

	id, err := s.recordID(d, KindService, op.ID)
	if err != nil {
		return Effect{}, err
	}
	e := Entity{
		ID:         id,
		Kind:       KindService,
		Active:     true,
		CreatedAt:  now,
		UpdatedAt:  now,
		Provenance: prov,
		Host:       hostID,
		Port:       op.Port,
		Proto:      proto,
		Product:    strings.TrimSpace(op.Product),
		Version:    strings.TrimSpace(op.Version),
		State:      state,
		Tags:       dedupeStrings(op.Tags),
	}
	applyActive(&e.Active, op.Active)
	d.Entities = append(d.Entities, e)
	return Effect{Op: op.Op, Kind: string(KindService), ID: e.ID, Created: true}, nil
}

// upsertCredential writes a credential: its type, principal, and secret form
// its natural key, so the same secret for the same principal is one record.
func (s *Store) upsertCredential(d *document, op Op, prov Provenance, now time.Time) (Effect, error) {
	credType := strings.ToLower(strings.TrimSpace(op.Type))
	switch credType {
	case CredentialPassword, CredentialHash, CredentialKey, CredentialToken:
	default:
		return Effect{}, fmt.Errorf("%w: kind credential: type %q: want %s, %s, %s, or %s",
			ErrOp, op.Type, CredentialPassword, CredentialHash, CredentialKey, CredentialToken)
	}
	principal := strings.TrimSpace(op.Principal)
	if principal == "" {
		return Effect{}, fmt.Errorf("%w: kind credential: principal is required", ErrOp)
	}
	secret := strings.TrimSpace(op.Secret)
	if secret == "" {
		return Effect{}, fmt.Errorf("%w: kind credential: secret is required", ErrOp)
	}

	for i := range d.Entities {
		e := &d.Entities[i]
		if e.Kind != KindCredential || e.Type != credType || e.Principal != principal || e.Secret != secret {
			continue
		}
		e.Tags = dedupeStrings(append(e.Tags, op.Tags...))
		applyActive(&e.Active, op.Active)
		e.UpdatedAt, e.Provenance = now, prov
		return Effect{Op: op.Op, Kind: string(KindCredential), ID: e.ID}, nil
	}

	id, err := s.recordID(d, KindCredential, op.ID)
	if err != nil {
		return Effect{}, err
	}
	e := Entity{
		ID:         id,
		Kind:       KindCredential,
		Active:     true,
		CreatedAt:  now,
		UpdatedAt:  now,
		Provenance: prov,
		Type:       credType,
		Principal:  principal,
		Secret:     secret,
		Tags:       dedupeStrings(op.Tags),
	}
	applyActive(&e.Active, op.Active)
	d.Entities = append(d.Entities, e)
	return Effect{Op: op.Op, Kind: string(KindCredential), ID: e.ID, Created: true}, nil
}

// upsertAccess writes a foothold: a principal operating on a target at a
// level. The target must resolve to a recorded host or service; the principal
// is a credential id or a bare account name. A `via` that names a finding
// maintains its EXPLOITED_VIA edge in the same operation, so the mirror field
// and the canonical edge cannot drift (§4).
func (s *Store) upsertAccess(d *document, op Op, prov Provenance, now time.Time) (Effect, error) {
	principal := strings.TrimSpace(op.Principal)
	if principal == "" {
		return Effect{}, fmt.Errorf("%w: kind access: principal is required (a credential ref or an account name)", ErrOp)
	}
	if err := d.checkPrincipal(principal, "access principal"); err != nil {
		return Effect{}, err
	}
	targetID, err := d.resolveRef(op.Target, []Kind{KindHost, KindService}, "target")
	if err != nil {
		return Effect{}, err
	}
	level := strings.ToLower(strings.TrimSpace(op.Level))
	if level == "" {
		level = LevelUser
	}
	if level != LevelUser && level != LevelAdmin && level != LevelSystem {
		return Effect{}, fmt.Errorf("%w: kind access: level %q: want %s, %s, or %s", ErrOp, op.Level, LevelUser, LevelAdmin, LevelSystem)
	}
	via, viaKind, err := d.resolveVia(op.Via)
	if err != nil {
		return Effect{}, err
	}

	for i := range d.Entities {
		e := &d.Entities[i]
		if e.Kind != KindAccess || e.Principal != principal || e.Target != targetID {
			continue
		}
		e.Level = level
		if via != "" {
			e.Via = via
		}
		applyActive(&e.Active, op.Active)
		e.UpdatedAt, e.Provenance = now, prov
		if err := s.mirrorVia(d, *e, via, viaKind, prov); err != nil {
			return Effect{}, err
		}
		return Effect{Op: op.Op, Kind: string(KindAccess), ID: e.ID}, nil
	}

	id, err := s.recordID(d, KindAccess, op.ID)
	if err != nil {
		return Effect{}, err
	}
	e := Entity{
		ID:         id,
		Kind:       KindAccess,
		Active:     true,
		CreatedAt:  now,
		UpdatedAt:  now,
		Provenance: prov,
		Principal:  principal,
		Target:     targetID,
		Level:      level,
		Via:        via,
	}
	applyActive(&e.Active, op.Active)
	d.Entities = append(d.Entities, e)
	if err := s.mirrorVia(d, e, via, viaKind, prov); err != nil {
		return Effect{}, err
	}
	return Effect{Op: op.Op, Kind: string(KindAccess), ID: e.ID, Created: true}, nil
}

// upsertSegment writes a labeled network range; its label is its natural key.
func (s *Store) upsertSegment(d *document, op Op, prov Provenance, now time.Time) (Effect, error) {
	label := strings.TrimSpace(op.Label)
	if label == "" {
		return Effect{}, fmt.Errorf("%w: kind segment: label is required", ErrOp)
	}
	cidrs := dedupeStrings(op.CIDRs)
	if len(cidrs) == 0 {
		return Effect{}, fmt.Errorf("%w: kind segment: cidrs: at least one is required", ErrOp)
	}
	for _, cidr := range cidrs {
		if !validCIDR(cidr) {
			return Effect{}, fmt.Errorf("%w: kind segment: cidr %q: want a CIDR block", ErrOp, cidr)
		}
	}

	for i := range d.Entities {
		e := &d.Entities[i]
		if e.Kind != KindSegment || e.Label != label {
			continue
		}
		e.CIDRs = dedupeStrings(append(e.CIDRs, cidrs...))
		applyActive(&e.Active, op.Active)
		e.UpdatedAt, e.Provenance = now, prov
		return Effect{Op: op.Op, Kind: string(KindSegment), ID: e.ID}, nil
	}

	id, err := s.recordID(d, KindSegment, op.ID)
	if err != nil {
		return Effect{}, err
	}
	e := Entity{
		ID:         id,
		Kind:       KindSegment,
		Active:     true,
		CreatedAt:  now,
		UpdatedAt:  now,
		Provenance: prov,
		Label:      label,
		CIDRs:      cidrs,
	}
	applyActive(&e.Active, op.Active)
	d.Entities = append(d.Entities, e)
	return Effect{Op: op.Op, Kind: string(KindSegment), ID: e.ID, Created: true}, nil
}

// upsertFinding writes a finding. Its natural key is its title plus its
// resolved affected refs; a matching finding keeps its id, its first-seen time,
// and its evidence. Status and verification move only along their legal
// transitions, and verification can never advance past `unverified` without
// evidence (§5).
//
// An omitted status or verification is not a reset: it leaves an existing
// finding's judgement alone, so a parser re-detecting a finding refreshes
// `last_seen` and appends evidence without reopening a `fixed` one or discarding
// a `verified` verdict (docs/parser-tool-contracts.md §8). A new finding still
// starts `detected` and `unverified`.
func (s *Store) upsertFinding(d *document, op Op, prov Provenance, now time.Time) (Effect, error) {
	title := strings.TrimSpace(op.Title)
	if title == "" {
		return Effect{}, fmt.Errorf("%w: upsert_finding: title is required", ErrOp)
	}
	if !op.Severity.valid() {
		return Effect{}, fmt.Errorf("%w: upsert_finding: severity %q: want one of %s", ErrOp, op.Severity, severityList())
	}
	affected, err := d.resolveRefs(op.Affected)
	if err != nil {
		return Effect{}, err
	}
	// Status and verification are optional: a caller that names neither is
	// refreshing an observation, not asserting a judgement. They are applied
	// only when named, so an existing finding keeps what an operator decided.
	status := op.Status
	if status != "" && !status.valid() {
		return Effect{}, fmt.Errorf("%w: upsert_finding: status %q: want one of %s", ErrOp, op.Status, statusList())
	}
	confidence := op.Confidence
	if confidence == "" {
		confidence = ConfidenceLow
	}
	if !confidence.valid() {
		return Effect{}, fmt.Errorf("%w: upsert_finding: confidence %q: want low, medium, or high", ErrOp, op.Confidence)
	}
	verification := op.Verification
	if verification != "" && !verification.valid() {
		return Effect{}, fmt.Errorf("%w: upsert_finding: verification %q: want unverified, verified, or refuted", ErrOp, op.Verification)
	}

	for i := range d.Findings {
		f := &d.Findings[i]
		if f.Title != title || !slices.Equal(sortedCopy(f.Affected), sortedCopy(affected)) {
			continue
		}
		if status != "" && status != f.Status {
			if err := checkTransition(f.Status, status); err != nil {
				return Effect{}, err
			}
			f.Status = status
		}
		if verification != "" && verification != f.Verification {
			if err := checkVerification(verification, len(f.Evidence)); err != nil {
				return Effect{}, err
			}
			f.Verification = verification
		}
		f.Severity = op.Severity
		if vector := strings.TrimSpace(op.CVSSVector); vector != "" {
			f.CVSSVector = vector
		}
		f.Confidence = confidence
		f.LastSeen = now
		f.UpdatedAt, f.Provenance = now, prov
		applyActive(&f.Active, op.Active)
		return Effect{Op: op.Op, Kind: string(KindFinding), ID: f.ID}, nil
	}

	if status == "" {
		status = StatusDetected
	}
	if status != StatusDetected {
		return Effect{}, fmt.Errorf("%w: upsert_finding: a new finding starts %s; use set_status to move it to %s",
			ErrOp, StatusDetected, status)
	}
	if verification == "" {
		verification = VerificationUnverified
	}
	if err := checkVerification(verification, 0); err != nil {
		return Effect{}, err
	}
	id, err := s.recordID(d, KindFinding, op.ID)
	if err != nil {
		return Effect{}, err
	}
	f := Finding{
		ID:           id,
		Active:       true,
		Title:        title,
		Severity:     op.Severity,
		CVSSVector:   strings.TrimSpace(op.CVSSVector),
		Status:       status,
		Confidence:   confidence,
		Verification: verification,
		Affected:     affected,
		FirstSeen:    now,
		LastSeen:     now,
		CreatedAt:    now,
		UpdatedAt:    now,
		Provenance:   prov,
	}
	applyActive(&f.Active, op.Active)
	d.Findings = append(d.Findings, f)
	return Effect{Op: op.Op, Kind: string(KindFinding), ID: f.ID, Created: true}, nil
}

// setStatus advances a finding's status along the §5 lifecycle. Nothing else
// is accepted: the lifecycle is the store's, not the caller's.
func (s *Store) setStatus(d *document, op Op, prov Provenance) (Effect, error) {
	f, err := d.finding(op.Finding)
	if err != nil {
		return Effect{}, err
	}
	if !op.Status.valid() {
		return Effect{}, fmt.Errorf("%w: set_status: status %q: want one of %s", ErrOp, op.Status, statusList())
	}
	if err := checkTransition(f.Status, op.Status); err != nil {
		return Effect{}, err
	}
	f.Status = op.Status
	f.UpdatedAt, f.Provenance = prov.At, prov
	applyActive(&f.Active, op.Active)
	return Effect{Op: op.Op, Kind: string(KindFinding), ID: f.ID}, nil
}

// attachEvidence attaches one evidence item to a finding, stamped with the
// harness's provenance. A caller supplies only the evidence's kind and ref. The
// finding resolves by id, or — for a harness-side batch that cannot know the id
// of a record it did not mint — by title, disambiguated by the op's affected
// refs (§8 of docs/parser-tool-contracts.md).
func (s *Store) attachEvidence(d *document, op Op, prov Provenance) (Effect, error) {
	f, err := d.findingForEvidence(op.Finding, op.Affected)
	if err != nil {
		return Effect{}, err
	}
	if !op.EvidenceKind.valid() {
		return Effect{}, fmt.Errorf("%w: attach_evidence: evidence_kind %q: want one of %s", ErrOp, op.EvidenceKind, evidenceKindList())
	}
	ref := strings.TrimSpace(op.Ref)
	if ref == "" {
		return Effect{}, fmt.Errorf("%w: attach_evidence: ref is required (an artifact path or an inline excerpt)", ErrOp)
	}
	f.Evidence = append(f.Evidence, Evidence{Kind: op.EvidenceKind, Ref: ref, Provenance: prov})
	f.UpdatedAt, f.Provenance = prov.At, prov
	return Effect{Op: op.Op, Kind: string(KindFinding), ID: f.ID}, nil
}

// setVerification sets a finding's verification state. `verified` and
// `refuted` are refused until at least one evidence item exists: a finding
// without evidence is unvalidated, always (§5).
func (s *Store) setVerification(d *document, op Op, prov Provenance) (Effect, error) {
	f, err := d.finding(op.Finding)
	if err != nil {
		return Effect{}, err
	}
	if !op.Verification.valid() {
		return Effect{}, fmt.Errorf("%w: set_verification: verification %q: want unverified, verified, or refuted", ErrOp, op.Verification)
	}
	if err := checkVerification(op.Verification, len(f.Evidence)); err != nil {
		return Effect{}, err
	}
	f.Verification = op.Verification
	f.UpdatedAt, f.Provenance = prov.At, prov
	applyActive(&f.Active, op.Active)
	return Effect{Op: op.Op, Kind: string(KindFinding), ID: f.ID}, nil
}

// addEdge writes one relationship-graph edge. Endpoints are validated against
// the closed per-type table and must resolve to recorded nodes, so an edge
// never dangles (§4).
func (s *Store) addEdge(d *document, op Op, prov Provenance) (Effect, error) {
	edgeType := EdgeType(strings.TrimSpace(op.Type))
	if !edgeType.valid() {
		return Effect{}, fmt.Errorf("%w: add_edge: type %q: want one of %s", ErrOp, op.Type, edgeTypeList())
	}
	from, to, err := d.resolveEndpoints(edgeType, op.From, op.To)
	if err != nil {
		return Effect{}, err
	}
	confidence := op.Confidence
	if confidence == "" {
		confidence = ConfidenceLow
	}
	if !confidence.valid() {
		return Effect{}, fmt.Errorf("%w: add_edge: confidence %q: want low, medium, or high", ErrOp, op.Confidence)
	}

	for i := range d.Edges {
		e := &d.Edges[i]
		if e.Type != edgeType || e.From != from || e.To != to {
			continue
		}
		e.Confidence = confidence
		e.UpdatedAt, e.Provenance = prov.At, prov
		return Effect{Op: op.Op, Kind: "edge", ID: e.Key()}, nil
	}

	now := prov.At
	edge := Edge{
		Type:       edgeType,
		From:       from,
		To:         to,
		Confidence: confidence,
		CreatedAt:  now,
		UpdatedAt:  now,
		Provenance: prov,
	}
	d.Edges = append(d.Edges, edge)
	if edgeType == EdgeExploitedVia {
		if idx := d.findEntity(to); idx >= 0 {
			d.Entities[idx].Via = from
			d.Entities[idx].UpdatedAt = now
			d.Entities[idx].Provenance = prov
		}
	}
	return Effect{Op: op.Op, Kind: "edge", ID: edge.Key(), Created: true}, nil
}

// removeEdge removes one edge by type and endpoints. When the removed edge was
// the access.via mirror's source, the mirror is cleared with it (§4).
func (s *Store) removeEdge(d *document, op Op, prov Provenance) (Effect, error) {
	edgeType := EdgeType(strings.TrimSpace(op.Type))
	if !edgeType.valid() {
		return Effect{}, fmt.Errorf("%w: remove_edge: type %q: want one of %s", ErrOp, op.Type, edgeTypeList())
	}
	from, to, err := d.resolveEndpoints(edgeType, op.From, op.To)
	if err != nil {
		return Effect{}, err
	}
	key := string(edgeType) + "|" + from + "|" + to
	for i, e := range d.Edges {
		if e.Key() != key {
			continue
		}
		d.Edges = append(d.Edges[:i], d.Edges[i+1:]...)
		if edgeType == EdgeExploitedVia {
			if idx := d.findEntity(to); idx >= 0 && d.Entities[idx].Via == from {
				d.Entities[idx].Via = ""
				d.Entities[idx].UpdatedAt = prov.At
				d.Entities[idx].Provenance = prov
			}
		}
		return Effect{Op: op.Op, Kind: "edge", ID: key, Removed: true}, nil
	}
	return Effect{}, fmt.Errorf("%w: remove_edge: %s %s -> %s is not recorded", ErrNotFound, edgeType, from, to)
}

// mirrorVia keeps an access entity's `via` mirror in step with its canonical
// EXPLOITED_VIA edge (§4). The closed endpoint table allows that edge to run
// finding → access, so a finding reference derives one; a credential
// reference is recorded on the entity alone, because CREDENTIAL_FROM's target
// is a host, service, or finding — never an access.
func (s *Store) mirrorVia(d *document, access Entity, via string, viaKind Kind, prov Provenance) error {
	if via == "" || viaKind != KindFinding {
		return nil
	}
	if idx := d.findEdge(string(EdgeExploitedVia) + "|" + via + "|" + access.ID); idx >= 0 {
		return nil
	}
	from, to, err := d.resolveEndpoints(EdgeExploitedVia, via, access.ID)
	if err != nil {
		return err
	}
	now := prov.At
	d.Edges = append(d.Edges, Edge{
		Type:       EdgeExploitedVia,
		From:       from,
		To:         to,
		Confidence: ConfidenceMedium,
		CreatedAt:  now,
		UpdatedAt:  now,
		Provenance: prov,
	})
	return nil
}

// applyActive applies an op's optional active flag: absent keeps the record's
// value, present sets it.
func applyActive(active *bool, set *bool) {
	if set != nil {
		*active = *set
	}
}

// checkTransition enforces the §5 status lifecycle.
func checkTransition(from, to Status) error {
	if from == to {
		return nil
	}
	if slices.Contains(statusTransitions[from], to) {
		return nil
	}
	return fmt.Errorf("%w: status %s -> %s: the lifecycle allows %s -> %s", ErrOp, from, to, from, transitionsFrom(from))
}

// checkVerification enforces the evidence-before-verified invariant.
func checkVerification(v Verification, evidence int) error {
	if v == VerificationVerified || v == VerificationRefuted {
		if evidence == 0 {
			return fmt.Errorf("%w: verification %q requires at least one evidence item; attach evidence first", ErrOp, v)
		}
	}
	return nil
}

// valid reports whether a severity is in the closed set.
func (s Severity) valid() bool { return slices.Contains(severities, s) }

// valid reports whether a confidence is in the closed set.
func (c Confidence) valid() bool {
	return c == ConfidenceLow || c == ConfidenceMedium || c == ConfidenceHigh
}

// valid reports whether a verification state is in the closed set.
func (v Verification) valid() bool {
	return v == VerificationUnverified || v == VerificationVerified || v == VerificationRefuted
}

// valid reports whether an evidence kind is in the closed set.
func (e EvidenceKind) valid() bool { return slices.Contains(evidenceKinds, e) }

// severityList renders the severity enum for an error message.
func severityList() string {
	names := make([]string, 0, len(severities))
	for _, s := range severities {
		names = append(names, string(s))
	}
	return strings.Join(names, ", ")
}

// statusList renders the status enum for an error message.
func statusList() string {
	names := make([]string, 0, len(statusTransitions))
	for _, s := range []Status{StatusDetected, StatusConfirmed, StatusFalsePositive, StatusFixed, StatusRiskAccepted} {
		names = append(names, string(s))
	}
	return strings.Join(names, ", ")
}

// evidenceKindList renders the evidence-kind enum for an error message.
func evidenceKindList() string {
	names := make([]string, 0, len(evidenceKinds))
	for _, k := range evidenceKinds {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}

// edgeTypeList renders the closed edge enum for an error message.
func edgeTypeList() string {
	names := make([]string, 0, len(EdgeTypes()))
	for _, t := range EdgeTypes() {
		names = append(names, string(t))
	}
	return strings.Join(names, ", ")
}

// sortedCopy returns a sorted copy, for order-insensitive set comparison.
func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	slices.Sort(out)
	return out
}
