package engagementstate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Refusal kinds. Every rejection wraps exactly one of these, so callers and
// tests branch on the kind of refusal rather than on message text.
var (
	// ErrOp is an operation the store refuses: an unknown op, a missing or
	// malformed field, an out-of-enum value, an unresolvable reference, or a
	// status/verification transition the lifecycle does not allow.
	ErrOp = errors.New("engagementstate: invalid operation")
	// ErrNotFound is a reference to a record the store does not hold.
	ErrNotFound = errors.New("engagementstate: not found")
	// ErrVersion is a document whose schema version this build does not read.
	// It refuses loudly, naming the file; v1 has no automatic migration.
	ErrVersion = errors.New("engagementstate: incompatible schema version")
	// ErrLocked is a write to an engagement another session holds: a second
	// session may read, but only one session writes.
	ErrLocked = errors.New("engagementstate: engagement state is locked")
)

// DefaultQueryLimit caps a `state_query` result's node count when the caller
// names no limit.
const DefaultQueryLimit = 200

// maxQueryLimit is the largest limit a caller may name. A read of a forensic
// record stays bounded; the digest, not a giant listing, is how the model
// keeps a working view.
const maxQueryLimit = 1000

// lockFile is the advisory lock's name inside an engagement's directory.
const lockFile = ".lock"

// Option configures a Store at Open.
type Option func(*Store)

// WithRoot replaces the store root (§1). An empty root uses DefaultRoot.
func WithRoot(dir string) Option {
	return func(s *Store) {
		if strings.TrimSpace(dir) != "" {
			s.root = dir
		}
	}
}

// WithClock replaces the store's clock: it stamps provenance and the document
// revision time. Tests pin it; production uses time.Now.
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// WithSession records the session id this store writes for. It is provenance,
// never caller-supplied: the model has no way to name a session.
func WithSession(id string) Option {
	return func(s *Store) { s.session = strings.TrimSpace(id) }
}

// WithIDSource replaces the identifier generator. Tests pin it so ids are
// predictable; production mints a random 4-hex suffix per kind.
func WithIDSource(mint func(kind Kind) (string, error)) Option {
	return func(s *Store) {
		if mint != nil {
			s.mint = mint
		}
	}
}

// Store is one engagement's state document. It is safe for concurrent use: one
// process writes at a time (the lockfile) and the in-process mutex serializes
// its callers.
type Store struct {
	root       string
	path       string
	dir        string
	project    string
	engagement string
	session    string

	now  func() time.Time
	mint func(kind Kind) (string, error)

	mu       sync.Mutex
	doc      *document
	writable bool
	holder   string
	closed   bool

	// lastDigest is the document revision the previous digest rendered, and
	// lastCounts the per-kind counts it reported, so the next digest can carry
	// deltas (§8). -1 means no digest has been rendered yet: the first read
	// after activation is always due.
	lastDigest int
	lastCounts map[string]int
}

// DefaultRoot is the engagement-state store root (§1, §10.4):
// $XDG_DATA_HOME/styx/engagements, else ~/.local/share/styx/engagements —
// alongside the session store, never inside the repo. It returns "" when no
// home directory is known.
func DefaultRoot() string {
	if dir := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dir != "" {
		return filepath.Join(dir, "styx", "engagements")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "share", "styx", "engagements")
}

// Open loads — or initializes — the state store for one engagement:
// <root>/<project>/<engagement>/state.json (§1). A document whose schema
// version this build does not read refuses loudly, naming the file. A store
// whose engagement another live session holds opens read-only: reads work,
// writes fail with a clear locked error rather than clobbering a forensic
// record.
func Open(projectDir, engagementName string, opts ...Option) (*Store, error) {
	s := &Store{
		root:       DefaultRoot(),
		engagement: strings.TrimSpace(engagementName),
		now:        time.Now,
		mint:       randomID,
		writable:   true,
		lastDigest: -1,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.engagement == "" {
		return nil, errors.New("engagementstate: an engagement name is required")
	}
	if strings.TrimSpace(s.root) == "" {
		return nil, errors.New("engagementstate: no state root (no home directory)")
	}

	s.project = projectComponent(projectDir)
	s.dir = filepath.Join(s.root, s.project, engagementComponent(s.engagement))
	s.path = filepath.Join(s.dir, "state.json")

	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("engagementstate: create %s: %w", s.dir, err)
	}
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	s.doc = doc

	if err := s.acquireLock(); err != nil {
		return nil, err
	}
	return s, nil
}

// load reads the document, or returns a fresh one when the engagement has no
// record yet.
func (s *Store) load() (*document, error) {
	//nolint:gosec // the path is derived from the store root and a sanitized name.
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return newDocument(s.project, s.engagement), nil
		}
		return nil, fmt.Errorf("engagementstate: read %s: %w", s.path, err)
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("engagementstate: %s: %w", s.path, err)
	}
	if doc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: %s declares schema_version %d; this build reads %d",
			ErrVersion, s.path, doc.SchemaVersion, SchemaVersion)
	}
	if doc.Entities == nil {
		doc.Entities = []Entity{}
	}
	if doc.Findings == nil {
		doc.Findings = []Finding{}
	}
	if doc.Edges == nil {
		doc.Edges = []Edge{}
	}
	return &doc, nil
}

// lockRecord is the lockfile's content: who holds the engagement's write lock.
type lockRecord struct {
	PID     int       `json:"pid"`
	Session string    `json:"session,omitempty"`
	At      time.Time `json:"at"`
}

// acquireLock claims the engagement's write lock. A live holder leaves the
// store readable but not writable; a stale holder (a process that is gone) is
// reclaimed.
func (s *Store) acquireLock() error {
	path := filepath.Join(s.dir, lockFile)
	for attempt := 0; attempt < 2; attempt++ {
		//nolint:gosec // the path is derived from the store root.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			record := lockRecord{PID: os.Getpid(), Session: s.session, At: s.now().UTC()}
			encoded, encErr := json.Marshal(record)
			if encErr == nil {
				_, encErr = f.Write(encoded)
			}
			closeErr := f.Close()
			if encErr != nil || closeErr != nil {
				_ = os.Remove(path)
				return errors.Join(encErr, closeErr)
			}
			return nil
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("engagementstate: lock %s: %w", path, err)
		}

		holder, readErr := readLock(path)
		if readErr != nil {
			// An unreadable lockfile is not a holder we can honor: treat it as
			// stale rather than blocking every future session on it.
			_ = os.Remove(path)
			continue
		}
		if processAlive(holder.PID) && !s.ownsLock(holder) {
			s.writable = false
			s.holder = describeHolder(holder)
			return nil
		}
		// A stale lock (the holder is gone, or it is this process's own
		// leftover) is reclaimed: the record it protected is not being written.
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("engagementstate: reclaim stale lock %s: %w", path, removeErr)
		}
	}
	s.writable = false
	s.holder = "another session"
	return nil
}

// readLock reads a lockfile's holder.
func readLock(path string) (lockRecord, error) {
	//nolint:gosec // the path is derived from the store root.
	data, err := os.ReadFile(path)
	if err != nil {
		return lockRecord{}, err
	}
	var record lockRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return lockRecord{}, err
	}
	return record, nil
}

// ownsLock reports whether a lockfile describes this store's own session: the
// same process and the same session id. A lock this very process holds for a
// different session belongs to another store and is honored like any other,
// while a leftover from this session's own earlier store is reclaimable.
func (s *Store) ownsLock(record lockRecord) bool {
	return record.PID == os.Getpid() && record.Session == s.session
}

// describeHolder renders a lock holder for the locked error and the digest.
func describeHolder(record lockRecord) string {
	who := "pid " + fmt.Sprint(record.PID)
	if record.Session != "" {
		who = "session " + record.Session + " (pid " + fmt.Sprint(record.PID) + ")"
	}
	return who
}

// processAlive reports whether a pid names a running process. Signal 0
// performs the permission and existence check without delivering anything: a
// nil error means the process exists, EPERM means it exists under another user
// (still alive), and anything else means it is gone.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.EPERM)
}

// Path is the document's file path. The store holds credentials and loot, so
// it lives outside the repo by construction (§1).
func (s *Store) Path() string { return s.path }

// Engagement is the engagement the store belongs to.
func (s *Store) Engagement() string { return s.engagement }

// Writable reports whether this session holds the engagement's write lock. A
// read-only store still serves every read.
func (s *Store) Writable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writable
}

// Holder reports who holds the write lock when this store does not: "session
// 20261019T101010Z-abcd (pid 4242)", or "" when this store may write.
func (s *Store) Holder() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.holder
}

// Close releases the write lock. It is idempotent, and a store that never held
// the lock releases nothing.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if !s.writable {
		return nil
	}
	path := filepath.Join(s.dir, lockFile)
	holder, err := readLock(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("engagementstate: release lock %s: %w", path, err)
	}
	if !s.ownsLock(holder) {
		// Another session owns the lock now; leave its lock alone.
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("engagementstate: release lock %s: %w", path, err)
	}
	return nil
}

// Snapshot returns the whole document as the read shape, deep-copied. It is
// the projection the attack-path computation consumes: complete, unfiltered,
// and never truncated.
func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	return s.doc.snapshot()
}

// refreshLocked re-reads the document for a read-only store, so a second
// session's reads follow the writer's commits instead of freezing at open
// time. A writer never needs it: its own in-memory document is authoritative,
// and re-reading would discard a batch it is in the middle of applying. A
// document that fails to load leaves the last good read in place rather than
// blanking what the session already knows.
func (s *Store) refreshLocked() {
	if s.writable || s.closed {
		return
	}
	doc, err := s.load()
	if err != nil {
		return
	}
	s.doc = doc
}

// Update applies one batch of typed ops atomically (§6): the working copy is
// validated and mutated, and only a fully valid batch is committed and written.
// A batch that fails anywhere writes nothing — not even the ops that preceded
// the failure — which is what makes the parser contract's commit shape true.
//
// Every mutation is stamped with the harness's provenance: the caller names the
// writing tool and subagent; the store stamps the session and the time.
func (s *Store) Update(ctx context.Context, origin Origin, ops []Op) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if len(ops) == 0 {
		return Receipt{}, fmt.Errorf("%w: at least one operation is required", ErrOp)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Receipt{}, errors.New("engagementstate: the store is closed")
	}
	if !s.writable {
		return Receipt{}, fmt.Errorf("%w: held by %s; this session can read but not write", ErrLocked, s.holder)
	}

	prov := Provenance{
		Source:   origin.Tool,
		Subagent: origin.Subagent,
		Session:  s.session,
		At:       s.now().UTC(),
	}

	work := s.doc.clone()
	receipt := Receipt{Effects: make([]Effect, 0, len(ops))}
	for i, op := range ops {
		effect, err := s.applyOp(work, op, prov)
		if err != nil {
			return Receipt{}, fmt.Errorf("ops_json[%d]: %w", i+1, err)
		}
		receipt.Effects = append(receipt.Effects, effect)
	}

	work.Revision++
	work.UpdatedAt = prov.At
	receipt.Revision = work.Revision

	if err := s.save(work); err != nil {
		// The batch did not land: the in-memory document stays exactly what is
		// on disk, so a caller that saw an error never sees a phantom write.
		return Receipt{}, err
	}
	s.doc = work
	return receipt, nil
}

// save writes the document atomically: a temp file in the same directory, then
// a rename over the target (§1). A crash leaves either the old document or the
// new one, never a torn one.
func (s *Store) save(doc *document) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("engagementstate: encode %s: %w", s.path, err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(s.dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("engagementstate: create temp file in %s: %w", s.dir, err)
	}
	name := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("engagementstate: write %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("engagementstate: sync %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("engagementstate: close %s: %w", name, err)
	}
	if err := os.Rename(name, s.path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("engagementstate: commit %s: %w", s.path, err)
	}
	return nil
}

// Query answers a structured read (§6): filters over kinds and attributes,
// listing, and 1–2-hop neighborhood reads. It never mutates the document.
func (s *Store) Query(q Query) (Snapshot, error) {
	if q.Kind != "" && !q.Kind.valid() {
		return Snapshot{}, fmt.Errorf("%w: kind %q: want %s", ErrOp, q.Kind, kindList(QueryKinds()))
	}
	if q.Hops < 0 || q.Hops > 2 {
		return Snapshot{}, fmt.Errorf("%w: hops %d: want 0, 1, or 2", ErrOp, q.Hops)
	}
	if q.Limit < 0 {
		return Snapshot{}, fmt.Errorf("%w: limit %d: must not be negative", ErrOp, q.Limit)
	}
	if err := checkFilters(q.Where); err != nil {
		return Snapshot{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	return s.doc.query(q)
}

// query applies one read to a document. It assumes the query is validated.
func (d *document) query(q Query) (Snapshot, error) {
	selected := map[string]bool{}
	var order []string

	add := func(id string) {
		if !selected[id] {
			selected[id] = true
			order = append(order, id)
		}
	}

	switch {
	case q.ID != "":
		if _, ok := d.nodeKind(q.ID); !ok {
			return Snapshot{}, fmt.Errorf("%w: no entity or finding with id %q", ErrNotFound, q.ID)
		}
		add(q.ID)
	default:
		for _, e := range d.Entities {
			if q.Kind != "" && e.Kind != q.Kind {
				continue
			}
			if !q.IncludeInactive && !e.Active {
				continue
			}
			if !matchesEntity(e, q.Where) {
				continue
			}
			add(e.ID)
		}
		for _, f := range d.Findings {
			if q.Kind != "" && q.Kind != KindFinding {
				continue
			}
			if !q.IncludeInactive && !f.Active {
				continue
			}
			if !matchesFinding(f, q.Where) {
				continue
			}
			add(f.ID)
		}
	}

	// Neighborhood reads expand the selection over the graph, in both
	// directions: an edge's provenance direction is not an action direction.
	included := map[string]bool{}
	for _, id := range order {
		included[id] = true
	}
	if q.Hops > 0 {
		frontier := append([]string(nil), order...)
		for hop := 0; hop < q.Hops; hop++ {
			var next []string
			for _, id := range frontier {
				for _, edge := range d.Edges {
					var neighbor string
					switch {
					case edge.From == id:
						neighbor = edge.To
					case edge.To == id:
						neighbor = edge.From
					default:
						continue
					}
					if included[neighbor] {
						continue
					}
					if !q.IncludeInactive && !d.nodeActive(neighbor) {
						continue
					}
					included[neighbor] = true
					next = append(next, neighbor)
				}
			}
			frontier = next
			if len(frontier) == 0 {
				break
			}
		}
	}

	snap := Snapshot{
		SchemaVersion: d.SchemaVersion,
		Revision:      d.Revision,
		Entities:      []Entity{},
		Findings:      []Finding{},
		Edges:         []Edge{},
	}
	// Node ids are room-ordered so the limit cuts a stable result, then the
	// reported order is sorted for the reader.
	ids := make([]string, 0, len(included))
	ids = append(ids, order...)
	for id := range included {
		if !slices.Contains(order, id) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)

	limit := q.Limit
	if limit == 0 {
		limit = DefaultQueryLimit
	}
	if limit > maxQueryLimit {
		limit = maxQueryLimit
	}
	for _, id := range ids {
		if len(snap.Entities)+len(snap.Findings) >= limit {
			snap.Truncated = true
			break
		}
		if i := d.findEntity(id); i >= 0 {
			e := d.Entities[i]
			e.Addresses = append([]string(nil), e.Addresses...)
			e.Tags = append([]string(nil), e.Tags...)
			e.CIDRs = append([]string(nil), e.CIDRs...)
			snap.Entities = append(snap.Entities, e)
			continue
		}
		if i := d.findFinding(id); i >= 0 {
			f := d.Findings[i]
			f.Evidence = append([]Evidence(nil), f.Evidence...)
			f.Affected = append([]string(nil), f.Affected...)
			snap.Findings = append(snap.Findings, f)
		}
	}

	for _, edge := range d.Edges {
		if included[edge.From] && included[edge.To] {
			snap.Edges = append(snap.Edges, edge)
		}
	}
	return snap, nil
}

// clone deep-copies the document: an atomic batch is applied to a copy, so a
// failed batch leaves the committed document untouched.
func (d *document) clone() *document {
	out := &document{
		SchemaVersion: d.SchemaVersion,
		Engagement:    d.Engagement,
		Project:       d.Project,
		Revision:      d.Revision,
		UpdatedAt:     d.UpdatedAt,
		Entities:      make([]Entity, 0, len(d.Entities)),
		Findings:      make([]Finding, 0, len(d.Findings)),
		Edges:         make([]Edge, 0, len(d.Edges)),
	}
	for _, e := range d.Entities {
		e.Addresses = append([]string(nil), e.Addresses...)
		e.Tags = append([]string(nil), e.Tags...)
		e.CIDRs = append([]string(nil), e.CIDRs...)
		out.Entities = append(out.Entities, e)
	}
	for _, f := range d.Findings {
		f.Evidence = append([]Evidence(nil), f.Evidence...)
		f.Affected = append([]string(nil), f.Affected...)
		out.Findings = append(out.Findings, f)
	}
	out.Edges = append(out.Edges, d.Edges...)
	return out
}

// newID mints a stable identifier for a new record: "<kind>-<4 hex>" (§3),
// retried on the (astronomically unlikely) collision.
func (s *Store) newID(d *document, kind Kind) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		id, err := s.mint(kind)
		if err != nil {
			return "", fmt.Errorf("engagementstate: mint %s id: %w", kind, err)
		}
		if id == "" {
			return "", errors.New("engagementstate: the id source produced an empty identifier")
		}
		if _, taken := d.nodeKind(id); !taken {
			return id, nil
		}
	}
	return "", fmt.Errorf("engagementstate: cannot mint a free %s id", kind)
}

// randomID is the production identifier source: two random bytes rendered as
// four hex characters, prefixed by the record kind.
func randomID(kind Kind) (string, error) {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return string(kind) + "-" + hex.EncodeToString(buf[:]), nil
}

// resolveRef resolves a reference to a recorded node's id. An id must exist and
// name one of the wanted kinds; an address or hostname resolves to the host it
// names. Anything else is refused: a reference that cannot resolve would leave
// a dangling field or edge behind.
func (d *document) resolveRef(ref string, want []Kind, what string) (string, error) {
	raw := strings.TrimSpace(ref)
	if raw == "" {
		return "", fmt.Errorf("%w: %s reference is required", ErrOp, what)
	}
	if kind, ok := d.nodeKind(raw); ok {
		if !slices.Contains(want, kind) {
			return "", fmt.Errorf("%w: %s %q names a %s; want %s", ErrOp, what, raw, kind, kindList(want))
		}
		return raw, nil
	}
	if slices.Contains(want, KindHost) {
		if host, ok := d.findHostByAddress(raw); ok {
			return host.ID, nil
		}
	}
	return "", fmt.Errorf("%w: %s %q does not resolve to %s; record it in the same batch first",
		ErrOp, what, raw, kindList(want))
}

// resolveRefs resolves a list of host/service references, dropping duplicates
// and preserving order.
func (d *document) resolveRefs(refs []string) ([]string, error) {
	var out []string
	for _, ref := range refs {
		id, err := d.resolveRef(ref, []Kind{KindHost, KindService}, "affected")
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out, nil
}

// resolveVia resolves an access `via` reference: a harness id of a finding or
// credential. Empty is resolved to nothing, which is not an error — `via` is
// optional.
func (d *document) resolveVia(ref string) (string, Kind, error) {
	raw := strings.TrimSpace(ref)
	if raw == "" {
		return "", "", nil
	}
	kind, ok := d.nodeKind(raw)
	if !ok {
		return "", "", fmt.Errorf("%w: via %q: want a finding or credential id", ErrOp, raw)
	}
	if kind != KindFinding && kind != KindCredential {
		return "", "", fmt.Errorf("%w: via %q names a %s; want a finding or credential", ErrOp, raw, kind)
	}
	return raw, kind, nil
}

// checkPrincipal validates an access principal: a credential id, or a bare
// account name. A value that names a recorded node of another kind is refused,
// so an id-looking principal can never silently mean a host.
func (d *document) checkPrincipal(principal, what string) error {
	kind, ok := d.nodeKind(principal)
	if !ok {
		return nil
	}
	if kind != KindCredential {
		return fmt.Errorf("%w: %s %q names a %s; want a credential id or an account name", ErrOp, what, principal, kind)
	}
	return nil
}

// resolveEndpoints validates an edge's endpoints against the closed per-type
// table (§4) and resolves them to recorded node ids.
func (d *document) resolveEndpoints(edgeType EdgeType, from, to string) (string, string, error) {
	table, ok := endpoints[edgeType]
	if !ok {
		return "", "", fmt.Errorf("%w: edge type %q: want one of %s", ErrOp, edgeType, edgeTypeList())
	}
	fromID, err := d.resolveRef(from, table.from, "from")
	if err != nil {
		return "", "", err
	}
	toID, err := d.resolveRef(to, table.to, "to")
	if err != nil {
		return "", "", err
	}
	return fromID, toID, nil
}

// finding resolves a finding reference to its record.
func (d *document) finding(ref string) (*Finding, error) {
	raw := strings.TrimSpace(ref)
	if raw == "" {
		return nil, fmt.Errorf("%w: finding: a finding id is required", ErrOp)
	}
	if i := d.findFinding(raw); i >= 0 {
		return &d.Findings[i], nil
	}
	return nil, fmt.Errorf("%w: no finding with id %q", ErrNotFound, raw)
}

// findHostByAddress resolves an address or hostname to the host that records
// it.
func (d *document) findHostByAddress(ref string) (Entity, bool) {
	want := normalizeAddress(ref)
	for _, e := range d.Entities {
		if e.Kind != KindHost {
			continue
		}
		for _, addr := range e.Addresses {
			if normalizeAddress(addr) == want {
				return e, true
			}
		}
		if e.Hostname != "" && normalizeAddress(e.Hostname) == want {
			return e, true
		}
	}
	return Entity{}, false
}

// projectComponent is the per-project directory name (§1): the directory's base
// name plus a short hash of its absolute path, so two checkouts named alike
// never share a state store.
func projectComponent(projectDir string) string {
	abs, err := filepath.Abs(projectDir)
	if err != nil {
		abs = projectDir
	}
	sum := sha256.Sum256([]byte(filepath.Clean(abs)))
	return sanitizeComponent(filepath.Base(filepath.Clean(abs))) + "-" + hex.EncodeToString(sum[:4])
}

// engagementComponent is the per-engagement directory name (§1). It always
// carries a short hash of the declared name, so two engagements whose names
// differ only in characters a file name cannot hold never share a document.
func engagementComponent(name string) string {
	sum := sha256.Sum256([]byte(name))
	return sanitizeComponent(name) + "-" + hex.EncodeToString(sum[:4])
}

// sanitizeComponent reduces a value to characters safe in a file name.
func sanitizeComponent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "engagement"
	}
	return out
}

// filterKeys is the closed attribute-filter vocabulary of a `state_query`
// read. An unknown key is refused with the vocabulary, never silently matched
// against nothing.
// A credential's secret is deliberately absent: it is never a predicate a
// caller may filter on, which keeps secret material out of prompt-visible
// arguments as well as out of rendered results.
var filterKeys = []string{
	"id", "kind", "active",
	"address", "hostname", "os", "host", "port", "proto", "product", "version",
	"state", "type", "principal", "target", "level", "via", "tag",
	"label", "cidr",
	"title", "severity", "status", "confidence", "verification", "evidence",
	"source", "session",
}

// checkFilters validates a query's filter keys.
func checkFilters(where map[string]string) error {
	for _, key := range sortedKeys(where) {
		if !slices.Contains(filterKeys, key) {
			return fmt.Errorf("%w: where %q: want one of %s", ErrOp, key, strings.Join(filterKeys, ", "))
		}
	}
	return nil
}

// sortedKeys returns a map's keys in a stable order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// matchesEntity applies a query's filters to one entity.
func matchesEntity(e Entity, where map[string]string) bool {
	for key, want := range where {
		var got []string
		switch key {
		case "id":
			got = []string{e.ID}
		case "kind":
			got = []string{string(e.Kind)}
		case "active":
			got = []string{fmt.Sprint(e.Active)}
		case "address":
			got = e.Addresses
		case "hostname":
			got = []string{e.Hostname}
		case "os":
			got = []string{e.OS}
		case "host":
			got = []string{e.Host}
		case "port":
			got = []string{fmt.Sprint(e.Port)}
		case "proto":
			got = []string{e.Proto}
		case "product":
			got = []string{e.Product}
		case "version":
			got = []string{e.Version}
		case "state":
			got = []string{e.State}
		case "type":
			got = []string{e.Type}
		case "principal":
			got = []string{e.Principal}
		case "target":
			got = []string{e.Target}
		case "level":
			got = []string{e.Level}
		case "via":
			got = []string{e.Via}
		case "tag":
			got = e.Tags
		case "label":
			got = []string{e.Label}
		case "cidr":
			got = e.CIDRs
		case "source":
			got = []string{e.Provenance.Source}
		case "session":
			got = []string{e.Provenance.Session}
		default:
			return false
		}
		if !matchesAny(got, want) {
			return false
		}
	}
	return true
}

// matchesFinding applies a query's filters to one finding.
func matchesFinding(f Finding, where map[string]string) bool {
	for key, want := range where {
		var got []string
		switch key {
		case "id":
			got = []string{f.ID}
		case "kind":
			got = []string{string(KindFinding)}
		case "active":
			got = []string{fmt.Sprint(f.Active)}
		case "title":
			got = []string{f.Title}
		case "severity":
			got = []string{string(f.Severity)}
		case "status":
			got = []string{string(f.Status)}
		case "confidence":
			got = []string{string(f.Confidence)}
		case "verification":
			got = []string{string(f.Verification)}
		case "target", "host", "address":
			got = f.Affected
		case "evidence":
			for _, item := range f.Evidence {
				got = append(got, item.Ref)
			}
		case "source":
			got = []string{f.Provenance.Source}
		case "session":
			got = []string{f.Provenance.Session}
		default:
			return false
		}
		if !matchesAny(got, want) {
			return false
		}
	}
	return true
}

// matchesAny reports whether any candidate equals the wanted value, compared
// case-insensitively: enum and address spellings differ across tools, and a
// filter that missed on capitalization would read as "no such record".
func matchesAny(candidates []string, want string) bool {
	wanted := strings.ToLower(strings.TrimSpace(want))
	for _, candidate := range candidates {
		if strings.ToLower(strings.TrimSpace(candidate)) == wanted {
			return true
		}
	}
	return false
}
