package apispec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// ToolName is the tool the loader backs. One tool, one schema, one loader for
// every accepted format (§2.1).
const ToolName = "api_spec_load"

// Limits (§7). The document is read under a hard ceiling and the load is
// bounded by a wall clock, matching read_file and the parsers.
const (
	// MaxDocumentBytes is the largest document a load reads.
	MaxDocumentBytes = 4 << 20 // 4 MiB
	// LoadTimeout bounds one load's wall clock.
	LoadTimeout = 30 * time.Second
	// InventoryDir is the derived artifact directory (§4.2): gitignored with
	// the rest of .styx/, rewritten per load, and outside the pending-parse
	// watch.
	InventoryDir = ".styx/out/api"
	// declaredTag marks a host the document declared rather than a scan
	// observed (ADR-0014).
	declaredTag = "declared"
	// maxRefused, maxUnresolved, maxSkipped, and maxWarnings bound a receipt's
	// rows; the receipt is truncated at capture like any tool output, and an
	// unbounded list would crowd out the counts.
	maxRefused    = 20
	maxUnresolved = 20
	maxSkipped    = 20
	maxWarnings   = 10
	// indexLimit bounds the pre-write read that reuses a host's id.
	indexLimit = 1000
)

// Scope is the engagement's authorization pool, as the loader needs it: a
// concrete destination's membership. The production implementation is
// engagement.Scope; tests substitute a deterministic fake.
type Scope interface {
	// InScope reports whether an IP literal or hostname is authorized.
	InScope(dest string) bool
}

// Resolver resolves a declared server's hostname once, at load, so the
// addresses can be pinned for the session (§3.1). The production
// implementation is engagement.DefaultResolver.
type Resolver interface {
	// LookupHost returns the addresses a hostname resolves to.
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Store is the seam the loader writes its host entities through: the
// engagement-state store's own shape, so the concrete store satisfies it
// directly and a fake substitutes in tests.
type Store interface {
	// Query answers the pre-write read that reuses an existing host's id.
	Query(q engagementstate.Query) (engagementstate.Snapshot, error)
	// Update applies one batch of typed ops atomically.
	Update(ctx context.Context, origin engagementstate.Origin, ops []engagementstate.Op) (engagementstate.Receipt, error)
}

// Request is one load: which document, and the session it belongs to. The
// caller (the tool in internal/agent) has already confined Path to the session
// workspace; the loader only reads the file it names.
type Request struct {
	// Artifact is the document as the caller named it, used in the receipt and
	// in refusals.
	Artifact string
	// Path is the document's absolute path.
	Path string
	// Workspace is the project root the inventory artifact is written under.
	Workspace string
	// Store is the engagement-state store the host batch commits through.
	Store Store
	// Scope is the engagement's pinned pool. A load has no meaning without
	// one, so a nil scope is a tool error.
	Scope Scope
	// Resolver pins declared hostnames. Nil means the host resolver.
	Resolver Resolver
	// Pool is the engagement's targets as declared, for refusal reasons.
	Pool []string
	// Pin records a usable declared server's addresses for the session, so a
	// later request against the name lands inside the pinned set (§3.1). It is
	// called only after the host batch commits and the inventory is written, so
	// a load that fails anywhere pins nothing. Nil skips the registration
	// (tests, and a session with no container).
	Pin func(host string, addrs []netip.Addr)
	// Audit records the load's target-set decision (§8): the document, the
	// usable and refused server counts, and every resolved address. It is
	// called once the servers are classified and before any write, so an
	// unlogged decision never reaches state or the resolver (fail closed). Nil
	// skips the record (tests).
	Audit func(Outcome) error
	// Origin is the writing tool's provenance: the harness stamps it, never
	// the model.
	Origin engagementstate.Origin
}

// document is one decoded declaration: its format and the surface its
// extractor found.
type document struct {
	// format is the sniffed format name ("openapi-3.1", "swagger-2.0",
	// "postman-2.1").
	format string
	// servers is every declared server occurrence, in document order.
	servers []serverDecl
	// operations is every operation, with the servers in force for it.
	operations []operationDecl
	// auth is the document's distinct security requirements.
	auth []AuthRequirement
	// redacted is how many literal credential values the document carries.
	redacted int
	// skipped reports the records the extractor understood enough to reject.
	skipped []Skipped
	// warnings reports what limited the extraction.
	warnings []string
	// noServer is the refusal explaining a document that declares no server at
	// all (§7).
	noServer string
}

// serverDecl is one declared server before resolution.
type serverDecl struct {
	// raw is the URL (or template) as the document declared it.
	raw string
	// url is the rendered absolute URL, empty when rendering failed.
	url string
	// variable names the undefined variable that stopped rendering.
	variable string
	// reason is why the declaration is unusable before resolution.
	reason string
}

// operationDecl is one operation and the servers in force for it. A non-empty
// skipped reason marks a record the extractor rejected. fingerprint is a hash
// of the operation as the document declares it, so a diff can tell a changed
// operation from an untouched one without rendering both.
type operationDecl struct {
	method      string
	path        string
	servers     []serverDecl
	auth        []string
	skipped     string
	fingerprint string
}

// Outcome is the target-set decision a load records in the audit trail (§8):
// the document, its usable and refused server counts, and every address the
// declared servers resolved to. A load is where a target set is decided, so
// the record names it even though the declaration itself authorizes nothing.
// It carries no secret: a variable name is not an address, and an unresolved
// declaration resolved to nothing.
type Outcome struct {
	// Document is the document as the caller named it.
	Document string
	// Usable and Refused count the declared servers after the scope check.
	Usable  int
	Refused int
	// Addresses are every resolved address, deduplicated and sorted.
	Addresses []string
	// Subagent attributes the load to the subagent run that made it, empty for
	// the main loop.
	Subagent string
}

// AuthRequirement is one scheme's requirement (§4.3): its name, its type, and
// where it travels. There is deliberately no value field.
type AuthRequirement struct {
	Scheme string `json:"scheme"`
	Type   string `json:"type"`
	In     string `json:"in,omitempty"`
	Name   string `json:"name,omitempty"`
}

// Skipped is one record the extractor understood enough to reject: never a
// silent drop (§7).
type Skipped struct {
	Record string `json:"record"`
	Reason string `json:"reason"`
}

// Counts is one record kind's per-load outcome.
type Counts struct {
	New     int `json:"new"`
	Updated int `json:"updated"`
}

// ServerCounts is how the declared servers fared.
type ServerCounts struct {
	Declared int `json:"declared"`
	Usable   int `json:"usable"`
	Refused  int `json:"refused"`
}

// OperationCounts is how the operations fared.
type OperationCounts struct {
	Total       int `json:"total"`
	Unavailable int `json:"unavailable"`
}

// Refusal is one declared server that could not be used, named with its host
// and the reason — out of scope, unresolvable, unresolved, or non-HTTP.
type Refusal struct {
	Server string `json:"server"`
	Host   string `json:"host,omitempty"`
	Reason string `json:"reason"`
}

// Unresolved is one declaration whose `{{var}}` the document does not define.
type Unresolved struct {
	Variable string `json:"variable"`
	Server   string `json:"server,omitempty"`
	Reason   string `json:"reason"`
}

// Receipt is the load's bounded result (§4.2): counts, the auth requirements,
// the refusals, and the inventory pointer. It is the model's view of the
// surface; the full operation list is the inventory artifact.
type Receipt struct {
	Tool       string            `json:"tool"`
	Document   string            `json:"document"`
	Format     string            `json:"format"`
	OK         bool              `json:"ok"`
	Servers    ServerCounts      `json:"servers"`
	Hosts      Counts            `json:"hosts"`
	Operations OperationCounts   `json:"operations"`
	Auth       []AuthRequirement `json:"auth,omitempty"`
	Redacted   int               `json:"redacted,omitempty"`
	Refused    []Refusal         `json:"refused,omitempty"`
	Unresolved []Unresolved      `json:"unresolved,omitempty"`
	Skipped    []Skipped         `json:"skipped,omitempty"`
	Inventory  string            `json:"inventory,omitempty"`
	Warnings   []string          `json:"warnings,omitempty"`
}

// Inventory is the full derived surface (§4.2): every server that loaded and
// every operation with its effective server, availability, and auth
// requirement. It is a rendering of a document the repository already holds,
// so nothing cites it as evidence.
type Inventory struct {
	Tool       string               `json:"tool"`
	Document   string               `json:"document"`
	Format     string               `json:"format"`
	Servers    []InventoryServer    `json:"servers"`
	Operations []InventoryOperation `json:"operations"`
	Auth       []AuthRequirement    `json:"auth,omitempty"`
}

// InventoryServer is one usable declared server.
type InventoryServer struct {
	URL       string   `json:"url"`
	Host      string   `json:"host"`
	Addresses []string `json:"addresses,omitempty"`
}

// InventoryOperation is one operation in the inventory.
type InventoryOperation struct {
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Server    string   `json:"server,omitempty"`
	Available bool     `json:"available"`
	Reason    string   `json:"reason,omitempty"`
	Auth      []string `json:"auth,omitempty"`
	// Fingerprint identifies the operation's declaration so a diff-scope run
	// can tell a changed operation from an untouched one. It is not part of
	// the inventory artifact: the artifact is the surface, not a change log.
	Fingerprint string `json:"-"`
}

// defaultResolver is the production Resolver: the host resolver, unmodified.
type defaultResolver struct{}

// LookupHost delegates to the host resolver.
func (defaultResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return netLookupHost(ctx, host)
}

// resolution is one declared server after the load-time scope check.
type resolution struct {
	decl   serverDecl
	url    string
	host   string
	addrs  []netip.Addr
	usable bool
	reason string
}

// loader carries one declaration check's seams: the pool to check against and
// the resolver to pin names with. It is shared by the tool's load and by diff
// scope's harness-side read, so both classify a declaration identically.
type loader struct {
	ctx      context.Context
	scope    Scope
	pool     []string
	resolver Resolver
	hosts    map[string]hostLookup
}

// hostLookup is one hostname's load-time resolution.
type hostLookup struct {
	addrs  []netip.Addr
	reason string
}

// Load executes one load (§§2–4, 7): sniff, extract, check every declared
// server against the pool, write one `declared` host per usable server, and
// return a receipt pointing at the inventory artifact. Nothing is written when
// the document is unreadable or declares nothing usable.
func Load(ctx context.Context, req Request) (Receipt, error) {
	if req.Store == nil {
		return Receipt{}, fmt.Errorf("no engagement state is available: %s needs an active engagement", ToolName)
	}
	if req.Scope == nil {
		return Receipt{}, fmt.Errorf("%s: no engagement scope is active, so a declaration has no pool to check", ToolName)
	}
	if strings.TrimSpace(req.Workspace) == "" {
		return Receipt{}, fmt.Errorf("%s: a workspace is required for the inventory artifact", ToolName)
	}
	if req.Origin.Tool == "" {
		req.Origin.Tool = ToolName
	}

	ctx, cancel := context.WithTimeout(ctx, LoadTimeout)
	defer cancel()

	data, err := readDocument(req.Path)
	if err != nil {
		return Receipt{}, err
	}
	// The declaration is read by the same function diff scope uses, so the tool
	// and a scoped run can never disagree about what a document declares. Only
	// the write half below is the tool's own.
	decl, err := Declare(ctx, DeclareRequest{
		Artifact: req.Artifact,
		Data:     data,
		Scope:    req.Scope,
		Resolver: req.Resolver,
		Pool:     req.Pool,
	})
	if err != nil {
		return Receipt{}, err
	}
	if len(decl.Servers) == 0 {
		return Receipt{}, fmt.Errorf("%s: %s: %s", ToolName, req.Artifact, decl.NoServer)
	}
	usable := decl.Usable()
	refused := decl.Refused()
	if len(usable) == 0 {
		return Receipt{}, fmt.Errorf("%s: %s: nothing usable was declared: %s",
			ToolName, req.Artifact, refusalSummary(refusals(refused)))
	}

	// Record the target-set decision before anything is written: a load that
	// cannot be audited must not land hosts or pins, exactly as a tool call that
	// cannot be audited never runs (§8).
	if req.Audit != nil {
		if err := req.Audit(Outcome{
			Document:  req.Artifact,
			Usable:    len(usable),
			Refused:   len(refused),
			Addresses: addressesOf(decl.Servers),
			Subagent:  req.Origin.Subagent,
		}); err != nil {
			return Receipt{}, fmt.Errorf("%s: record the target-set decision: %w", ToolName, err)
		}
	}

	inventory := Inventory{
		Tool:       ToolName,
		Document:   req.Artifact,
		Format:     decl.Format,
		Servers:    inventoryServers(usable),
		Operations: decl.Operations,
		Auth:       decl.Auth,
	}

	hosts, err := writeHosts(ctx, req.Store, req.Origin, usable)
	if err != nil {
		return Receipt{}, err
	}
	inventoryPath, err := writeInventory(req.Workspace, req.Path, inventory)
	if err != nil {
		return Receipt{}, err
	}

	// Pin the usable names only now that the batch committed and the surface is
	// on disk (§3.1): a name the resolver answers for but the store never
	// recorded would be reachable with no record of why, so a load that fails
	// anywhere pins nothing.
	for _, server := range usable {
		if req.Pin == nil || isIPLiteral(server.Host) {
			continue
		}
		req.Pin(server.Host, append([]netip.Addr(nil), server.Addresses...))
	}

	return Receipt{
		Tool:       ToolName,
		Document:   req.Artifact,
		Format:     decl.Format,
		OK:         true,
		Servers:    ServerCounts{Declared: len(decl.Servers), Usable: len(usable), Refused: len(refused)},
		Hosts:      hosts,
		Operations: OperationCounts{Total: len(decl.Operations), Unavailable: decl.Unavailable()},
		Auth:       decl.Auth,
		Redacted:   decl.Redacted,
		Refused:    capRefused(refusals(refused)),
		Unresolved: capUnresolved(unresolvedOf(decl.Servers)),
		Skipped:    capSkipped(decl.Skipped),
		Inventory:  inventoryPath,
		Warnings:   capWarnings(decl.Warnings),
	}, nil
}

// resolve checks one declared server against the pool (§3.1): the scheme must
// be HTTP, the host must resolve, and every resolved address must be inside the
// engagement's targets. Any address outside refuses the whole server —
// answer-binding, not narrowing.
func (l *loader) resolve(decl serverDecl) *resolution {
	r := &resolution{decl: decl, reason: decl.reason}
	if r.reason != "" {
		return r
	}
	parsed, err := url.Parse(decl.url)
	if err != nil || parsed.Hostname() == "" {
		r.reason = fmt.Sprintf("%q is not an absolute URL with a host", decl.url)
		return r
	}
	r.url = decl.url
	r.host = strings.ToLower(parsed.Hostname())
	switch scheme := strings.ToLower(parsed.Scheme); scheme {
	case "http", "https":
	case "":
		r.reason = fmt.Sprintf("%q is not an absolute URL with a scheme", decl.url)
		return r
	default:
		r.reason = fmt.Sprintf("non-HTTP scheme %q: this tool loads HTTP API declarations", parsed.Scheme)
		return r
	}

	if ip, err := netip.ParseAddr(r.host); err == nil {
		r.addrs = []netip.Addr{ip.Unmap()}
	} else {
		addrs, reason := l.lookup(r.host)
		if reason != "" {
			r.reason = reason
			return r
		}
		r.addrs = addrs
	}

	for _, addr := range r.addrs {
		if !l.scope.InScope(addr.String()) {
			r.reason = fmt.Sprintf("%s resolves to %s, outside engagement targets (%s)",
				r.host, addr, l.targets())
			return r
		}
	}
	r.usable = true
	return r
}

// lookup resolves a hostname once per load, with a refusal naming the name and
// the pool it missed.
func (l *loader) lookup(host string) ([]netip.Addr, string) {
	if cached, ok := l.hosts[host]; ok {
		return cached.addrs, cached.reason
	}
	out := hostLookup{}
	raw, err := l.resolver.LookupHost(l.ctx, host)
	if err != nil {
		out.reason = fmt.Sprintf("%s resolves to no addresses (%v); engagement targets: %s", host, err, l.targets())
	} else if len(raw) == 0 {
		out.reason = fmt.Sprintf("%s resolves to no addresses; engagement targets: %s", host, l.targets())
	} else {
		for _, value := range raw {
			ip, err := netip.ParseAddr(strings.TrimSpace(value))
			if err != nil {
				out.reason = fmt.Sprintf("%s resolved to %q, not an address", host, value)
				break
			}
			out.addrs = append(out.addrs, ip.Unmap())
		}
		sort.Slice(out.addrs, func(i, j int) bool { return out.addrs[i].Compare(out.addrs[j]) < 0 })
		if len(out.addrs) == 0 && out.reason == "" {
			out.reason = fmt.Sprintf("%s resolves to no addresses; engagement targets: %s", host, l.targets())
		}
	}
	l.hosts[host] = out
	return out.addrs, out.reason
}

// targets renders the engagement's targets for a refusal reason.
func (l *loader) targets() string {
	if len(l.pool) == 0 {
		return "no targets declared"
	}
	return strings.Join(l.pool, ", ")
}

// writeHosts upserts one `declared` host per usable server, reusing the id the
// store already holds for the record's natural key (§4.1). It writes nothing
// else: no service, finding, credential, edge, or evidence.
func writeHosts(ctx context.Context, store Store, origin engagementstate.Origin, usable []DeclaredServer) (Counts, error) {
	snapshot, err := store.Query(engagementstate.Query{Kind: engagementstate.KindHost, IncludeInactive: true, Limit: indexLimit})
	if err != nil {
		return Counts{}, fmt.Errorf("%s: read engagement state: %w", ToolName, err)
	}
	byAddr, byName := indexHosts(snapshot)

	written := map[string]bool{}
	var ops []engagementstate.Op
	for _, server := range usable {
		id, addresses := "", []string(nil)
		match, ok := matchHost(server, byAddr, byName)
		if ok {
			id = match.id
			addresses = append(addresses, match.addresses...)
			for _, addr := range server.Addresses {
				addresses = appendUnique(addresses, addr.String())
			}
		} else {
			for _, addr := range server.Addresses {
				addresses = appendUnique(addresses, addr.String())
			}
			id = mintedHostID(addresses[0])
		}
		if written[id] {
			continue
		}
		written[id] = true

		op := engagementstate.Op{
			Op:        engagementstate.OpUpsertEntity,
			Kind:      engagementstate.KindHost,
			ID:        id,
			Addresses: addresses,
			Tags:      []string{declaredTag},
		}
		if !isIPLiteral(server.Host) {
			op.Hostname = server.Host
		}
		ops = append(ops, op)
	}
	// A truncated read can miss an existing id; the store still matches the
	// natural key and reuses the record, so a truncated index never duplicates
	// a host.

	if len(ops) == 0 {
		return Counts{}, nil
	}
	receipt, err := store.Update(ctx, origin, ops)
	if err != nil {
		return Counts{}, fmt.Errorf("%s: write engagement state: %w", ToolName, err)
	}
	counts := Counts{}
	for _, effect := range receipt.Effects {
		if effect.Op != engagementstate.OpUpsertEntity {
			continue
		}
		if effect.Created {
			counts.New++
		} else {
			counts.Updated++
		}
	}
	return counts, nil
}

// existingHost is a host the store already holds, with the addresses it is
// keyed under.
type existingHost struct {
	id        string
	addresses []string
}

// indexHosts keys a host snapshot by every address it carries and its hostname,
// so a declaration matches the record whichever alias was recorded first.
func indexHosts(snapshot engagementstate.Snapshot) (map[string]existingHost, map[string]existingHost) {
	byAddr := map[string]existingHost{}
	byName := map[string]existingHost{}
	for _, e := range snapshot.Entities {
		if e.Kind != engagementstate.KindHost || len(e.Addresses) == 0 {
			continue
		}
		host := existingHost{id: e.ID, addresses: append([]string(nil), e.Addresses...)}
		for _, addr := range e.Addresses {
			byAddr[normalizeAddress(addr)] = host
		}
		if e.Hostname != "" {
			byName[strings.ToLower(e.Hostname)] = host
		}
	}
	return byAddr, byName
}

// matchHost finds the record a usable server names: any resolved address, or
// the declared hostname.
func matchHost(server DeclaredServer, byAddr, byName map[string]existingHost) (existingHost, bool) {
	for _, addr := range server.Addresses {
		if host, ok := byAddr[normalizeAddress(addr.String())]; ok {
			return host, true
		}
	}
	if !isIPLiteral(server.Host) {
		if host, ok := byName[strings.ToLower(server.Host)]; ok {
			return host, true
		}
	}
	return existingHost{}, false
}

// inventoryOperations renders every operation with the server in force for it.
// A refused nested server takes only the operations under it, so those rows are
// `available: false` with the refusal reason (§3.3).
func inventoryOperations(doc *document, resolutions map[string]*resolution) ([]InventoryOperation, int) {
	out := make([]InventoryOperation, 0, len(doc.operations))
	unavailable := 0
	for _, op := range doc.operations {
		row := InventoryOperation{Method: op.method, Path: op.path, Auth: op.auth, Fingerprint: op.fingerprint}
		var chosen *resolution
		reason := ""
		for _, decl := range op.servers {
			r := resolutions[declKey(decl)]
			if r == nil {
				continue
			}
			if r.usable {
				chosen = r
				break
			}
			if reason == "" {
				reason = r.reason
			}
		}
		if chosen != nil {
			row.Available = true
			row.Server = chosen.url
		} else {
			row.Reason = reason
			if row.Reason == "" {
				row.Reason = "no server is in force for this operation"
			}
			unavailable++
		}
		out = append(out, row)
	}
	return out, unavailable
}

// inventoryServers renders the usable declared servers.
func inventoryServers(usable []DeclaredServer) []InventoryServer {
	out := make([]InventoryServer, 0, len(usable))
	for _, server := range usable {
		addresses := make([]string, 0, len(server.Addresses))
		for _, addr := range server.Addresses {
			addresses = append(addresses, addr.String())
		}
		out = append(out, InventoryServer{URL: server.URL, Host: server.Host, Addresses: addresses})
	}
	return out
}

// writeInventory writes the derived inventory artifact (§4.2). The name is the
// document's stem plus a hash of its path, so a changed document replaces its
// inventory rather than accumulating versions.
func writeInventory(workspace, documentPath string, inventory Inventory) (string, error) {
	abs, err := filepath.Abs(documentPath)
	if err != nil {
		abs = documentPath
	}
	sum := sha256.Sum256([]byte(abs))
	name := inventoryStem(abs) + "-" + hex.EncodeToString(sum[:3]) + ".json"
	dir := filepath.Join(workspace, InventoryDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("%s: create %s: %w", ToolName, dir, err)
	}
	encoded, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return "", fmt.Errorf("%s: encode inventory: %w", ToolName, err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join(dir, name)
	//nolint:gosec // the inventory directory is under the session workspace.
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return "", fmt.Errorf("%s: write %s: %w", ToolName, path, err)
	}
	return filepath.ToSlash(filepath.Join(InventoryDir, name)), nil
}

// declKey identifies one declaration for deduplication: its absolute URL, or
// its refusal when it could not be rendered.
func declKey(decl serverDecl) string {
	if decl.url != "" {
		return "=" + decl.url
	}
	return "!" + decl.reason + "|" + decl.raw
}

// normalizeAddress canonicalizes an address for natural-key matching: an IP
// literal in its unmapped form, or a lowercased name without a trailing root
// dot.
func normalizeAddress(raw string) string {
	s := strings.TrimSpace(raw)
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// isIPLiteral reports whether a host is an address rather than a name.
func isIPLiteral(host string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(host))
	return err == nil
}

// mintedHostID is the id a load assigns a host it creates: the kind plus a hash
// of the natural key, so two loads of one server agree on the id.
func mintedHostID(primary string) string {
	sum := sha256.Sum256([]byte(string(engagementstate.KindHost) + "\x1f" + normalizeAddress(primary)))
	return string(engagementstate.KindHost) + "-" + hex.EncodeToString(sum[:4])
}

// appendUnique appends a value unless it is already present.
func appendUnique(into []string, value string) []string {
	for _, existing := range into {
		if existing == value {
			return into
		}
	}
	return append(into, value)
}

// inventoryStem reduces a document's base name to an artifact-safe stem.
func inventoryStem(abs string) string {
	stem := strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs))
	var b strings.Builder
	for _, r := range stem {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "api"
	}
	return b.String()
}

// refusalSummary names the first refusals in a nothing-usable error.
func refusalSummary(refused []Refusal) string {
	if len(refused) == 0 {
		return "no server could be checked"
	}
	parts := make([]string, 0, len(refused))
	for _, row := range refused {
		parts = append(parts, row.Reason)
		if len(parts) == 3 {
			break
		}
	}
	return strings.Join(parts, "; ")
}

// capRefused bounds a receipt's refusal rows.
func capRefused(rows []Refusal) []Refusal {
	if len(rows) <= maxRefused {
		return rows
	}
	out := append([]Refusal(nil), rows[:maxRefused]...)
	return append(out, Refusal{Server: fmt.Sprintf("%d more", len(rows)-maxRefused), Reason: "omitted from this receipt"})
}

// capUnresolved bounds a receipt's unresolved rows.
func capUnresolved(rows []Unresolved) []Unresolved {
	if len(rows) <= maxUnresolved {
		return rows
	}
	out := append([]Unresolved(nil), rows[:maxUnresolved]...)
	return append(out, Unresolved{Variable: fmt.Sprintf("%d more", len(rows)-maxUnresolved), Reason: "omitted from this receipt"})
}

// capSkipped bounds a receipt's skipped rows.
func capSkipped(rows []Skipped) []Skipped {
	if len(rows) <= maxSkipped {
		return rows
	}
	out := append([]Skipped(nil), rows[:maxSkipped]...)
	return append(out, Skipped{Record: fmt.Sprintf("%d more", len(rows)-maxSkipped), Reason: "omitted from this receipt"})
}

// capWarnings bounds a receipt's warnings.
func capWarnings(warnings []string) []string {
	if len(warnings) <= maxWarnings {
		return warnings
	}
	out := append([]string(nil), warnings[:maxWarnings]...)
	return append(out, fmt.Sprintf("… %d more", len(warnings)-maxWarnings))
}
