package parsers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// The six parser tools (docs/parser-tool-contracts.md §1), one per scanner.
const (
	// NmapParse parses nmap XML (`-oX`) into hosts, services, and segments.
	NmapParse = "nmap_parse"
	// NucleiParse parses nuclei JSON Lines into hosts, services, and findings.
	NucleiParse = "nuclei_parse"
	// SQLMapParse parses a sqlmap per-target log into findings, credentials,
	// and access.
	SQLMapParse = "sqlmap_parse"
	// GobusterParse parses gobuster output into hosts, services, and one
	// discovered-path finding per host.
	GobusterParse = "gobuster_parse"
	// CMEParse parses CrackMapExec / NetExec output into hosts, credentials,
	// access, and findings.
	CMEParse = "cme_parse"
	// BloodHoundParse parses legacy BloodHound collector JSON into hosts and
	// access records.
	BloodHoundParse = "bloodhound_parse"
)

// Names returns the parser tool names, in the contract's order.
func Names() []string {
	return []string{NmapParse, NucleiParse, SQLMapParse, GobusterParse, CMEParse, BloodHoundParse}
}

// Known reports whether a name is one of the six parser tools.
func Known(name string) bool {
	_, ok := registry[name]
	return ok
}

// Store is the seam the parser tools read and write engagement state through:
// the store's own shape, so the concrete store satisfies it directly and a fake
// substitutes in tests.
type Store interface {
	// Query answers the pre-parse read that resolves the ids of records the
	// parse is about to touch.
	Query(q engagementstate.Query) (engagementstate.Snapshot, error)
	// Update applies one batch of typed ops atomically.
	Update(ctx context.Context, origin engagementstate.Origin, ops []engagementstate.Op) (engagementstate.Receipt, error)
}

// Limits (§10). The read is bounded so one artifact cannot balloon the
// harness's heap, and the parse is bounded so a hang becomes a tool error.
const (
	// MaxArtifactBytes is the largest artifact a parser will read. A larger
	// one refuses with a clear error rather than exhausting memory.
	MaxArtifactBytes = 64 << 20 // 64 MiB
	// ParseTimeout bounds one parse's wall clock.
	ParseTimeout = 60 * time.Second
	// maxSampleBytes is how much of an artifact a refusal quotes back.
	maxSampleBytes = 240
	// maxSkipped and maxWarnings bound a receipt's reports; the receipt is
	// truncated at capture like any tool output, and an unbounded list would
	// crowd out the counts.
	maxSkipped  = 20
	maxWarnings = 10
	// indexLimit is the pre-parse read's cap. It is engagementstate's
	// maximum, so the index sees everything the store will report.
	indexLimit = 1000
)

// ErrNotParsed is the sentinel every format refusal wraps: an artifact that is
// unparseable, unrecognized, or in another format. Nothing is written when one
// is returned (§7).
var ErrNotParsed = errors.New("parsers: the artifact is not this parser's format")

// FormatError is one refusal: what the parser expected, which artifact it read,
// and what it saw instead. §7 requires all three — a refusal that names the
// format is what lets the model route the artifact to the right parser.
type FormatError struct {
	// Tool is the parser that refused.
	Tool string
	// Artifact is the artifact as the caller named it.
	Artifact string
	// Format is the format the parser expected.
	Format string
	// Detail is what was wrong, when the extractor can be specific.
	Detail string
	// Sample is the head of the artifact, for a human or model to recognize.
	Sample string
}

// Error implements error.
func (e *FormatError) Error() string {
	msg := fmt.Sprintf("%s: %s: not %s", e.Tool, e.Artifact, e.Format)
	if e.Detail != "" {
		msg += " (" + e.Detail + ")"
	}
	if e.Sample != "" {
		msg += "; read: " + strconv.Quote(e.Sample)
	}
	return msg + "; nothing was written"
}

// Unwrap reports the refusal's sentinel, so callers branch on the kind.
func (e *FormatError) Unwrap() error { return ErrNotParsed }

// Request is one parse: which parser, which artifact, and where its writes go.
// The caller (the tool in internal/agent) has already confined Path to the
// session workspace; parsers only read the file it names.
type Request struct {
	// Tool is the parser tool name (Names).
	Tool string
	// Artifact is the artifact as the caller named it, used in the receipt and
	// in refusals.
	Artifact string
	// Path is the artifact's absolute path.
	Path string
	// Store is the engagement-state store the batch commits through.
	Store Store
	// Origin is the writing tool's provenance: the harness stamps it, never
	// the model.
	Origin engagementstate.Origin
	// Tracker is the pending-parse obligation set, cleared for this artifact
	// when the parse succeeds (§4). Nil means no obligation to clear.
	Tracker *Tracker
}

// Counts is one record kind's per-parse outcome.
type Counts struct {
	// New is how many records the parse created.
	New int `json:"new"`
	// Updated is how many it refreshed.
	Updated int `json:"updated"`
}

// Skipped is one record the extractor understood enough to reject: never a
// silent drop (§7).
type Skipped struct {
	// Record is the offending record, rendered compactly.
	Record string `json:"record"`
	// Reason is why it could not be recorded.
	Reason string `json:"reason"`
}

// Receipt is the parse receipt (§5): what entered state, what did not, and why.
// It is the model's feedback loop — it never has to re-read the raw output.
type Receipt struct {
	// Tool is the parser that ran.
	Tool string `json:"tool"`
	// Artifact is the artifact it read.
	Artifact string `json:"artifact"`
	// OK is true: a failed parse returns an error instead of a receipt, so a
	// receipt always means the batch committed (or was empty but valid).
	OK bool `json:"ok"`
	// Entities counts the entity writes, by kind.
	Entities map[string]Counts `json:"entities,omitempty"`
	// Findings counts the finding writes.
	Findings *Counts `json:"findings,omitempty"`
	// Edges counts the edges added, by type.
	Edges map[string]int `json:"edges,omitempty"`
	// CreatedIDs are the ids of the records this parse created, in write order.
	CreatedIDs []string `json:"created_ids,omitempty"`
	// Skipped reports the records the extractor rejected.
	Skipped []Skipped `json:"skipped,omitempty"`
	// Warnings are the parse's non-record observations: a format detail that
	// limited fidelity, or a record class this version does not record.
	Warnings []string `json:"warnings,omitempty"`
}

// HostRecord is one host observation.
type HostRecord struct {
	// Addresses are the host's addresses; the first is its natural key.
	Addresses []string
	// Hostname is its name, when the artifact gives one.
	Hostname string
	// OS is the operating system the artifact reports.
	OS string
	// Tags are labels the artifact implies.
	Tags []string
}

// ServiceRecord is one offered service.
type ServiceRecord struct {
	// Host is the host it runs on, named by the same address the parse wrote
	// as that host's first address.
	Host string
	// Port and Proto identify the service.
	Port  int
	Proto string
	// Product and Version are the observed banner identity, when present.
	Product string
	Version string
}

// SegmentRecord is one labeled network range.
type SegmentRecord struct {
	// Label is the segment's label (its natural key).
	Label string
	// CIDRs are the ranges it covers.
	CIDRs []string
}

// CredentialRecord is one captured secret.
type CredentialRecord struct {
	// Type is the credential type: password, hash, key, or token.
	Type string
	// Principal is the account the secret belongs to.
	Principal string
	// Secret is the secret material.
	Secret string
}

// AccessRecord is one foothold: a principal operating on a target at a level.
type AccessRecord struct {
	// Principal is a credential ref, or an account name the artifact names.
	Principal ref
	// Target is the host or service the principal reaches.
	Target ref
	// Level is user, admin, or system.
	Level string
	// Via is the finding that produced the foothold, when the artifact says.
	Via ref
}

// FindingRecord is one observation the artifact calls a vulnerability or
// result, with the evidence that produced it.
type FindingRecord struct {
	// Title is the finding's short label; with Affected it is its natural key.
	Title string
	// Severity is the qualitative severity the artifact reports.
	Severity engagementstate.Severity
	// Confidence is the qualitative confidence the parse can justify.
	Confidence engagementstate.Confidence
	// CVSSVector is the vector the artifact carries, when it carries one.
	CVSSVector string
	// Affected are the hosts or services the finding concerns.
	Affected []ref
	// Evidence is the evidence the parse attaches.
	Evidence []Evidence
}

// Evidence is one item attached to a finding.
type Evidence struct {
	// Kind is the evidence form.
	Kind engagementstate.EvidenceKind
	// Ref is an artifact path or an inline excerpt.
	Ref string
}

// EdgeRecord is one relationship-graph edge between records of this parse.
type EdgeRecord struct {
	// Type is the closed-enum edge type.
	Type engagementstate.EdgeType
	// From and To are the endpoints, named by ref.
	From ref
	To   ref
	// Confidence is the qualitative confidence the parse can justify.
	Confidence engagementstate.Confidence
}

// Records is one extractor's output: the observations it understood, in the
// order it found them, plus what it could not use. The shared pipeline turns
// this into the §6 op batch.
type Records struct {
	// Hosts are the hosts the parse observed. Every other record's references
	// resolve against them.
	Hosts []HostRecord
	// Segments are the labeled ranges the artifact reveals.
	Segments []SegmentRecord
	// Services are the offered services the artifact reveals.
	Services []ServiceRecord
	// Credentials are the secrets the artifact dumped.
	Credentials []CredentialRecord
	// Accesses are the footholds the artifact proves.
	Accesses []AccessRecord
	// Findings are the vulnerabilities and results the artifact reports.
	Findings []FindingRecord
	// Edges are the relationships the artifact establishes beyond those the
	// store derives itself.
	Edges []EdgeRecord
	// Skipped reports the records the extractor rejected, with reasons.
	Skipped []Skipped
	// Warnings reports what limited the parse: fidelity the format does not
	// carry, or a record class this version does not write.
	Warnings []string
}

// extractor turns one artifact into the records it carries. An extractor that
// does not recognize the format returns a *FormatError and writes nothing.
type extractor func(in input) (Records, error)

// spec is one parser's registration.
type spec struct {
	// format names the format in refusals.
	format string
	// extract reads the artifact.
	extract extractor
}

// registry is the six parsers, keyed by tool name. It is the single place the
// contract's set is defined; the tools, the policy rules, and the preset
// allowlists are all derived from it (or cover it), so the set cannot drift.
var registry = map[string]spec{
	NmapParse:       {format: "nmap XML output (nmap -oX)", extract: extractNmap},
	NucleiParse:     {format: "nuclei JSON Lines output (nuclei -jsonl)", extract: extractNuclei},
	SQLMapParse:     {format: "a sqlmap log", extract: extractSQLMap},
	GobusterParse:   {format: "gobuster output", extract: extractGobuster},
	CMEParse:        {format: "CrackMapExec or NetExec output", extract: extractCME},
	BloodHoundParse: {format: "legacy BloodHound collector JSON", extract: extractBloodHound},
}

// input is one artifact handed to an extractor.
type input struct {
	// tool is the parser tool name.
	tool string
	// artifact is the artifact as the caller named it.
	artifact string
	// file is the open artifact. Extractor code reads it from the start.
	file *os.File
	// path is the artifact's absolute path, used to quote a sample.
	path string
}

// unrecognized builds a refusal for this artifact: the format the parser wanted
// and what it saw instead, sampled from the artifact's head (§7).
func (in input) unrecognized(format, detail string) error {
	return &FormatError{
		Tool:     in.tool,
		Artifact: in.artifact,
		Format:   format,
		Detail:   detail,
		Sample:   sampleOf(in.path),
	}
}

// Run executes one parse (§5): open the artifact, extract, resolve references,
// commit one atomic batch, and report a receipt. Nothing is written on a
// refusal or on a store error — the batch is the store's, not the pipeline's,
// so a mid-batch validation failure writes nothing at all.
func Run(ctx context.Context, req Request) (Receipt, error) {
	spec, ok := registry[req.Tool]
	if !ok {
		return Receipt{}, fmt.Errorf("parsers: %q is not one of the parser tools (%s)", req.Tool, strings.Join(Names(), ", "))
	}
	if req.Store == nil {
		return Receipt{}, fmt.Errorf("no engagement state is available: %s needs an active engagement", req.Tool)
	}

	ctx, cancel := context.WithTimeout(ctx, ParseTimeout)
	defer cancel()

	file, err := openArtifact(req.Path)
	if err != nil {
		return Receipt{}, err
	}
	defer func() { _ = file.Close() }()

	records, err := spec.extract(input{tool: req.Tool, artifact: req.Artifact, file: file, path: req.Path})
	if err != nil {
		return Receipt{}, err
	}

	// The pre-parse read resolves every reference this batch makes to the id
	// the store already holds for that record, so a re-detected host, service,
	// credential, access, or finding is written and referenced under one id
	// whichever writer created it (§8).
	snapshot, err := req.Store.Query(engagementstate.Query{IncludeInactive: true, Limit: indexLimit})
	if err != nil {
		return Receipt{}, fmt.Errorf("%s: read engagement state: %w", req.Tool, err)
	}
	ix := newIndex(snapshot)
	if snapshot.Truncated {
		records.Warnings = append(records.Warnings,
			fmt.Sprintf("the engagement holds more than %d records; a re-detected record beyond that read is matched by natural key, not by id", indexLimit))
	}

	ops, err := buildOps(records, ix)
	if err != nil {
		return Receipt{}, fmt.Errorf("%s: %w", req.Tool, err)
	}

	receipt := Receipt{
		Tool:     req.Tool,
		Artifact: req.Artifact,
		OK:       true,
		Skipped:  capSkipped(records.Skipped),
		Warnings: capWarnings(records.Warnings),
	}
	if len(ops) > 0 {
		storeReceipt, err := req.Store.Update(ctx, req.Origin, ops)
		if err != nil {
			return Receipt{}, fmt.Errorf("%s: write engagement state: %w", req.Tool, err)
		}
		foldCounts(&receipt, storeReceipt)
	}
	if req.Tracker != nil {
		// Cleared on success: the obligation is that this artifact has not been
		// parsed, and it now has (§4). An empty-but-valid parse clears it too —
		// there was nothing to record, which is itself an answer.
		req.Tracker.Clear(req.Path)
	}
	return receipt, nil
}

// buildOps turns an extractor's records into one §6 op batch. Order matters: a
// host is written before the services, evidence, and edges that name it, and a
// record is written before anything references it — the store resolves
// references within the batch, and refuses a batch that dangles.
func buildOps(records Records, ix *index) ([]engagementstate.Op, error) {
	records = dedupeRecords(records)
	var ops []engagementstate.Op
	upsert := func(op engagementstate.Op) { ops = append(ops, op) }

	for _, h := range records.Hosts {
		upsert(engagementstate.Op{
			Op:        engagementstate.OpUpsertEntity,
			Kind:      engagementstate.KindHost,
			ID:        ix.id(hostRef(h.Addresses[0])),
			Addresses: h.Addresses,
			Hostname:  h.Hostname,
			OS:        h.OS,
			Tags:      h.Tags,
		})
	}
	for _, s := range records.Segments {
		upsert(engagementstate.Op{
			Op:    engagementstate.OpUpsertEntity,
			Kind:  engagementstate.KindSegment,
			ID:    ix.id(segmentRef(s.Label)),
			Label: s.Label,
			CIDRs: s.CIDRs,
		})
	}
	for _, s := range records.Services {
		upsert(engagementstate.Op{
			Op:      engagementstate.OpUpsertEntity,
			Kind:    engagementstate.KindService,
			ID:      ix.id(serviceRef(s.Host, s.Port, s.Proto)),
			Host:    s.Host,
			Port:    s.Port,
			Proto:   s.Proto,
			Product: s.Product,
			Version: s.Version,
			State:   engagementstate.StateOpen,
		})
	}
	for _, c := range records.Credentials {
		upsert(engagementstate.Op{
			Op:        engagementstate.OpUpsertEntity,
			Kind:      engagementstate.KindCredential,
			ID:        ix.id(credentialRef(c.Type, c.Principal, c.Secret)),
			Type:      c.Type,
			Principal: c.Principal,
			Secret:    c.Secret,
		})
	}
	// Findings come before accesses: an access's `via` names the finding it
	// came through, and the store resolves a reference only to a record the
	// batch has already written.
	for _, f := range records.Findings {
		affected := make([]string, 0, len(f.Affected))
		for _, a := range f.Affected {
			affected = append(affected, ix.ref(a))
		}
		upsert(engagementstate.Op{
			Op:         engagementstate.OpUpsertFinding,
			ID:         ix.id(findingRef(f.Title, f.Affected...)),
			Title:      f.Title,
			Severity:   f.Severity,
			Confidence: f.Confidence,
			CVSSVector: f.CVSSVector,
			Affected:   affected,
		})
		for _, e := range f.Evidence {
			if strings.TrimSpace(e.Ref) == "" {
				continue
			}
			ops = append(ops, engagementstate.Op{
				Op:           engagementstate.OpAttachEvidence,
				Finding:      ix.id(findingRef(f.Title, f.Affected...)),
				Affected:     affected,
				EvidenceKind: e.Kind,
				Ref:          e.Ref,
			})
		}
	}
	for _, a := range records.Accesses {
		principal := a.Principal
		if principal.kind == refCredential {
			principal = ref{kind: refCredential, value: ix.id(a.Principal)}
		}
		op := engagementstate.Op{
			Op:        engagementstate.OpUpsertEntity,
			Kind:      engagementstate.KindAccess,
			ID:        ix.id(accessRef(a.Principal, a.Target)),
			Principal: principal.value,
			Target:    ix.ref(a.Target),
			Level:     a.Level,
		}
		if a.Via.kind == refFinding {
			// The mirror: upserting the access with `via` also writes its
			// EXPLOITED_VIA edge, so the field and the edge cannot drift.
			op.Via = ix.id(a.Via)
		}
		upsert(op)
	}
	for _, e := range records.Edges {
		ops = append(ops, engagementstate.Op{
			Op:         engagementstate.OpAddEdge,
			Type:       string(e.Type),
			From:       ix.ref(e.From),
			To:         ix.ref(e.To),
			Confidence: e.Confidence,
		})
	}
	return ops, nil
}

// dedupeRecords collapses records one artifact reports more than once — the
// host every line of a NetExec run repeats, the service three nuclei matches
// share — so a batch touches each record once and the receipt counts
// observations rather than lines. It is the same identity rule the store
// applies per op (§8's natural-key upserts), one step earlier.
func dedupeRecords(records Records) Records {
	out := Records{Skipped: records.Skipped, Warnings: records.Warnings}

	hosts := map[string]int{}
	for _, host := range records.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}
		key := hostRef(host.Addresses[0]).key()
		if i, seen := hosts[key]; seen {
			out.Hosts[i].Addresses = mergeStrings(out.Hosts[i].Addresses, host.Addresses)
			if out.Hosts[i].Hostname == "" {
				out.Hosts[i].Hostname = host.Hostname
			}
			if out.Hosts[i].OS == "" {
				out.Hosts[i].OS = host.OS
			}
			out.Hosts[i].Tags = mergeStrings(out.Hosts[i].Tags, host.Tags)
			continue
		}
		hosts[key] = len(out.Hosts)
		out.Hosts = append(out.Hosts, HostRecord{
			Addresses: mergeStrings(nil, host.Addresses),
			Hostname:  host.Hostname,
			OS:        host.OS,
			Tags:      mergeStrings(nil, host.Tags),
		})
	}

	services := map[string]bool{}
	for _, service := range records.Services {
		key := serviceRef(service.Host, service.Port, service.Proto).key()
		if services[key] {
			continue
		}
		services[key] = true
		out.Services = append(out.Services, service)
	}

	segments := map[string]int{}
	for _, segment := range records.Segments {
		key := segmentRef(segment.Label).key()
		if i, seen := segments[key]; seen {
			out.Segments[i].CIDRs = mergeStrings(out.Segments[i].CIDRs, segment.CIDRs)
			continue
		}
		segments[key] = len(out.Segments)
		out.Segments = append(out.Segments, segment)
	}

	credentials := map[string]bool{}
	for _, credential := range records.Credentials {
		key := credentialRef(credential.Type, credential.Principal, credential.Secret).key()
		if credentials[key] {
			continue
		}
		credentials[key] = true
		out.Credentials = append(out.Credentials, credential)
	}

	accesses := map[string]int{}
	for _, access := range records.Accesses {
		key := accessRef(access.Principal, access.Target).key()
		if i, seen := accesses[key]; seen {
			// The same foothold seen twice at two levels keeps the higher one:
			// an admin observation is the stronger fact.
			if levelRank(access.Level) > levelRank(out.Accesses[i].Level) {
				out.Accesses[i].Level = access.Level
			}
			if out.Accesses[i].Via.kind != refFinding {
				out.Accesses[i].Via = access.Via
			}
			continue
		}
		accesses[key] = len(out.Accesses)
		out.Accesses = append(out.Accesses, access)
	}

	// Findings are not collapsed: two matches of one template on one host are
	// two pieces of evidence for one finding, which is what §8 appends.
	out.Findings = records.Findings

	edges := map[string]bool{}
	for _, edge := range records.Edges {
		key := string(edge.Type) + "|" + ixRefKey(edge.From) + "|" + ixRefKey(edge.To)
		if edges[key] {
			continue
		}
		edges[key] = true
		out.Edges = append(out.Edges, edge)
	}
	return out
}

// ixRefKey renders a ref as a key for edge deduplication.
func ixRefKey(r ref) string { return r.key() }

// levelRank orders access levels, so a stronger observation wins.
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

// mergeStrings appends values, skipping blanks and duplicates, in order.
func mergeStrings(into, values []string) []string {
	out := append([]string(nil), into...)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen := false
		for _, existing := range out {
			if existing == value {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, value)
		}
	}
	return out
}

// foldCounts folds a store receipt's per-op effects into the parse receipt.
func foldCounts(receipt *Receipt, store engagementstate.Receipt) {
	for _, effect := range store.Effects {
		switch effect.Op {
		case engagementstate.OpUpsertEntity:
			if receipt.Entities == nil {
				receipt.Entities = map[string]Counts{}
			}
			counts := receipt.Entities[effect.Kind]
			if effect.Created {
				counts.New++
			} else {
				counts.Updated++
			}
			receipt.Entities[effect.Kind] = counts
			if effect.Created {
				receipt.CreatedIDs = append(receipt.CreatedIDs, effect.ID)
			}
		case engagementstate.OpUpsertFinding:
			if receipt.Findings == nil {
				receipt.Findings = &Counts{}
			}
			if effect.Created {
				receipt.Findings.New++
				receipt.CreatedIDs = append(receipt.CreatedIDs, effect.ID)
			} else {
				receipt.Findings.Updated++
			}
		case engagementstate.OpAddEdge:
			if receipt.Edges == nil {
				receipt.Edges = map[string]int{}
			}
			receipt.Edges[edgeTypeOf(effect.ID)]++
		}
	}
}

// edgeTypeOf reads an edge effect's type back out of its key ("TYPE|from|to").
func edgeTypeOf(key string) string {
	if kind, _, ok := strings.Cut(key, "|"); ok {
		return kind
	}
	return key
}

// capSkipped bounds a receipt's skipped list, so one rotted artifact cannot
// crowd out the counts.
func capSkipped(skipped []Skipped) []Skipped {
	if len(skipped) <= maxSkipped {
		return skipped
	}
	out := append([]Skipped(nil), skipped[:maxSkipped]...)
	return append(out, Skipped{
		Record: fmt.Sprintf("%d more", len(skipped)-maxSkipped),
		Reason: "omitted from this receipt",
	})
}

// capWarnings bounds a receipt's warnings the same way.
func capWarnings(warnings []string) []string {
	if len(warnings) <= maxWarnings {
		return warnings
	}
	out := append([]string(nil), warnings[:maxWarnings]...)
	return append(out, fmt.Sprintf("… %d more", len(warnings)-maxWarnings))
}

// openArtifact opens the artifact a parser was pointed at, refusing anything
// that is not a regular file or that exceeds MaxArtifactBytes.
func openArtifact(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not a scanner artifact", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > MaxArtifactBytes {
		return nil, fmt.Errorf("%s is %d bytes; a parser reads at most %d bytes", path, info.Size(), MaxArtifactBytes)
	}
	//nolint:gosec // the path was confined to the session workspace by the tool.
	return os.Open(path)
}

// sampleOf quotes the head of an artifact, for a refusal. It is bounded and
// single-line: an error the model reads must stay readable.
func sampleOf(path string) string {
	//nolint:gosec // the path was confined to the session workspace by the tool.
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	buf := make([]byte, maxSampleBytes)
	n, _ := file.Read(buf)
	return collapse(string(buf[:n]))
}

// collapse renders text on one line with runs of whitespace squashed, so a
// sample from a log or an XML head does not wreck an error's shape.
func collapse(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// mintedID is the id a parse assigns to a record it writes: the record kind
// plus a hash of its natural key. Deriving it from the natural key (rather than
// at random) is what makes two parses of the same observation agree on the id:
// a service nmap found and nuclei later matched keeps one identity, and its
// edges never dangle.
func mintedID(r ref) string {
	sum := sha256.Sum256([]byte(r.kind.name() + "\x1f" + r.value))
	return r.kind.name() + "-" + hex.EncodeToString(sum[:4])
}

// refKind is the kind of record a ref names.
type refKind int

const (
	// refAccount is a bare account name: an access principal the artifact
	// names without a captured secret. It is never an entity of its own.
	refAccount refKind = iota
	// refHost names a host by one of its addresses.
	refHost
	// refService names a service by its host and port.
	refService
	// refCredential names a captured secret.
	refCredential
	// refAccess names a foothold.
	refAccess
	// refFinding names a finding by title and affected refs.
	refFinding
	// refSegment names a segment by its label.
	refSegment
)

// name is the record kind a refKind names in an id, and the discriminator in a
// natural key.
func (k refKind) name() string {
	switch k {
	case refHost:
		return string(engagementstate.KindHost)
	case refService:
		return string(engagementstate.KindService)
	case refCredential:
		return string(engagementstate.KindCredential)
	case refAccess:
		return string(engagementstate.KindAccess)
	case refFinding:
		return string(engagementstate.KindFinding)
	case refSegment:
		return string(engagementstate.KindSegment)
	default:
		return "account"
	}
}

// ref names a record this parse writes, by its natural key. Extractors speak in
// refs because they cannot know the id the store will assign; the pipeline
// resolves each ref to the id the store holds or the id it mints.
type ref struct {
	// kind is the record kind, or refAccount for a bare principal name.
	kind refKind
	// value is the canonical natural-key string.
	value string
}

// hostRef names a host by an address or hostname.
func hostRef(addr string) ref { return ref{kind: refHost, value: normalizeKey(addr)} }

// serviceRef names a service by the address its host is recorded under and its
// port and protocol.
func serviceRef(host string, port int, proto string) ref {
	return ref{kind: refService, value: fmt.Sprintf("%s\x1f%d\x1f%s", normalizeKey(host), port, strings.ToLower(proto))}
}

// credentialRef names a captured secret by its type, principal, and material.
func credentialRef(credType, principal, secret string) ref {
	return ref{kind: refCredential, value: strings.Join([]string{strings.ToLower(credType), principal, secret}, "\x1f")}
}

// accountRef names an account the artifact lists without a captured secret: a
// bare principal name, which is how an access record names the identity that
// reached a target.
func accountRef(name string) ref { return ref{kind: refAccount, value: strings.TrimSpace(name)} }

// accessRef names a foothold by its principal and target.
func accessRef(principal, target ref) ref {
	return ref{kind: refAccess, value: principal.value + "\x1f" + target.value}
}

// findingRef names a finding by its title and affected refs.
func findingRef(title string, affected ...ref) ref {
	keys := make([]string, 0, len(affected))
	for _, a := range affected {
		keys = append(keys, a.value)
	}
	sort.Strings(keys)
	return ref{kind: refFinding, value: title + "\x1f" + strings.Join(keys, ",")}
}

// segmentRef names a segment by its label.
func segmentRef(label string) ref { return ref{kind: refSegment, value: label} }

// key is the ref's natural-key string, for the index and for hashing.
func (r ref) key() string { return r.kind.name() + "\x1f" + r.value }
