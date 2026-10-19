package parsers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// fixtureDir is the shared fixture directory (§11.3): the scanner artifacts the
// parsers are locked against live beside the other testdata.
var fixtureDir = filepath.Join("..", "testdata", "parsers")

// fakeStore records what a parser commits and answers with the effects the
// store would produce, so a test can inspect the batch itself.
type fakeStore struct {
	snapshot engagementstate.Snapshot
	queries  []engagementstate.Query
	origins  []engagementstate.Origin
	batches  [][]engagementstate.Op
	err      error
}

func (f *fakeStore) Query(q engagementstate.Query) (engagementstate.Snapshot, error) {
	f.queries = append(f.queries, q)
	return f.snapshot, nil
}

func (f *fakeStore) Update(_ context.Context, origin engagementstate.Origin, ops []engagementstate.Op) (engagementstate.Receipt, error) {
	if f.err != nil {
		return engagementstate.Receipt{}, f.err
	}
	f.origins = append(f.origins, origin)
	f.batches = append(f.batches, ops)
	receipt := engagementstate.Receipt{Revision: len(f.batches)}
	for _, op := range ops {
		effect := engagementstate.Effect{Op: op.Op}
		switch op.Op {
		case engagementstate.OpUpsertEntity:
			effect.Kind, effect.ID, effect.Created = string(op.Kind), op.ID, true
		case engagementstate.OpUpsertFinding:
			effect.Kind, effect.ID, effect.Created = string(engagementstate.KindFinding), op.ID, true
		case engagementstate.OpAddEdge:
			effect.Kind = "edge"
			effect.ID = op.Type + "|" + op.From + "|" + op.To
			effect.Created = true
		}
		receipt.Effects = append(receipt.Effects, effect)
	}
	return receipt, nil
}

// artifact returns a request for one fixture, as the tool would build it.
func artifact(t *testing.T, tool, name string) Request {
	t.Helper()
	path := filepath.Join(fixtureDir, name)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return Request{
		Tool:     tool,
		Artifact: ".styx/out/" + name,
		Path:     path,
		Origin:   engagementstate.Origin{Tool: tool},
	}
}

// run parses a fixture through a recording store.
func run(t *testing.T, tool, name string) (Receipt, []engagementstate.Op, *fakeStore) {
	t.Helper()
	store := &fakeStore{}
	req := artifact(t, tool, name)
	req.Store = store
	receipt, err := Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run(%s, %s) = %v", tool, name, err)
	}
	if len(store.batches) != 1 {
		t.Fatalf("store batches = %d, want exactly one atomic batch (§5)", len(store.batches))
	}
	return receipt, store.batches[0], store
}

// findOp returns the first op matching a predicate.
func findOp(ops []engagementstate.Op, match func(engagementstate.Op) bool) (engagementstate.Op, bool) {
	for _, op := range ops {
		if match(op) {
			return op, true
		}
	}
	return engagementstate.Op{}, false
}

func TestNmapParseWritesHostsServicesAndTheSegment(t *testing.T) {
	receipt, ops, store := run(t, NmapParse, "nmap-scan.xml")

	host, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpUpsertEntity && op.Kind == engagementstate.KindHost
	})
	if !ok {
		t.Fatalf("no host op in the batch: %+v", ops)
	}
	if len(host.Addresses) == 0 || host.Addresses[0] != "10.0.0.5" {
		t.Errorf("host addresses = %v, want the scanned address first", host.Addresses)
	}
	if host.Hostname != "web01.acme.example" || host.OS != "Linux 5.15 - 6.1" {
		t.Errorf("host = %+v, want the PTR name and the OS match", host)
	}
	if host.ID != mintedID(hostRef("10.0.0.5")) {
		t.Errorf("host id = %q, want the natural-key id", host.ID)
	}

	service, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpUpsertEntity && op.Kind == engagementstate.KindService && op.Port == 443
	})
	if !ok {
		t.Fatalf("no 443 service op: %+v", ops)
	}
	if service.Host != "10.0.0.5" || service.Proto != "tcp" || service.State != engagementstate.StateOpen {
		t.Errorf("service = %+v, want an open tcp service on the host", service)
	}
	if service.Product != "nginx" || service.Version != "1.24.0" {
		t.Errorf("service banner = %q/%q, want nginx 1.24.0", service.Product, service.Version)
	}

	// A filtered port is not a service; a udp port is (the store accepts both
	// protocols), and the port with no banner keeps its nmap service name.
	if _, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Kind == engagementstate.KindService && op.Port == 8080
	}); ok {
		t.Error("the filtered 8080 port should not be recorded as a service")
	}
	if _, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Kind == engagementstate.KindService && op.Port == 161 && op.Proto == "udp"
	}); !ok {
		t.Error("the open udp 161 service is missing")
	}

	segment, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpUpsertEntity && op.Kind == engagementstate.KindSegment
	})
	if !ok || segment.Label != "10.0.0.0/24" {
		t.Errorf("segment = %+v, want the scanned 10.0.0.0/24", segment)
	}
	for _, want := range []engagementstate.EdgeType{engagementstate.EdgeRunsOn, engagementstate.EdgeInSegment} {
		if _, ok := findOp(ops, func(op engagementstate.Op) bool { return op.Type == string(want) }); !ok {
			t.Errorf("no %s edge in the batch: %+v", want, ops)
		}
	}
	if _, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Type == string(engagementstate.EdgeResolvesTo)
	}); ok {
		t.Error("nmap records a host's PTR name on the host itself; a RESOLVES_TO edge would relate one node to itself")
	}

	if receipt.Entities["host"].New != 1 || receipt.Entities["service"].New != 3 {
		t.Errorf("receipt entities = %+v, want 1 host and 3 services", receipt.Entities)
	}
	if receipt.Edges["RUNS_ON"] != 3 || receipt.Edges["IN_SEGMENT"] != 1 {
		t.Errorf("receipt edges = %+v, want 3 RUNS_ON and 1 IN_SEGMENT", receipt.Edges)
	}
	if receipt.Findings != nil {
		t.Error("nmap ports are facts, not vulnerabilities: the parse writes no findings (§6)")
	}
	if store.queries[0].Limit != indexLimit || !store.queries[0].IncludeInactive {
		t.Errorf("pre-parse read = %+v, want the full index read", store.queries[0])
	}
	if !strings.Contains(strings.Join(receipt.Warnings, "\n"), "reported down") {
		t.Errorf("warnings = %v, want the down-host note", receipt.Warnings)
	}
	if !strings.Contains(strings.Join(receipt.Warnings, "\n"), "closed or filtered") {
		t.Errorf("warnings = %v, want the non-open-port note", receipt.Warnings)
	}
}

func TestNucleiParseWritesFindingsWithEvidence(t *testing.T) {
	receipt, ops, _ := run(t, NucleiParse, "nuclei-results.jsonl")

	critical, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpUpsertFinding && op.Title == "Apache Log4j2 Remote Code Execution"
	})
	if !ok {
		t.Fatalf("no Log4j finding: %+v", ops)
	}
	if critical.Severity != engagementstate.SeverityCritical || critical.Confidence != engagementstate.ConfidenceMedium {
		t.Errorf("finding = %+v, want critical/medium per §6", critical)
	}
	if len(critical.Affected) != 1 || critical.Affected[0] != "10.0.0.5" {
		t.Errorf("affected = %v, want the resolved host", critical.Affected)
	}
	if _, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpAttachEvidence && op.Finding == critical.ID &&
			op.EvidenceKind == engagementstate.EvidenceHTTPResponse && strings.Contains(op.Ref, "jndi:ldap")
	}); !ok {
		t.Error("the request/response excerpt is not attached as http-response evidence")
	}
	if _, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpAttachEvidence && op.Finding == critical.ID &&
			op.EvidenceKind == engagementstate.EvidenceArtifact && op.Ref == ".styx/out/nuclei-results.jsonl"
	}); !ok {
		t.Error("the artifact is not cited as evidence")
	}

	// The unknown severity is recorded as info; the invented one is skipped.
	if _, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpUpsertFinding && op.Title == "Something Odd"
	}); ok {
		t.Error("an unrecognized severity should be skipped, not guessed")
	}
	if len(receipt.Skipped) < 2 {
		t.Errorf("skipped = %+v, want the bad-severity record and the malformed line", receipt.Skipped)
	}
	if receipt.Findings == nil || receipt.Findings.New != 2 {
		t.Errorf("receipt findings = %+v, want the two valid findings", receipt.Findings)
	}

	// The matched ports become services, and the host is written once.
	hosts, services := 0, 0
	for _, op := range ops {
		switch {
		case op.Op == engagementstate.OpUpsertEntity && op.Kind == engagementstate.KindHost:
			hosts++
		case op.Op == engagementstate.OpUpsertEntity && op.Kind == engagementstate.KindService:
			services++
		}
	}
	if hosts != 1 {
		t.Errorf("host ops = %d, want one deduplicated host", hosts)
	}
	if services != 2 {
		t.Errorf("service ops = %d, want 443 and 8080", services)
	}
}

func TestSQLMapParseWritesFindingsCredentialsAndAccess(t *testing.T) {
	receipt, ops, _ := run(t, SQLMapParse, "sqlmap-10.0.0.5.log")

	injection, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpUpsertFinding && strings.HasPrefix(op.Title, "SQL injection in GET parameter 'id'")
	})
	if !ok {
		t.Fatalf("no injection finding: %+v", ops)
	}
	if injection.Severity != engagementstate.SeverityHigh || injection.Confidence != engagementstate.ConfidenceHigh {
		t.Errorf("finding = %+v, want high/high per §6", injection)
	}
	if _, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpUpsertFinding && strings.HasPrefix(op.Title, "SQL injection in POST parameter 'user'")
	}); !ok {
		t.Error("the second injectable parameter is missing")
	}

	// Two dumped hashes become credentials; the NULL one is skipped.
	if receipt.Entities["credential"].New != 2 {
		t.Errorf("credentials = %+v, want the two dumped hashes", receipt.Entities["credential"])
	}
	credential, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Kind == engagementstate.KindCredential && op.Principal == "root"
	})
	if !ok || credential.Type != engagementstate.CredentialHash || credential.Secret != "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19" {
		t.Errorf("credential = %+v, want root's dumped hash", credential)
	}
	for _, want := range []engagementstate.EdgeType{
		engagementstate.EdgeRunsOn, engagementstate.EdgeCredentialFrom, engagementstate.EdgeValidFor,
	} {
		if _, ok := findOp(ops, func(op engagementstate.Op) bool { return op.Type == string(want) }); !ok {
			t.Errorf("no %s edge in the batch: %+v", want, ops)
		}
	}

	access, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Kind == engagementstate.KindAccess
	})
	if !ok {
		t.Fatalf("no access record for the DBA report: %+v", ops)
	}
	if access.Principal != "root@localhost" || access.Level != engagementstate.LevelAdmin {
		t.Errorf("access = %+v, want root@localhost at admin", access)
	}
	if access.Via != injection.ID {
		t.Errorf("access.via = %q, want the injection finding %q it came through", access.Via, injection.ID)
	}
	if !strings.Contains(strings.Join(receipt.Warnings, "\n"), "listed without secrets") {
		t.Errorf("warnings = %v, want the user-list note", receipt.Warnings)
	}
}

func TestGobusterDirParseCollapsesPathsIntoOneFinding(t *testing.T) {
	receipt, ops, _ := run(t, GobusterParse, "gobuster-dir.txt")

	findings := 0
	for _, op := range ops {
		if op.Op == engagementstate.OpUpsertFinding {
			findings++
		}
	}
	if findings != 1 {
		t.Fatalf("findings = %d, want one info finding carrying the path list (§6)", findings)
	}
	finding, _ := findOp(ops, func(op engagementstate.Op) bool { return op.Op == engagementstate.OpUpsertFinding })
	if finding.Severity != engagementstate.SeverityInfo || finding.Confidence != engagementstate.ConfidenceLow {
		t.Errorf("finding = %+v, want info/low", finding)
	}
	evidence, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpAttachEvidence && op.EvidenceKind == engagementstate.EvidenceCLIOutput
	})
	if !ok {
		t.Fatal("the path list is not attached as cli-output evidence")
	}
	for _, path := range []string{"/admin", "/api", "/login", "/backup.sql"} {
		if !strings.Contains(evidence.Ref, path) {
			t.Errorf("evidence is missing %s: %q", path, evidence.Ref)
		}
	}
	if strings.Contains(evidence.Ref, "server-status") {
		t.Error("a Missed line is not a discovered path")
	}
	service, ok := findOp(ops, func(op engagementstate.Op) bool { return op.Kind == engagementstate.KindService })
	if !ok || service.Port != 8080 {
		t.Errorf("service = %+v, want the banner URL's 8080", service)
	}
	if receipt.Edges["RUNS_ON"] != 1 {
		t.Errorf("edges = %+v, want the host's RUNS_ON", receipt.Edges)
	}
}

func TestGobusterDnsParseRelatesNamesToTheirAddresses(t *testing.T) {
	_, ops, _ := run(t, GobusterParse, "gobuster-dns.txt")

	hosts := map[string]bool{}
	for _, op := range ops {
		if op.Kind == engagementstate.KindHost && len(op.Addresses) > 0 {
			hosts[op.Addresses[0]] = true
		}
	}
	for _, want := range []string{"dev.acme.example", "jenkins.acme.example", "vpn.acme.example", "10.0.0.11", "10.0.0.12"} {
		if !hosts[want] {
			t.Errorf("host %q is missing from %v", want, hosts)
		}
	}
	resolves := 0
	for _, op := range ops {
		if op.Type != string(engagementstate.EdgeResolvesTo) {
			continue
		}
		resolves++
		if op.From == op.To {
			t.Errorf("RESOLVES_TO relates a node to itself: %+v", op)
		}
	}
	if resolves != 2 {
		t.Errorf("RESOLVES_TO edges = %d, want the two names that carried an address", resolves)
	}
	if _, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Type == string(engagementstate.EdgeResolvesTo) && op.To == "10.0.0.11"
	}); !ok {
		t.Error("dev.acme.example is not related to the address gobuster printed for it")
	}
}

func TestCMEParseWritesCredentialsAccessAndTheSigningFinding(t *testing.T) {
	receipt, ops, _ := run(t, CMEParse, "cme-10.0.0.5.log")

	credential, ok := findOp(ops, func(op engagementstate.Op) bool { return op.Kind == engagementstate.KindCredential })
	if !ok {
		t.Fatalf("no credential: %+v", ops)
	}
	if credential.Principal != `ACME.LOCAL\admin` || credential.Secret != "hunter2" {
		t.Errorf("credential = %+v, want the working login", credential)
	}
	if credential.Type != engagementstate.CredentialPassword {
		t.Errorf("credential type = %q, want password", credential.Type)
	}
	access, ok := findOp(ops, func(op engagementstate.Op) bool { return op.Kind == engagementstate.KindAccess })
	if !ok || access.Level != engagementstate.LevelAdmin {
		t.Errorf("access = %+v, want an admin foothold for the Pwn3d! login", access)
	}
	if access.Principal != credential.ID || access.Target != "10.0.0.5" {
		t.Errorf("access = %+v, want the credential on the host", access)
	}
	for _, want := range []engagementstate.EdgeType{
		engagementstate.EdgeValidFor, engagementstate.EdgeAdminOf, engagementstate.EdgePivotTo, engagementstate.EdgeRunsOn,
	} {
		if _, ok := findOp(ops, func(op engagementstate.Op) bool { return op.Type == string(want) }); !ok {
			t.Errorf("no %s edge: %+v", want, ops)
		}
	}

	signing, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpUpsertFinding && op.Title == "SMB signing disabled"
	})
	if !ok || signing.Severity != engagementstate.SeverityMedium {
		t.Errorf("signing finding = %+v, want the medium-severity SMB signing finding", signing)
	}
	positive, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Op == engagementstate.OpUpsertFinding && op.Title == "LSA Secrets"
	})
	if !ok || positive.Severity != engagementstate.SeverityInfo {
		t.Errorf("module result = %+v, want an info finding", positive)
	}
	if !strings.Contains(strings.Join(receipt.Warnings, "\n"), "states none") {
		t.Errorf("warnings = %v, want the no-severity note", receipt.Warnings)
	}

	// The failed logins are not observations, and only one credential exists.
	if receipt.Entities["credential"].New != 1 {
		t.Errorf("credentials = %+v, want only the working login", receipt.Entities["credential"])
	}
	host, _ := findOp(ops, func(op engagementstate.Op) bool { return op.Kind == engagementstate.KindHost })
	if host.OS != "Windows Server 2019 Build 17763 x64" || host.Hostname != "DC01" {
		t.Errorf("host = %+v, want the banner's OS and machine name", host)
	}
}

func TestBloodHoundParseWritesComputersAndFootholds(t *testing.T) {
	receipt, ops, _ := run(t, BloodHoundParse, "bloodhound-computers.json")

	dc, ok := findOp(ops, func(op engagementstate.Op) bool {
		return op.Kind == engagementstate.KindHost && len(op.Addresses) > 0 && op.Addresses[0] == "DC01.ACME.LOCAL"
	})
	if !ok || dc.OS != "Windows Server 2019 Standard" {
		t.Errorf("host = %+v, want the domain controller", dc)
	}
	admins, users := 0, 0
	for _, op := range ops {
		if op.Kind != engagementstate.KindAccess {
			continue
		}
		switch op.Level {
		case engagementstate.LevelAdmin:
			admins++
		case engagementstate.LevelUser:
			users++
		}
		if op.Principal == "" {
			t.Errorf("access without a principal: %+v", op)
		}
	}
	// Two sessions on DC01, one on FILE01; one local admin on each.
	if users != 3 || admins != 2 {
		t.Errorf("access levels = %d user / %d admin, want 3/2", users, admins)
	}
	for _, want := range []engagementstate.EdgeType{engagementstate.EdgeAdminOf, engagementstate.EdgePivotTo} {
		if _, ok := findOp(ops, func(op engagementstate.Op) bool { return op.Type == string(want) }); !ok {
			t.Errorf("no %s edge: %+v", want, ops)
		}
	}
	if receipt.Findings != nil {
		t.Error("a BloodHound collector exposes no vulnerabilities: the parse writes no findings")
	}
	// A computers-only document has nothing deferred to report.
	if len(receipt.Warnings) != 0 {
		t.Errorf("warnings = %v, want none for a computers-only artifact", receipt.Warnings)
	}
}

func TestUnrecognizedArtifactsAreRefusedWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(path, []byte("just some notes about the engagement\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, tool := range Names() {
		t.Run(tool, func(t *testing.T) {
			store := &fakeStore{}
			_, err := Run(context.Background(), Request{
				Tool: tool, Artifact: ".styx/out/notes.txt", Path: path, Store: store,
			})
			if !errors.Is(err, ErrNotParsed) {
				t.Fatalf("Run(%s, notes) = %v, want a format refusal", tool, err)
			}
			var format *FormatError
			if !errors.As(err, &format) {
				t.Fatalf("error = %T, want *FormatError", err)
			}
			if format.Format == "" || format.Artifact != ".styx/out/notes.txt" || format.Sample == "" {
				t.Errorf("refusal = %+v, want the format, the artifact, and a sample (§7)", format)
			}
			if len(store.batches) != 0 {
				t.Errorf("a refusal wrote %d batch(es)", len(store.batches))
			}
		})
	}
}

func TestMissingArtifactAndEmptyStoreAreRefused(t *testing.T) {
	req := artifact(t, NmapParse, "nmap-scan.xml")
	req.Path = filepath.Join(t.TempDir(), "gone.xml")
	req.Store = &fakeStore{}
	if _, err := Run(context.Background(), req); err == nil {
		t.Error("a missing artifact should be refused")
	}

	req = artifact(t, NmapParse, "nmap-scan.xml")
	if _, err := Run(context.Background(), req); err == nil {
		t.Error("a parse with no store should be refused")
	}

	req.Store = &fakeStore{}
	req.Tool = "nmap_parse_typo"
	if _, err := Run(context.Background(), req); err == nil {
		t.Error("an unknown tool name should be refused")
	}
}

func TestArtifactBeyondTheCeilingIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.xml")
	//nolint:gosec // the path is the test's own temp directory.
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := file.Truncate(MaxArtifactBytes + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	store := &fakeStore{}
	_, err = Run(context.Background(), Request{
		Tool: NmapParse, Artifact: ".styx/out/huge.xml", Path: path, Store: store,
	})
	if err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("Run(huge) = %v, want the size ceiling refusal", err)
	}
	if len(store.batches) != 0 {
		t.Error("an oversized artifact wrote a batch")
	}
}

// storeHarness is a real engagement-state store in a temporary root, for the
// tests that must prove what actually lands in state.
func storeHarness(t *testing.T) *engagementstate.Store {
	t.Helper()
	store, err := engagementstate.Open("/work/acme", "acme-q4", engagementstate.WithRoot(t.TempDir()))
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// runReal parses a fixture into a real store.
func runReal(t *testing.T, tool, name string, store *engagementstate.Store) Receipt {
	t.Helper()
	req := artifact(t, tool, name)
	req.Store = store
	receipt, err := Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run(%s, %s) = %v", tool, name, err)
	}
	return receipt
}

func TestReParseUpdatesRatherThanDuplicating(t *testing.T) {
	store := storeHarness(t)
	first := runReal(t, NmapParse, "nmap-scan.xml", store)
	revision := store.Snapshot().Revision
	second := runReal(t, NmapParse, "nmap-scan.xml", store)

	_ = first
	if store.Snapshot().Revision != revision+1 {
		t.Errorf("revision = %d, want one commit per parse", store.Snapshot().Revision)
	}
	if second.Entities["host"].New != 0 || second.Entities["service"].New != 0 {
		t.Errorf("re-parse entities = %+v, want every record reused (§8)", second.Entities)
	}
	if second.Entities["host"].Updated != first.Entities["host"].New {
		t.Errorf("re-parse host updates = %+v, want the first parse's hosts", second.Entities["host"])
	}
	if len(store.Snapshot().Entities) != 5 {
		t.Errorf("entities = %d, want 1 host + 3 services + 1 segment", len(store.Snapshot().Entities))
	}
	if len(store.Snapshot().Edges) != 4 {
		t.Errorf("edges = %d, want 3 RUNS_ON + 1 IN_SEGMENT", len(store.Snapshot().Edges))
	}
}

// TestOneIdentityAcrossParsers: a service nmap found and nuclei matched keeps
// one record and one id, whichever parser wrote it first.
func TestOneIdentityAcrossParsers(t *testing.T) {
	store := storeHarness(t)
	runReal(t, NmapParse, "nmap-scan.xml", store)
	nuclei := runReal(t, NucleiParse, "nuclei-results.jsonl", store)

	snapshot := store.Snapshot()
	services := 0
	for _, e := range snapshot.Entities {
		if e.Kind != engagementstate.KindService {
			continue
		}
		services++
		if e.Port == 443 && e.ID != mintedID(serviceRef("10.0.0.5", 443, "tcp")) {
			t.Errorf("service id = %q, want the shared natural-key id", e.ID)
		}
	}
	if services != 4 {
		t.Errorf("services = %d, want the nmap 22/443/161 plus nuclei's 8080", services)
	}
	if nuclei.Entities["service"].New != 1 {
		t.Errorf("nuclei services = %+v, want only its new 8080", nuclei.Entities["service"])
	}
	if nuclei.Entities["host"] != (Counts{Updated: 1}) {
		t.Errorf("nuclei host = %+v, want the host nmap already recorded", nuclei.Entities["host"])
	}
}

// TestEvidenceAttachesToARecordTheModelWrote covers the mixed-authorship case
// the index exists for: a finding recorded through state_update (a random id)
// is re-detected by a parser, which must reference the id the store holds.
func TestEvidenceAttachesToARecordTheModelWrote(t *testing.T) {
	store := storeHarness(t)
	if _, err := store.Update(context.Background(), engagementstate.Origin{Tool: "state_update"}, []engagementstate.Op{
		{Op: engagementstate.OpUpsertEntity, Kind: engagementstate.KindHost, Addresses: []string{"10.0.0.5"}},
		{Op: engagementstate.OpUpsertFinding, Title: "Apache Log4j2 Remote Code Execution", Severity: engagementstate.SeverityCritical, Affected: []string{"10.0.0.5"}},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	receipt := runReal(t, NucleiParse, "nuclei-results.jsonl", store)

	if receipt.Findings.New != 1 || receipt.Findings.Updated != 1 {
		t.Errorf("findings = %+v, want the model's record updated, not duplicated", receipt.Findings)
	}
	snapshot := store.Snapshot()
	if len(snapshot.Findings) != 2 {
		t.Fatalf("findings = %d, want the seeded one plus the artifact's second template", len(snapshot.Findings))
	}
	for _, finding := range snapshot.Findings {
		if finding.Title != "Apache Log4j2 Remote Code Execution" {
			continue
		}
		if finding.Provenance.Source != NucleiParse {
			t.Errorf("provenance = %+v, want the parser's write", finding.Provenance)
		}
		if finding.EvidenceCount() != 2 {
			t.Errorf("evidence = %d, want the excerpt and the artifact on the existing record", finding.EvidenceCount())
		}
	}
}

// TestReceiptMatchesTheContractShape pins the receipt's JSON to §5.
func TestReceiptMatchesTheContractShape(t *testing.T) {
	receipt, _, _ := run(t, NmapParse, "nmap-scan.xml")
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"tool", "artifact", "ok", "entities", "edges", "created_ids", "warnings"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("receipt is missing %q: %s", key, encoded)
		}
	}
	if decoded["tool"] != NmapParse || decoded["ok"] != true {
		t.Errorf("receipt = %s, want the tool name and ok", encoded)
	}
	entities, _ := decoded["entities"].(map[string]any)
	host, _ := entities["host"].(map[string]any)
	if host["new"] != float64(1) {
		t.Errorf("entities.host = %v, want {new:1}", host)
	}
	edges, _ := decoded["edges"].(map[string]any)
	if edges["RUNS_ON"] != float64(3) {
		t.Errorf("edges = %v, want RUNS_ON counted by type", edges)
	}
	created, _ := decoded["created_ids"].([]any)
	if len(created) != 5 {
		t.Errorf("created_ids = %v, want the five records the parse created", created)
	}
}

// TestSQLMapAccessMirrorsItsEdge: the access op's `via` is the canonical
// EXPLOITED_VIA edge's mirror, so the store writes both in one batch.
func TestSQLMapAccessMirrorsItsEdge(t *testing.T) {
	store := storeHarness(t)
	runReal(t, SQLMapParse, "sqlmap-10.0.0.5.log", store)

	snapshot := store.Snapshot()
	accesses := 0
	for _, entity := range snapshot.Entities {
		if entity.Kind != engagementstate.KindAccess {
			continue
		}
		accesses++
		if entity.Via == "" {
			t.Errorf("access %s has no via mirror", entity.ID)
		}
		found := false
		for _, edge := range snapshot.Edges {
			if edge.Type == engagementstate.EdgeExploitedVia && edge.From == entity.Via && edge.To == entity.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("no EXPLOITED_VIA edge for access %s: %+v", entity.ID, snapshot.Edges)
		}
	}
	if accesses != 1 {
		t.Errorf("accesses = %d, want the DBA foothold", accesses)
	}
}

// TestBloodHoundUsersOnlyIsAnEmptySuccess: a document this parse can recognize
// but express nothing from is a success with zero counts (§7), not a refusal —
// and it says why.
func TestBloodHoundUsersOnlyIsAnEmptySuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	document := `{"users": [{"Properties": {"name": "JDOE@ACME.LOCAL", "samaccountname": "jdoe"}}], "meta": {"count": 1, "type": "users"}}`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	store := &fakeStore{}
	receipt, err := Run(context.Background(), Request{
		Tool: BloodHoundParse, Artifact: ".styx/out/users.json", Path: path, Store: store,
	})
	if err != nil {
		t.Fatalf("Run() = %v, want a recognized but empty parse", err)
	}
	if len(store.batches) != 0 {
		t.Errorf("an empty parse committed %d batch(es)", len(store.batches))
	}
	if receipt.Entities != nil || receipt.Findings != nil {
		t.Errorf("receipt = %+v, want zero counts", receipt)
	}
	joined := strings.Join(receipt.Warnings, "\n")
	if !strings.Contains(joined, "AD users (1)") || !strings.Contains(joined, "deferred") {
		t.Errorf("warnings = %v, want the deferred-AD-entity note", receipt.Warnings)
	}
}

func TestStoreFailureLeavesNoPartialState(t *testing.T) {
	store := &fakeStore{err: errors.New("locked by session other")}
	req := artifact(t, NmapParse, "nmap-scan.xml")
	req.Store = store
	if _, err := Run(context.Background(), req); err == nil || !strings.Contains(err.Error(), "write engagement state") {
		t.Fatalf("Run() = %v, want the store failure surfaced", err)
	}
}

func TestOriginReachesTheStore(t *testing.T) {
	store := &fakeStore{}
	req := artifact(t, NmapParse, "nmap-scan.xml")
	req.Store = store
	req.Origin = engagementstate.Origin{Tool: NmapParse, Subagent: "recon"}
	if _, err := Run(context.Background(), req); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if store.origins[0].Tool != NmapParse || store.origins[0].Subagent != "recon" {
		t.Errorf("origin = %+v, want the parser and its subagent", store.origins[0])
	}
}
