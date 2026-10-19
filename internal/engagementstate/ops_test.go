package engagementstate

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestUpsertEntityReusesNaturalKeys(t *testing.T) {
	store := openTestStore(t)

	hostReceipt := mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}, Hostname: "web01.acme.example", OS: "linux"},
	)
	hostID := hostReceipt.Effects[0].ID
	if !hostReceipt.Effects[0].Created {
		t.Errorf("first host upsert should create")
	}

	hostAgain := mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}, Tags: []string{"dmz"}},
	)
	if hostAgain.Effects[0].Created {
		t.Errorf("a matching primary address should reuse the host, got %+v", hostAgain.Effects[0])
	}
	if hostAgain.Effects[0].ID != hostID {
		t.Errorf("host id = %q, want the reused %q", hostAgain.Effects[0].ID, hostID)
	}

	service := mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindService, Host: "10.0.0.7", Port: 445, Proto: "tcp", Product: "smb", State: "open"},
	)
	if !service.Effects[0].Created {
		t.Errorf("first service upsert should create")
	}
	serviceAgain := mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindService, Host: "10.0.0.7", Port: 445, Proto: "tcp", Version: "3.1.1"},
	)
	if serviceAgain.Effects[0].Created || serviceAgain.Effects[0].ID != service.Effects[0].ID {
		t.Errorf("host+port+proto should be the service's natural key: %+v", serviceAgain.Effects[0])
	}

	cred := mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindCredential, Type: "password", Principal: "ACME\\admin", Secret: "hunter2"},
	)
	credAgain := mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindCredential, Type: "password", Principal: "ACME\\admin", Secret: "hunter2"},
	)
	if credAgain.Effects[0].Created || credAgain.Effects[0].ID != cred.Effects[0].ID {
		t.Errorf("principal+type+secret should be the credential's natural key: %+v", credAgain.Effects[0])
	}

	segment := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindSegment, Label: "dmz", CIDRs: []string{"10.0.0.0/24"}})
	segmentAgain := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindSegment, Label: "dmz", CIDRs: []string{"10.0.1.0/24"}})
	if segmentAgain.Effects[0].Created || segmentAgain.Effects[0].ID != segment.Effects[0].ID {
		t.Errorf("label should be the segment's natural key: %+v", segmentAgain.Effects[0])
	}

	snap := store.Snapshot()
	if len(snap.Entities) != 4 {
		t.Fatalf("entities = %d, want 4 (host, service, credential, segment)", len(snap.Entities))
	}
	host, ok := snap.Entity(hostID)
	if !ok {
		t.Fatalf("host %s is missing", hostID)
	}
	if host.Hostname != "web01.acme.example" || host.OS != "linux" {
		t.Errorf("re-upsert dropped attributes: %+v", host)
	}
	if len(host.Tags) != 1 || host.Tags[0] != "dmz" {
		t.Errorf("tags = %v, want the accumulated [dmz]", host.Tags)
	}
	if host.Provenance.Source != "state_update" || host.Provenance.Session != "20261019T120000Z-abcd" {
		t.Errorf("provenance = %+v, want the harness-stamped write", host.Provenance)
	}
	if !host.Provenance.At.Equal(testTime) {
		t.Errorf("provenance time = %s, want the store clock %s", host.Provenance.At, testTime)
	}
}

func TestUpsertRefusesUnknownEnumsAndDanglingRefs(t *testing.T) {
	store := openTestStore(t)
	mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})

	cases := []struct {
		name string
		op   Op
		want string
	}{
		{
			name: "unknown kind",
			op:   Op{Op: OpUpsertEntity, Kind: "domain", Label: "acme"},
			want: "kind \"domain\"",
		},
		{
			name: "finding through the entity op",
			op:   Op{Op: OpUpsertEntity, Kind: KindFinding, Title: "x"},
			want: "upsert_finding",
		},
		{
			name: "host without an address",
			op:   Op{Op: OpUpsertEntity, Kind: KindHost},
			want: "addresses: at least one is required",
		},
		{
			name: "service on an unrecorded host",
			op:   Op{Op: OpUpsertEntity, Kind: KindService, Host: "10.9.9.9", Port: 80, Proto: "tcp"},
			want: "does not resolve",
		},
		{
			name: "service with an unknown protocol",
			op:   Op{Op: OpUpsertEntity, Kind: KindService, Host: "10.0.0.7", Port: 80, Proto: "sctp"},
			want: "want tcp or udp",
		},
		{
			name: "credential without a secret",
			op:   Op{Op: OpUpsertEntity, Kind: KindCredential, Type: "password", Principal: "admin"},
			want: "secret is required",
		},
		{
			name: "segment without ranges",
			op:   Op{Op: OpUpsertEntity, Kind: KindSegment, Label: "dmz"},
			want: "cidrs: at least one is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.Update(context.Background(), Origin{Tool: "state_update"}, []Op{tc.op})
			if !errors.Is(err, ErrOp) {
				t.Fatalf("Update() = %v, want an ErrOp refusal", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal %q should mention %q", err, tc.want)
			}
		})
	}

	// A service with a valid host in the same batch resolves.
	mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindService, Host: "10.0.0.7", Port: 80, Proto: "tcp"})
	_, err := store.Update(context.Background(), Origin{Tool: "state_update"},
		[]Op{{Op: OpUpsertEntity, Kind: KindService, Host: "10.0.0.7", Port: 443, Proto: "sctp"}})
	if err == nil || !strings.Contains(err.Error(), "proto") {
		t.Errorf("Update(bad proto) = %v, want a proto refusal", err)
	}
}

func TestFindingLifecycleAndEvidenceInvariant(t *testing.T) {
	store := openTestStore(t)
	host := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})

	finding := mustUpdate(t, store, Op{
		Op: OpUpsertFinding, Title: "SMB signing disabled", Severity: SeverityMedium,
		Confidence: ConfidenceHigh, Affected: []string{host.Effects[0].ID},
	})
	id := finding.Effects[0].ID

	// Verification cannot advance without evidence.
	_, err := store.Update(context.Background(), Origin{Tool: "state_update"},
		[]Op{{Op: OpSetVerification, Finding: id, Verification: VerificationVerified}})
	if !errors.Is(err, ErrOp) || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("set_verification(verified, no evidence) = %v, want an evidence refusal", err)
	}

	mustUpdate(t, store, Op{Op: OpAttachEvidence, Finding: id, EvidenceKind: EvidenceCLIOutput, Ref: "smbclient -L //10.0.0.7"})
	mustUpdate(t, store, Op{Op: OpSetVerification, Finding: id, Verification: VerificationVerified})

	// Status moves only along the lifecycle.
	if _, err := store.Update(context.Background(), Origin{Tool: "state_update"},
		[]Op{{Op: OpSetStatus, Finding: id, Status: StatusFixed}}); err == nil {
		t.Errorf("detected -> fixed should be refused")
	}
	mustUpdate(t, store, Op{Op: OpSetStatus, Finding: id, Status: StatusConfirmed})
	mustUpdate(t, store, Op{Op: OpSetStatus, Finding: id, Status: StatusFixed})
	mustUpdate(t, store, Op{Op: OpSetStatus, Finding: id, Status: StatusConfirmed})

	f, ok := store.Snapshot().Finding(id)
	if !ok {
		t.Fatalf("finding %s is missing", id)
	}
	if f.Status != StatusConfirmed || f.Verification != VerificationVerified || f.EvidenceCount() != 1 {
		t.Errorf("finding = %+v, want confirmed + verified with one evidence item", f)
	}
	if !f.FirstSeen.Equal(testTime) || !f.LastSeen.Equal(testTime) {
		t.Errorf("first_seen/last_seen = %s/%s, want the store clock", f.FirstSeen, f.LastSeen)
	}
	if f.Evidence[0].Provenance.Source != "state_update" {
		t.Errorf("evidence provenance = %+v, want a harness stamp", f.Evidence[0].Provenance)
	}
}

func TestUpsertFindingReusesItsNaturalKey(t *testing.T) {
	store := openTestStore(t)
	host := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})
	affected := []string{host.Effects[0].ID}

	first := mustUpdate(t, store, Op{Op: OpUpsertFinding, Title: "Open SMB", Severity: SeverityHigh, Affected: affected})
	second := mustUpdate(t, store, Op{Op: OpUpsertFinding, Title: "Open SMB", Severity: SeverityCritical, Affected: affected})
	if second.Effects[0].Created || second.Effects[0].ID != first.Effects[0].ID {
		t.Errorf("title + affected should be the natural key: %+v", second.Effects[0])
	}
	f, _ := store.Snapshot().Finding(first.Effects[0].ID)
	if f.Severity != SeverityCritical {
		t.Errorf("severity = %q, want the update's critical", f.Severity)
	}
	if f.Status != StatusDetected || f.Verification != VerificationUnverified {
		t.Errorf("an ordinary re-upsert must not advance status or verification: %+v", f)
	}

	// A new finding cannot be born past the lifecycle's entry point.
	if _, err := store.Update(context.Background(), Origin{Tool: "state_update"},
		[]Op{{Op: OpUpsertFinding, Title: "Fresh", Severity: SeverityLow, Status: StatusConfirmed}}); err == nil {
		t.Errorf("a new finding declaring status confirmed should be refused")
	}
}

func TestEdgeEndpointsAreValidatedAndAccessViaMirrors(t *testing.T) {
	store := openTestStore(t)
	host := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})
	hostID := host.Effects[0].ID
	service := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindService, Host: hostID, Port: 445, Proto: "tcp"})
	serviceID := service.Effects[0].ID
	finding := mustUpdate(t, store, Op{Op: OpUpsertFinding, Title: "EternalBlue", Severity: SeverityCritical, Affected: []string{hostID}})
	findingID := finding.Effects[0].ID

	mustUpdate(t, store, Op{
		Op: OpUpsertEntity, Kind: KindAccess, Principal: "ACME\\admin", Target: serviceID, Level: "admin", Via: findingID,
	})
	accessID := store.Snapshot().Entities[len(store.Snapshot().Entities)-1].ID

	edges := store.Snapshot().Edges
	if len(edges) != 1 || edges[0].Type != EdgeExploitedVia || edges[0].From != findingID || edges[0].To != accessID {
		t.Fatalf("edges = %+v, want one EXPLOITED_VIA %s -> %s", edges, findingID, accessID)
	}
	access, _ := store.Snapshot().Entity(accessID)
	if access.Via != findingID {
		t.Errorf("access.via = %q, want the finding mirror", access.Via)
	}

	// The reverse direction maintains the same mirror.
	mustUpdate(t, store, Op{Op: OpRemoveEdge, Type: string(EdgeExploitedVia), From: findingID, To: accessID})
	access, _ = store.Snapshot().Entity(accessID)
	if access.Via != "" {
		t.Errorf("removing the mirror's edge should clear via, got %q", access.Via)
	}
	mustUpdate(t, store, Op{Op: OpAddEdge, Type: string(EdgeExploitedVia), From: findingID, To: accessID, Confidence: "high"})
	access, _ = store.Snapshot().Entity(accessID)
	if access.Via != findingID {
		t.Errorf("adding the mirror's edge should restore via, got %q", access.Via)
	}

	// Typed endpoints: RUNS_ON runs service -> host, never the reverse.
	if _, err := store.Update(context.Background(), Origin{Tool: "state_update"},
		[]Op{{Op: OpAddEdge, Type: string(EdgeRunsOn), From: hostID, To: serviceID}}); !errors.Is(err, ErrOp) {
		t.Errorf("RUNS_ON host -> service = %v, want an endpoint refusal", err)
	}
	if _, err := store.Update(context.Background(), Origin{Tool: "state_update"},
		[]Op{{Op: OpAddEdge, Type: "LATERAL", From: hostID, To: serviceID}}); !errors.Is(err, ErrOp) {
		t.Errorf("unknown edge type = %v, want a refusal", err)
	}
	if _, err := store.Update(context.Background(), Origin{Tool: "state_update"},
		[]Op{{Op: OpAddEdge, Type: string(EdgeRunsOn), From: serviceID, To: "host-ffff"}}); !errors.Is(err, ErrOp) {
		t.Errorf("dangling endpoint = %v, want a refusal", err)
	}

	// An edge upsert is idempotent and carries confidence.
	first := mustUpdate(t, store, Op{Op: OpAddEdge, Type: string(EdgeRunsOn), From: serviceID, To: hostID, Confidence: "high"})
	second := mustUpdate(t, store, Op{Op: OpAddEdge, Type: string(EdgeRunsOn), From: serviceID, To: hostID, Confidence: "high"})
	if !first.Effects[0].Created || second.Effects[0].Created {
		t.Errorf("re-adding an edge should update, not duplicate: %+v / %+v", first.Effects[0], second.Effects[0])
	}
	if _, err := store.Update(context.Background(), Origin{Tool: "state_update"},
		[]Op{{Op: OpRemoveEdge, Type: string(EdgeRunsOn), From: serviceID, To: hostID},
			{Op: OpRemoveEdge, Type: string(EdgeRunsOn), From: serviceID, To: hostID}}); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing a missing edge = %v, want ErrNotFound", err)
	}
}

func TestBatchIsAtomic(t *testing.T) {
	store := openTestStore(t)
	before := store.Snapshot()

	_, err := store.Update(context.Background(), Origin{Tool: "state_update"}, []Op{
		{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}},
		{Op: OpUpsertEntity, Kind: KindService, Host: "10.0.0.7", Port: 445, Proto: "tcp"},
		{Op: OpUpsertEntity, Kind: KindSegment, Label: "dmz", CIDRs: []string{"not-a-cidr"}},
	})
	if err == nil {
		t.Fatalf("Update(one bad op) = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "ops_json[3]") {
		t.Errorf("refusal %q should name the failing op's position", err)
	}

	after := store.Snapshot()
	if after.Revision != before.Revision {
		t.Errorf("revision = %d, want it unchanged at %d", after.Revision, before.Revision)
	}
	if len(after.Entities) != 0 {
		t.Errorf("entities = %d, want none: a refused batch writes nothing", len(after.Entities))
	}
	if _, err := os.Stat(store.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused batch should not create the document: %v", err)
	}

	// The same batch with a valid CIDR commits wholly.
	receipt := mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}},
		Op{Op: OpUpsertEntity, Kind: KindService, Host: "10.0.0.7", Port: 445, Proto: "tcp"},
		Op{Op: OpUpsertEntity, Kind: KindSegment, Label: "dmz", CIDRs: []string{"10.0.0.0/24"}},
	)
	if len(receipt.Effects) != 3 || receipt.Revision != 1 {
		t.Errorf("receipt = %+v, want three effects at revision 1", receipt)
	}
	if got := len(store.Snapshot().Entities); got != 3 {
		t.Errorf("entities = %d, want 3", got)
	}
}

func TestDecodeOpsRefusesModelSuppliedProvenance(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"source", `[{"op":"upsert_entity","kind":"host","addresses":["10.0.0.7"],"source":"nmap_parse"}]`},
		{"session", `[{"op":"upsert_entity","kind":"host","addresses":["10.0.0.7"],"session":"someone-else"}]`},
		{"time", `[{"op":"upsert_entity","kind":"host","addresses":["10.0.0.7"],"at":"2020-01-01T00:00:00Z"}]`},
		{"provenance", `[{"op":"upsert_entity","kind":"host","addresses":["10.0.0.7"],"provenance":{"source":"x"}}]`},
		{"unknown field", `[{"op":"upsert_entity","kind":"host","addresses":["10.0.0.7"],"verified":true}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeOps(tc.raw); err == nil {
				t.Fatalf("DecodeOps(%s) = nil error, want provenance to be unrepresentable", tc.raw)
			}
		})
	}

	ops, err := DecodeOps(`[{"op":"upsert_entity","kind":"host","addresses":["10.0.0.7"]}]`)
	if err != nil {
		t.Fatalf("DecodeOps(valid) = %v", err)
	}
	if len(ops) != 1 || ops[0].Op != OpUpsertEntity {
		t.Errorf("DecodeOps(valid) = %+v", ops)
	}

	for _, raw := range []string{"", "  ", "{}", "[]", `[{"kind":"host"}]`, `[{"op":"upsert_entity"}] trailing`} {
		if _, err := DecodeOps(raw); err == nil {
			t.Errorf("DecodeOps(%q) = nil error, want a refusal", raw)
		}
	}
}

func TestUnknownOpIsRefused(t *testing.T) {
	store := openTestStore(t)
	_, err := store.Update(context.Background(), Origin{Tool: "state_update"}, []Op{{Op: "delete_entity", ID: "host-0001"}})
	if !errors.Is(err, ErrOp) || !strings.Contains(err.Error(), "unknown op") {
		t.Fatalf("Update(unknown op) = %v, want an unknown-op refusal", err)
	}
	if _, err := store.Update(context.Background(), Origin{}, nil); !errors.Is(err, ErrOp) {
		t.Errorf("Update(no ops) = %v, want a refusal", err)
	}
}

func TestUpdateStampsTheWritingToolAndSubagent(t *testing.T) {
	store := openTestStore(t)
	receipt, err := store.Update(context.Background(), Origin{Tool: "nmap_parse", Subagent: "recon"},
		[]Op{{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}}})
	if err != nil {
		t.Fatalf("Update() = %v", err)
	}
	host, _ := store.Snapshot().Entity(receipt.Effects[0].ID)
	if host.Provenance.Source != "nmap_parse" || host.Provenance.Subagent != "recon" {
		t.Errorf("provenance = %+v, want the parser tool and its subagent", host.Provenance)
	}
}

func TestUpdateRespectsACanceledCall(t *testing.T) {
	store := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Update(ctx, Origin{Tool: "state_update"},
		[]Op{{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Update(canceled) = %v, want context.Canceled", err)
	}
	if len(store.Snapshot().Entities) != 0 {
		t.Errorf("a canceled call must not write")
	}
}

func TestDeactivationInsteadOfDeletion(t *testing.T) {
	store := openTestStore(t)
	receipt := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})
	id := receipt.Effects[0].ID

	inactive := false
	mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}, Active: &inactive})
	host, _ := store.Snapshot().Entity(id)
	if host.Active {
		t.Errorf("upsert with active:false should deactivate the record")
	}
	if len(store.Snapshot().Entities) != 1 {
		t.Errorf("deactivation is not deletion: the record stays")
	}
	if host.UpdatedAt.Before(host.CreatedAt) {
		t.Errorf("updated_at %s precedes created_at %s", host.UpdatedAt, host.CreatedAt)
	}
}

func TestAccessPrincipalMustNotNameAnotherKind(t *testing.T) {
	store := openTestStore(t)
	host := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})
	hostID := host.Effects[0].ID

	if _, err := store.Update(context.Background(), Origin{Tool: "state_update"},
		[]Op{{Op: OpUpsertEntity, Kind: KindAccess, Principal: hostID, Target: hostID}}); !errors.Is(err, ErrOp) {
		t.Errorf("an access principal naming a host = %v, want a refusal", err)
	}
	// A bare account name is fine.
	mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindAccess, Principal: "ACME\\svc-backup", Target: hostID, Level: "user"})
	// A credential id is fine too.
	cred := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindCredential, Type: "hash", Principal: "admin", Secret: "aad3b435"})
	mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindAccess, Principal: cred.Effects[0].ID, Target: hostID, Level: "admin"})
	if got := len(store.Snapshot().Entities); got != 4 {
		t.Errorf("entities = %d, want host + credential + two access records", got)
	}
}

// TestOneBatchCanReferenceWhatItCreates is the parser contract's commit shape
// (docs/parser-tool-contracts.md §5): a single atomic batch writes a host, a
// service, a finding with its evidence, a credential, and the edges among them,
// naming the records the same batch creates. Without a settable id the batch
// could not be expressed at all, because only the store knows an id it mints.
func TestOneBatchCanReferenceWhatItCreates(t *testing.T) {
	store := openTestStore(t)
	receipt := mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}, Hostname: "web01"},
		Op{Op: OpUpsertEntity, Kind: KindService, ID: "service-00a1", Host: "10.0.0.7", Port: 445, Proto: "tcp", State: "open"},
		Op{Op: OpUpsertFinding, ID: "finding-00a1", Title: "SMB signing disabled", Severity: SeverityMedium, Confidence: ConfidenceHigh, Affected: []string{"10.0.0.7"}},
		Op{Op: OpAttachEvidence, Finding: "finding-00a1", EvidenceKind: EvidenceCLIOutput, Ref: "[+] SMB 10.0.0.7 445 web01 (signing:False)"},
		Op{Op: OpAddEdge, Type: string(EdgeRunsOn), From: "service-00a1", To: "10.0.0.7", Confidence: ConfidenceHigh},
		Op{Op: OpUpsertEntity, Kind: KindCredential, ID: "credential-00a1", Type: CredentialPassword, Principal: "ACME\\admin", Secret: "hunter2"},
		Op{Op: OpAddEdge, Type: string(EdgeValidFor), From: "credential-00a1", To: "service-00a1", Confidence: ConfidenceHigh},
		Op{Op: OpUpsertEntity, Kind: KindAccess, ID: "access-00a1", Principal: "credential-00a1", Target: "service-00a1", Level: LevelAdmin, Via: "finding-00a1"},
	)
	for i, want := range []string{"host-0001", "service-00a1", "finding-00a1", "finding-00a1", "", "credential-00a1", "", "access-00a1"} {
		if want == "" {
			continue
		}
		if got := receipt.Effects[i].ID; got != want {
			t.Errorf("effects[%d].id = %q, want %q", i, got, want)
		}
	}

	snap := store.Snapshot()
	service, ok := snap.Entity("service-00a1")
	if !ok {
		t.Fatalf("the batch's service is missing: %+v", snap.Entities)
	}
	if service.Kind != KindService || service.Port != 445 {
		t.Errorf("service = %+v, want the batch's 445/tcp record", service)
	}
	finding, ok := snap.Finding("finding-00a1")
	if !ok {
		t.Fatalf("the batch's finding is missing: %+v", snap.Findings)
	}
	if finding.EvidenceCount() != 1 {
		t.Errorf("evidence = %d, want the one item the batch attached", finding.EvidenceCount())
	}
	if finding.Status != StatusDetected || finding.Verification != VerificationUnverified {
		t.Errorf("status/verification = %s/%s, want detected/unverified: a parser escalates neither", finding.Status, finding.Verification)
	}
	access, ok := snap.Entity("access-00a1")
	if !ok {
		t.Fatalf("the batch's access is missing")
	}
	if access.Via != "finding-00a1" {
		t.Errorf("access.via = %q, want the batch's finding", access.Via)
	}
	wantEdges := []string{"RUNS_ON|service-00a1|host-0001", "VALID_FOR|credential-00a1|service-00a1", "EXPLOITED_VIA|finding-00a1|access-00a1"}
	for _, want := range wantEdges {
		found := false
		for _, e := range snap.Edges {
			if e.Key() == want {
				found = true
			}
		}
		if !found {
			t.Errorf("edge %s is missing: %+v", want, snap.Edges)
		}
	}
}

// TestSuppliedIDMustBeFreeAndOfTheOpsKind keeps a supplied id from rewriting a
// record the batch never meant to touch.
func TestSuppliedIDMustBeFreeAndOfTheOpsKind(t *testing.T) {
	store := openTestStore(t)
	mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})

	cases := []struct {
		name string
		op   Op
	}{
		{"another kind's prefix", Op{Op: OpUpsertEntity, Kind: KindService, ID: "host-00ff", Host: "10.0.0.7", Port: 80, Proto: "tcp"}},
		{"a taken id", Op{Op: OpUpsertEntity, Kind: KindHost, ID: "host-0001", Addresses: []string{"10.0.0.8"}}},
		{"a malformed id", Op{Op: OpUpsertEntity, Kind: KindHost, ID: "host-zzzz", Addresses: []string{"10.0.0.9"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.Update(context.Background(), Origin{Tool: "nmap_parse"}, []Op{tc.op}); !errors.Is(err, ErrOp) {
				t.Errorf("Update(%s) = %v, want a refusal", tc.name, err)
			}
		})
	}
	if got := len(store.Snapshot().Entities); got != 1 {
		t.Errorf("entities = %d, want only the host the first batch wrote", got)
	}
}

// TestNaturalKeyMatchKeepsTheRecordsID: a re-scan that matches an existing
// record must reuse it, whatever id the op asked for, so the record's edges and
// evidence stay attached to one node (§3, §8 of the parser contract).
func TestNaturalKeyMatchKeepsTheRecordsID(t *testing.T) {
	store := openTestStore(t)
	first := mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}},
		Op{Op: OpUpsertEntity, Kind: KindService, Host: "10.0.0.7", Port: 445, Proto: "tcp"},
	)
	rescan := mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}},
		Op{Op: OpUpsertEntity, Kind: KindService, ID: "service-abcdef", Host: "10.0.0.7", Port: 445, Proto: "tcp"},
	)
	if rescan.Effects[1].Created || rescan.Effects[1].ID != first.Effects[1].ID {
		t.Errorf("re-scan effect = %+v, want the existing service reused", rescan.Effects[1])
	}
	if len(store.Snapshot().Entities) != 2 {
		t.Errorf("entities = %d, want the host and its service", len(store.Snapshot().Entities))
	}
}

// TestEvidenceAttachesToAnExistingFindingByTitle covers §8: a re-detected
// finding may already be recorded under an id the parser never minted (a model
// wrote it), and its evidence must attach to that record.
func TestEvidenceAttachesToAnExistingFindingByTitle(t *testing.T) {
	store := openTestStore(t)
	mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})
	modelWritten := mustUpdate(t, store, Op{Op: OpUpsertFinding, Title: "SMB signing disabled", Severity: SeverityMedium, Affected: []string{"10.0.0.7"}})

	// The parser's batch: it mints an id for the finding, the natural key
	// matches the record the model wrote, and its evidence names the finding by
	// title — the only reference a parser can be sure of.
	attach := mustUpdate(t, store,
		Op{Op: OpUpsertFinding, ID: "finding-00a1", Title: "SMB signing disabled", Severity: SeverityMedium, Confidence: ConfidenceHigh, Affected: []string{"10.0.0.7"}},
		Op{Op: OpAttachEvidence, Finding: "SMB signing disabled", Affected: []string{"10.0.0.7"}, EvidenceKind: EvidenceArtifact, Ref: ".styx/out/cme-10.0.0.7.log"},
	)
	if attach.Effects[0].ID != modelWritten.Effects[0].ID {
		t.Errorf("re-detection wrote a second finding (%s) instead of reusing %s", attach.Effects[0].ID, modelWritten.Effects[0].ID)
	}
	finding, _ := store.Snapshot().Finding(modelWritten.Effects[0].ID)
	if finding.EvidenceCount() != 1 {
		t.Fatalf("evidence = %d, want the re-parse's item on the existing record", finding.EvidenceCount())
	}
	if finding.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %s, want the re-parse's high", finding.Confidence)
	}
	if finding.Status != StatusDetected {
		t.Errorf("status = %s, want the re-scan to leave it alone", finding.Status)
	}
}

func TestAmbiguousEvidenceTitleIsRefused(t *testing.T) {
	store := openTestStore(t)
	mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}},
		Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.8"}},
		Op{Op: OpUpsertFinding, Title: "OpenSSH 8.2 -- user enumeration", Severity: SeverityLow, Affected: []string{"10.0.0.7"}},
		Op{Op: OpUpsertFinding, Title: "OpenSSH 8.2 -- user enumeration", Severity: SeverityLow, Affected: []string{"10.0.0.8"}},
	)
	_, err := store.Update(context.Background(), Origin{Tool: "nuclei_parse"}, []Op{
		{Op: OpAttachEvidence, Finding: "OpenSSH 8.2 -- user enumeration", EvidenceKind: EvidenceArtifact, Ref: ".styx/out/nuclei.jsonl"},
	})
	if !errors.Is(err, ErrOp) || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("Update(ambiguous title) = %v, want an ambiguity refusal", err)
	}
	// Naming the affected refs separates them.
	mustUpdate(t, store, Op{Op: OpAttachEvidence, Finding: "OpenSSH 8.2 -- user enumeration", Affected: []string{"10.0.0.8"}, EvidenceKind: EvidenceArtifact, Ref: ".styx/out/nuclei.jsonl"})
	for _, f := range store.Snapshot().Findings {
		if f.Affected[0] == "host-0002" && f.EvidenceCount() != 1 {
			t.Errorf("finding %+v did not receive the evidence", f)
		}
	}
}

func TestStoreRefusesWritesAfterClose(t *testing.T) {
	store := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if _, err := store.Update(context.Background(), Origin{Tool: "state_update"},
		[]Op{{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}}}); err == nil {
		t.Errorf("Update(closed) = nil error, want a refusal")
	}
	if store.Snapshot().Revision != 0 {
		t.Errorf("a closed store should not have written anything")
	}
}
