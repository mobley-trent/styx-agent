package engagementstate

import (
	"errors"
	"strings"
	"testing"
)

// seedGraph records a small graph: one host with a service, a hostname
// resolving to it, a segment, a credential, an access, and one finding.
func seedGraph(t *testing.T, store *Store) (hostID, serviceID, findingID string) {
	t.Helper()
	host := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}, Hostname: "web01.acme.example"})
	service := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindService, Host: host.Effects[0].ID, Port: 445, Proto: "tcp", Product: "smb"})
	segment := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindSegment, Label: "dmz", CIDRs: []string{"10.0.0.0/24"}})
	cred := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindCredential, Type: "password", Principal: "ACME\\admin", Secret: "hunter2"})
	finding := mustUpdate(t, store, Op{
		Op: OpUpsertFinding, Title: "SMB signing disabled", Severity: SeverityMedium,
		Confidence: ConfidenceHigh, Affected: []string{host.Effects[0].ID},
	})
	mustUpdate(t, store,
		Op{Op: OpAddEdge, Type: string(EdgeRunsOn), From: service.Effects[0].ID, To: host.Effects[0].ID},
		Op{Op: OpAddEdge, Type: string(EdgeInSegment), From: host.Effects[0].ID, To: segment.Effects[0].ID},
		Op{Op: OpAddEdge, Type: string(EdgeValidFor), From: cred.Effects[0].ID, To: service.Effects[0].ID},
		Op{Op: OpAddEdge, Type: string(EdgeCredentialFrom), From: cred.Effects[0].ID, To: finding.Effects[0].ID},
	)
	return host.Effects[0].ID, service.Effects[0].ID, finding.Effects[0].ID
}

func TestQueryFiltersByKindAndAttribute(t *testing.T) {
	store := openTestStore(t)
	hostID, _, _ := seedGraph(t, store)

	hosts, err := store.Query(Query{Kind: KindHost})
	if err != nil {
		t.Fatalf("Query(hosts) = %v", err)
	}
	if len(hosts.Entities) != 1 || hosts.Entities[0].ID != hostID {
		t.Errorf("Query(hosts) = %+v, want the seeded host", hosts.Entities)
	}
	if len(hosts.Findings) != 0 {
		t.Errorf("a kind filter should not return findings: %+v", hosts.Findings)
	}

	findings, err := store.Query(Query{Kind: KindFinding, Where: map[string]string{"severity": "MEDIUM"}})
	if err != nil {
		t.Fatalf("Query(findings by severity) = %v", err)
	}
	if len(findings.Findings) != 1 || findings.Findings[0].Title != "SMB signing disabled" {
		t.Errorf("Query(findings by severity) = %+v", findings.Findings)
	}

	byAddr, err := store.Query(Query{Kind: KindService, Where: map[string]string{"port": "445"}})
	if err != nil {
		t.Fatalf("Query(service by port) = %v", err)
	}
	if len(byAddr.Entities) != 1 {
		t.Errorf("Query(service by port) = %+v, want one service", byAddr.Entities)
	}

	byEvidenceAffected, err := store.Query(Query{Kind: KindFinding, Where: map[string]string{"target": hostID}})
	if err != nil {
		t.Fatalf("Query(finding by affected) = %v", err)
	}
	if len(byEvidenceAffected.Findings) != 1 {
		t.Errorf("Query(finding by affected) = %+v, want one finding", byEvidenceAffected.Findings)
	}

	if _, err := store.Query(Query{Where: map[string]string{"os_family": "linux"}}); !errors.Is(err, ErrOp) {
		t.Errorf("Query(unknown filter) = %v, want a refusal naming the vocabulary", err)
	}
	if _, err := store.Query(Query{Kind: "domain"}); !errors.Is(err, ErrOp) {
		t.Errorf("Query(unknown kind) = %v, want a refusal", err)
	}
	if _, err := store.Query(Query{Hops: 3}); !errors.Is(err, ErrOp) {
		t.Errorf("Query(3 hops) = %v, want a refusal", err)
	}
	if _, err := store.Query(Query{ID: "host-ffff"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("Query(missing id) = %v, want ErrNotFound", err)
	}
}

func TestQueryReadsANeighborhood(t *testing.T) {
	store := openTestStore(t)
	hostID, _, findingID := seedGraph(t, store)

	// One hop from the host: its service, its segment, and the finding that
	// affected it, plus the edges among them.
	one, err := store.Query(Query{ID: hostID, Hops: 1})
	if err != nil {
		t.Fatalf("Query(host, 1 hop) = %v", err)
	}
	kinds := map[Kind]int{}
	for _, e := range one.Entities {
		kinds[e.Kind]++
	}
	if kinds[KindHost] != 1 || kinds[KindService] != 1 || kinds[KindSegment] != 1 {
		t.Errorf("one-hop neighborhood = %+v, want the host, its service, and its segment", kinds)
	}
	types := map[EdgeType]bool{}
	for _, edge := range one.Edges {
		types[edge.Type] = true
	}
	if len(one.Edges) != 2 || !types[EdgeRunsOn] || !types[EdgeInSegment] {
		t.Errorf("one-hop edges = %+v, want exactly RUNS_ON and IN_SEGMENT", one.Edges)
	}

	// Two hops reaches the credential (service <- VALID_FOR - credential) —
	// and follows edges in both directions.
	two, err := store.Query(Query{ID: hostID, Hops: 2})
	if err != nil {
		t.Fatalf("Query(host, 2 hops) = %v", err)
	}
	found := false
	for _, e := range two.Entities {
		if e.Kind == KindCredential {
			found = true
		}
	}
	if !found {
		t.Errorf("two-hop neighborhood = %+v, want the credential behind VALID_FOR", two.Entities)
	}

	// The finding is one hop from the credential, too: reads are undirected.
	viaCredential, err := store.Query(Query{Kind: KindCredential, Hops: 1})
	if err != nil {
		t.Fatalf("Query(credential neighborhood) = %v", err)
	}
	ids := map[string]bool{}
	for _, f := range viaCredential.Findings {
		ids[f.ID] = true
	}
	if !ids[findingID] {
		t.Errorf("credential neighborhood = %+v, want the finding its CREDENTIAL_FROM edge names", viaCredential.Findings)
	}

	// Zero hops selects without expanding.
	zero, err := store.Query(Query{ID: hostID})
	if err != nil {
		t.Fatalf("Query(host) = %v", err)
	}
	if len(zero.Entities) != 1 || len(zero.Edges) != 0 {
		t.Errorf("zero-hop read = %+v, want the host alone", zero)
	}
}

func TestQueryHidesInactiveRecordsAndCapsResults(t *testing.T) {
	store := openTestStore(t)
	inactive := false
	mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}, Active: &inactive},
		Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.8"}},
	)

	active, err := store.Query(Query{Kind: KindHost})
	if err != nil {
		t.Fatalf("Query() = %v", err)
	}
	if len(active.Entities) != 1 || active.Entities[0].Addresses[0] != "10.0.0.8" {
		t.Errorf("an ordinary listing hides deactivated records: %+v", active.Entities)
	}

	withInactive, err := store.Query(Query{Kind: KindHost, IncludeInactive: true})
	if err != nil {
		t.Fatalf("Query(include inactive) = %v", err)
	}
	if len(withInactive.Entities) != 2 {
		t.Errorf("include_inactive = %d entities, want 2", len(withInactive.Entities))
	}

	limited, err := store.Query(Query{Kind: KindHost, IncludeInactive: true, Limit: 1})
	if err != nil {
		t.Fatalf("Query(limit 1) = %v", err)
	}
	if len(limited.Entities) != 1 || !limited.Truncated {
		t.Errorf("Query(limit 1) = %+v, want one entity and a truncation marker", limited)
	}
}

func TestQueryDoesNotAliasStoreState(t *testing.T) {
	store := openTestStore(t)
	hostID, _, _ := seedGraph(t, store)

	snap, err := store.Query(Query{Kind: KindHost})
	if err != nil {
		t.Fatalf("Query() = %v", err)
	}
	snap.Entities[0].Addresses = append(snap.Entities[0].Addresses, "10.0.0.99")
	snap.Entities[0].Tags = []string{"tampered"}

	again, _ := store.Query(Query{ID: hostID})
	if len(again.Entities) != 1 || len(again.Entities[0].Addresses) != 1 || len(again.Entities[0].Tags) != 0 {
		t.Errorf("a snapshot must be a copy: %+v", again.Entities)
	}

	// The full snapshot is a copy too.
	full := store.Snapshot()
	for i := range full.Entities {
		full.Entities[i].Addresses = []string{"0.0.0.0"}
	}
	if fresh := store.Snapshot(); strings.Join(fresh.Entities[0].Addresses, ",") == "0.0.0.0" {
		t.Errorf("Snapshot() must not alias the document")
	}
}
