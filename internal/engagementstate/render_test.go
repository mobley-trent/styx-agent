package engagementstate

import (
	"strings"
	"testing"
)

func TestSnapshotTextRedactsSecretsAndEvidence(t *testing.T) {
	store := openTestStore(t)
	host := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})
	hostID := host.Effects[0].ID
	mustUpdate(t, store, Op{
		Op: OpUpsertEntity, Kind: KindCredential, Type: "password",
		Principal: "ACME\\admin", Secret: "SuperSecret123!",
	})
	finding := mustUpdate(t, store, Op{
		Op: OpUpsertFinding, Title: "SMB signing disabled", Severity: SeverityMedium, Affected: []string{hostID},
	})
	mustUpdate(t, store, Op{
		Op: OpAttachEvidence, Finding: finding.Effects[0].ID,
		EvidenceKind: EvidenceCLIOutput, Ref: "Authorization: Bearer top-secret-token",
	})

	text := store.Snapshot().Text()
	for _, leaked := range []string{"SuperSecret123!", "top-secret-token"} {
		if strings.Contains(text, leaked) {
			t.Errorf("rendered snapshot leaks %q:\n%s", leaked, text)
		}
	}
	if !strings.Contains(text, "secret=<redacted>") {
		t.Errorf("rendered snapshot should name the redaction:\n%s", text)
	}
	if !strings.Contains(text, "evidence=1") {
		t.Errorf("rendered snapshot should summarize evidence by count:\n%s", text)
	}
	if !strings.Contains(text, "SMB signing disabled") {
		t.Errorf("rendered snapshot should still carry the finding:\n%s", text)
	}

	// The same holds for a filtered read: a query must not become a way to
	// pull a secret back into the transcript.
	credential, err := store.Query(Query{Kind: KindCredential})
	if err != nil {
		t.Fatalf("Query(credential) = %v", err)
	}
	if strings.Contains(credential.Text(), "SuperSecret123!") {
		t.Errorf("a credential query leaks its secret:\n%s", credential.Text())
	}
}

func TestSnapshotTextRendersIdsFirstAndEmptyResults(t *testing.T) {
	store := openTestStore(t)
	mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})

	text := store.Snapshot().Text()
	if !strings.HasPrefix(text, "state revision 1:") {
		t.Errorf("listing = %q, want a revision header first", text)
	}
	if !strings.Contains(text, "host host-0001 active addresses=10.0.0.7") {
		t.Errorf("listing = %q, want the kind, id, state, and attributes", text)
	}

	empty, err := store.Query(Query{Kind: KindSegment})
	if err != nil {
		t.Fatalf("Query(segment) = %v", err)
	}
	if !strings.Contains(empty.Text(), "no matching records") {
		t.Errorf("empty listing = %q, want an explicit empty result", empty.Text())
	}
}
