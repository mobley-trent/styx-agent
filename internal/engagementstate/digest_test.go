package engagementstate

import (
	"fmt"
	"strings"
	"testing"
)

func TestDigestIsDueAtActivationAndOnChange(t *testing.T) {
	store := openTestStore(t)

	body, due := store.Digest(false)
	if !due {
		t.Fatalf("the first digest of an engagement should be due")
	}
	if !strings.Contains(body, "no observations recorded yet") {
		t.Errorf("an empty store's digest should say so: %q", body)
	}
	if !strings.Contains(body, "first digest of this engagement") {
		t.Errorf("the first digest should be labeled as such: %q", body)
	}

	if body, due := store.Digest(false); due || body != "" {
		t.Errorf("Digest(unchanged) = (%q, %v), want nothing due", body, due)
	}

	mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})
	body, due = store.Digest(false)
	if !due {
		t.Fatalf("a write should make a digest due")
	}
	if !strings.Contains(body, "hosts 1") {
		t.Errorf("digest = %q, want the host count", body)
	}
	if !strings.Contains(body, "+1 host") {
		t.Errorf("digest = %q, want the delta since the previous digest", body)
	}
	if !strings.Contains(body, "state_query") {
		t.Errorf("digest = %q, want the state_query pointer", body)
	}
	if strings.Contains(body, "observed") {
		t.Errorf("digest = %q, should not claim an empty store", body)
	}
}

func TestDigestForceReappendsAfterCompaction(t *testing.T) {
	store := openTestStore(t)
	mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})
	if _, due := store.Digest(false); !due {
		t.Fatalf("first digest should be due")
	}

	body, due := store.Digest(true)
	if !due || body == "" {
		t.Fatalf("a forced digest should always produce a body")
	}
	if !strings.Contains(body, "no new observations since the last digest") {
		t.Errorf("forced digest = %q, want the unchanged marker", body)
	}
}

func TestDigestListsTopFindingsAndUnverifiedCount(t *testing.T) {
	store := openTestStore(t)
	host := mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})
	hostID := host.Effects[0].ID

	for i, severity := range []Severity{SeverityCritical, SeverityLow, SeverityInfo, SeverityHigh, SeverityMedium, SeverityMedium, SeverityMedium, SeverityMedium} {
		mustUpdate(t, store, Op{
			Op: OpUpsertFinding, Title: fmt.Sprintf("finding %d", i), Severity: severity, Affected: []string{hostID},
		})
	}

	body, due := store.Digest(false)
	if !due {
		t.Fatalf("digest should be due")
	}
	if !strings.Contains(body, "findings 8 (8 open, 8 unverified)") {
		t.Errorf("digest = %q, want the finding counts", body)
	}
	if !strings.Contains(body, "- critical · finding 0") {
		t.Errorf("digest = %q, want the most severe finding first", body)
	}
	if !strings.Contains(body, "… 2 more open finding(s)") {
		t.Errorf("digest = %q, want an overflow pointer past the cap", body)
	}
	if len(body) > digestMaxBytes+64 {
		t.Errorf("digest is %d bytes, want it bounded near %d", len(body), digestMaxBytes)
	}

	// A confirmed finding still counts as open; a fixed one does not.
	finding := store.Snapshot().Findings[0]
	mustUpdate(t, store, Op{Op: OpSetStatus, Finding: finding.ID, Status: StatusConfirmed})
	body, _ = store.Digest(true)
	if !strings.Contains(body, "finding(s); use state_query") && !strings.Contains(body, "8 open") {
		t.Errorf("digest = %q, want open findings still counted after confirmation", body)
	}
	mustUpdate(t, store, Op{Op: OpSetStatus, Finding: finding.ID, Status: StatusFixed})
	body, _ = store.Digest(true)
	if !strings.Contains(body, "7 open") {
		t.Errorf("digest = %q, want the fixed finding closed", body)
	}
}

func TestDigestReportsAReadOnlyStore(t *testing.T) {
	root := t.TempDir()
	writer, err := Open("/work/acme", "acme-q4", WithRoot(root), WithSession("session-one"))
	if err != nil {
		t.Fatalf("Open(writer) = %v", err)
	}
	defer func() { _ = writer.Close() }()
	mustUpdate(t, writer, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})

	reader, err := Open("/work/acme", "acme-q4", WithRoot(root), WithSession("session-two"))
	if err != nil {
		t.Fatalf("Open(reader) = %v", err)
	}
	defer func() { _ = reader.Close() }()

	body, due := reader.Digest(false)
	if !due {
		t.Fatalf("a reader's first digest should be due")
	}
	if !strings.Contains(body, "writes unavailable") || !strings.Contains(body, "session-one") {
		t.Errorf("digest = %q, want the locked-store warning naming the holder", body)
	}
}
