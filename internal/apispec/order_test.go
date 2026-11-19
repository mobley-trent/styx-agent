package apispec_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/apispec"
	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// failingStore accepts reads and refuses every write, standing in for a store
// another session holds.
type failingStore struct{}

// Query answers an empty snapshot.
func (failingStore) Query(engagementstate.Query) (engagementstate.Snapshot, error) {
	return engagementstate.Snapshot{}, nil
}

// Update refuses.
func (failingStore) Update(context.Context, engagementstate.Origin, []engagementstate.Op) (engagementstate.Receipt, error) {
	return engagementstate.Receipt{}, errors.New("engagement state is locked by another session")
}

// recordingStore succeeds and counts the batches it received.
type recordingStore struct{ updates int }

// Query answers an empty snapshot.
func (s *recordingStore) Query(engagementstate.Query) (engagementstate.Snapshot, error) {
	return engagementstate.Snapshot{}, nil
}

// Update records the batch.
func (s *recordingStore) Update(context.Context, engagementstate.Origin, []engagementstate.Op) (engagementstate.Receipt, error) {
	s.updates++
	return engagementstate.Receipt{}, nil
}

// TestFailedStateWritePinsNothing keeps the pin ordering honest: a declared
// name is pinned only after the host batch commits, so a load whose write
// failed leaves the resolver exactly as it was.
func TestFailedStateWritePinsNothing(t *testing.T) {
	workspace := t.TempDir()
	var pinned []string
	_, err := apispec.Load(context.Background(), apispec.Request{
		Artifact:  "openapi.yaml",
		Path:      writeDoc(t, "openapi.yaml", openAPIDoc),
		Workspace: workspace,
		Store:     failingStore{},
		Scope:     cidrScope("10.1.0.0/24"),
		Resolver:  acmeResolver,
		Pool:      []string{"10.1.0.0/24"},
		Pin: func(host string, _ []netip.Addr) {
			pinned = append(pinned, host)
		},
	})
	if err == nil {
		t.Fatalf("Load() = nil error, want the store refusal")
	}
	if len(pinned) != 0 {
		t.Errorf("pinned = %v after a failed write, want nothing pinned", pinned)
	}
}

// TestAuditFailureWritesAndPinsNothing proves the target-set record is
// fail-closed: a load that cannot be audited lands no host and pins no name.
func TestAuditFailureWritesAndPinsNothing(t *testing.T) {
	workspace := t.TempDir()
	store := &recordingStore{}
	var pinned []string
	_, err := apispec.Load(context.Background(), apispec.Request{
		Artifact:  "openapi.yaml",
		Path:      writeDoc(t, "openapi.yaml", openAPIDoc),
		Workspace: workspace,
		Store:     store,
		Scope:     cidrScope("10.1.0.0/24"),
		Resolver:  acmeResolver,
		Pool:      []string{"10.1.0.0/24"},
		Pin: func(host string, _ []netip.Addr) {
			pinned = append(pinned, host)
		},
		Audit: func(apispec.Outcome) error {
			return errors.New("audit trail is incomplete")
		},
	})
	if err == nil {
		t.Fatalf("Load() = nil error, want the audit refusal")
	}
	if !strings.Contains(err.Error(), "audit trail is incomplete") {
		t.Errorf("error = %q, want the audit failure named", err)
	}
	if store.updates != 0 {
		t.Errorf("Update() ran %d times, want none before the record landed", store.updates)
	}
	if len(pinned) != 0 {
		t.Errorf("pinned = %v after an unaudited load, want nothing pinned", pinned)
	}
}

// TestSuccessfulPinHappensAfterCommit records the call order: the write lands
// first, then the declared name is pinned.
func TestSuccessfulPinHappensAfterCommit(t *testing.T) {
	workspace := t.TempDir()
	store := &recordingStore{}
	var updateCallsAtPin int
	_, err := apispec.Load(context.Background(), apispec.Request{
		Artifact:  "openapi.yaml",
		Path:      writeDoc(t, "openapi.yaml", openAPIDoc),
		Workspace: workspace,
		Store:     store,
		Scope:     cidrScope("10.1.0.0/24"),
		Resolver:  acmeResolver,
		Pool:      []string{"10.1.0.0/24"},
		Pin: func(host string, addrs []netip.Addr) {
			updateCallsAtPin = store.updates
			if host != "api.acme.example" || len(addrs) != 1 || addrs[0].String() != "10.1.0.5" {
				t.Errorf("pin = %q/%v, want the resolved declared server", host, addrs)
			}
		},
		Audit: func(apispec.Outcome) error { return nil },
	})
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if updateCallsAtPin != 1 {
		t.Errorf("pin ran with %d committed batches, want the batch already committed", updateCallsAtPin)
	}
}
