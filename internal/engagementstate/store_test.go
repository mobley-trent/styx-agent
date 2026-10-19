package engagementstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testTime is the fixed instant every test's clock reports.
var testTime = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// openTestStore opens a store rooted in a temporary directory with a pinned
// clock and a predictable id source. The returned store is writable.
func openTestStore(t *testing.T, opts ...Option) *Store {
	t.Helper()
	base := []Option{
		WithRoot(t.TempDir()),
		WithClock(func() time.Time { return testTime }),
		WithSession("20261019T120000Z-abcd"),
		WithIDSource(sequentialIDs()),
	}
	store, err := Open("/work/acme", "acme-q4", append(base, opts...)...)
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// sequentialIDs mints deterministic ids, one counter per kind.
func sequentialIDs() func(Kind) (string, error) {
	n := 0
	return func(kind Kind) (string, error) {
		n++
		return fmt.Sprintf("%s-%04x", kind, n), nil
	}
}

// mustUpdate applies a batch and fails the test on refusal.
func mustUpdate(t *testing.T, s *Store, ops ...Op) Receipt {
	t.Helper()
	receipt, err := s.Update(context.Background(), Origin{Tool: "state_update"}, ops)
	if err != nil {
		t.Fatalf("Update(%v) = %v", ops, err)
	}
	return receipt
}

// readDocument reads the store's file as JSON.
func readDocument(t *testing.T, s *Store) map[string]any {
	t.Helper()
	//nolint:gosec // the path is the store's own document.
	data, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatalf("read %s: %v", s.Path(), err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("document is not valid JSON: %v", err)
	}
	return doc
}

func TestOpenCreatesTheEngagementLayout(t *testing.T) {
	store := openTestStore(t)

	if !strings.HasSuffix(store.Path(), filepath.Join("state.json")) {
		t.Errorf("Path() = %q, want it to end in state.json", store.Path())
	}
	if !strings.Contains(store.Path(), "acme-q4-") {
		t.Errorf("Path() = %q, want the engagement's sanitized name and a hash", store.Path())
	}
	if !store.Writable() {
		t.Errorf("a fresh store should be writable")
	}
	if snap := store.Snapshot(); snap.SchemaVersion != SchemaVersion || snap.Revision != 0 {
		t.Errorf("Snapshot() = %+v, want schema %d at revision 0", snap, SchemaVersion)
	}
	if _, err := os.Stat(store.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a store that has never been written should have no document yet: %v", err)
	}
}

func TestUpdateWritesAtomicallyAndLeavesNoTempFiles(t *testing.T) {
	store := openTestStore(t)
	mustUpdate(t, store,
		Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}},
	)

	doc := readDocument(t, store)
	if version, ok := doc["schema_version"].(float64); !ok || int(version) != SchemaVersion {
		t.Errorf("schema_version = %v, want %d", doc["schema_version"], SchemaVersion)
	}
	if revision, _ := doc["revision"].(float64); int(revision) != 1 {
		t.Errorf("revision = %v, want 1", doc["revision"])
	}

	entries, err := os.ReadDir(filepath.Dir(store.Path()))
	if err != nil {
		t.Fatalf("read store directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("temp file %s survived the atomic write", entry.Name())
		}
	}
}

func TestOpenRefusesAnIncompatibleSchemaVersion(t *testing.T) {
	root := t.TempDir()
	store, err := Open("/work/acme", "acme-q4", WithRoot(root))
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	dir := filepath.Dir(store.Path())
	if err := store.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	//nolint:gosec // the test writes its own document.
	if err := os.WriteFile(store.Path(), []byte(`{"schema_version": 7, "entities": []}`), 0o600); err != nil {
		t.Fatalf("write document: %v", err)
	}
	_, err = Open("/work/acme", "acme-q4", WithRoot(root))
	if !errors.Is(err, ErrVersion) {
		t.Fatalf("Open(incompatible version) = %v, want ErrVersion", err)
	}
	if !strings.Contains(err.Error(), store.Path()) {
		t.Errorf("refusal %q should name the file", err)
	}
	if !strings.Contains(dir, "acme-q4-") {
		t.Errorf("document directory %q should carry the engagement name", dir)
	}
}

func TestOpenToleratesAdditiveKeys(t *testing.T) {
	root := t.TempDir()
	store, err := Open("/work/acme", "acme-q4", WithRoot(root))
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	path := store.Path()
	if err := store.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	// A future minor version adds a key this build does not know: it reads.
	//nolint:gosec // the test writes its own document.
	if err := os.WriteFile(path, []byte(`{"schema_version": 1, "revision": 3, "future_key": {"nested": true}}`), 0o600); err != nil {
		t.Fatalf("write document: %v", err)
	}
	reopened, err := Open("/work/acme", "acme-q4", WithRoot(root))
	if err != nil {
		t.Fatalf("Open(additive keys) = %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if snap := reopened.Snapshot(); snap.Revision != 3 {
		t.Errorf("Snapshot().Revision = %d, want 3", snap.Revision)
	}
}

func TestSecondSessionReadsButCannotWrite(t *testing.T) {
	root := t.TempDir()
	first, err := Open("/work/acme", "acme-q4", WithRoot(root), WithSession("session-one"))
	if err != nil {
		t.Fatalf("Open(first) = %v", err)
	}
	defer func() { _ = first.Close() }()
	receipt := mustUpdate(t, first, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})
	hostID := receipt.Effects[0].ID

	second, err := Open("/work/acme", "acme-q4", WithRoot(root), WithSession("session-two"))
	if err != nil {
		t.Fatalf("Open(second) = %v", err)
	}
	defer func() { _ = second.Close() }()

	if second.Writable() {
		t.Fatalf("a second session should not hold the write lock")
	}
	if !strings.Contains(second.Holder(), "session-one") {
		t.Errorf("Holder() = %q, want it to name the holding session", second.Holder())
	}
	if _, ok := second.Snapshot().Entity(hostID); !ok {
		t.Errorf("a read-only session should read the first session's records")
	}

	// A read-only session follows the writer: a later commit is visible to it.
	mustUpdate(t, first, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.8"}})
	if got := len(second.Snapshot().Entities); got != 2 {
		t.Errorf("read-only session sees %d entities, want the writer's 2", got)
	}

	_, err = second.Update(context.Background(), Origin{Tool: "state_update"},
		[]Op{{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.8"}}})
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("Update(read-only) = %v, want ErrLocked", err)
	}
	if !strings.Contains(err.Error(), "session-one") {
		t.Errorf("locked error %q should name the holder", err)
	}
}

func TestStaleLockIsReclaimed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(projectComponent("/work/acme"), engagementComponent("acme-q4"))
	if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
		t.Fatalf("prepare store directory: %v", err)
	}
	dead := deadPID(t)
	record, err := json.Marshal(lockRecord{PID: dead, Session: "long-gone"})
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	//nolint:gosec // the test writes its own lockfile.
	if err := os.WriteFile(filepath.Join(root, dir, lockFile), record, 0o600); err != nil {
		t.Fatalf("write stale lock: %v", err)
	}

	store, err := Open("/work/acme", "acme-q4", WithRoot(root), WithSession("new-session"))
	if err != nil {
		t.Fatalf("Open(stale lock) = %v", err)
	}
	defer func() { _ = store.Close() }()
	if !store.Writable() {
		t.Fatalf("a stale lock should be reclaimed, Holder() = %q", store.Holder())
	}
	mustUpdate(t, store, Op{Op: OpUpsertEntity, Kind: KindHost, Addresses: []string{"10.0.0.7"}})
}

func TestCloseReleasesTheLock(t *testing.T) {
	root := t.TempDir()
	first, err := Open("/work/acme", "acme-q4", WithRoot(root))
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	second, err := Open("/work/acme", "acme-q4", WithRoot(root))
	if err != nil {
		t.Fatalf("Open(after close) = %v", err)
	}
	defer func() { _ = second.Close() }()
	if !second.Writable() {
		t.Fatalf("a released lock should be acquirable")
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Errorf("Close() should be idempotent: %v", err)
	}
}

// deadPID returns the pid of a process that has exited and been reaped.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a probe process: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("probe process: %v", err)
	}
	if processAlive(pid) {
		t.Skipf("pid %d is still reported alive; cannot test stale reclamation", pid)
	}
	return pid
}
