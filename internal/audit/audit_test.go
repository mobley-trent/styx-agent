package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// auditClock is the instant every test stamps with.
const auditClock = "2026-09-30T12:00:00Z"

func fixedClock(t *testing.T) func() time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, auditClock)
	if err != nil {
		t.Fatalf("bad test clock: %v", err)
	}
	return func() time.Time { return at }
}

// decision is one representative call with deeply nested parameters, the
// shape "full verbatim params" has to survive (§7.5).
func decision() Record {
	return Record{
		Mode:    ModeEngagement,
		Tool:    "bash",
		Params:  map[string]any{"command": "nmap -sV 10.0.0.5", "env": map[string]any{"LC_ALL": "C"}, "args": []any{"-sV", 1.0, nil}},
		Verdict: VerdictHardDeny,
		Reason:  "roe",
	}
}

// TestAppendEmitsOneJSONObjectPerDecision is the audit-shape acceptance: one
// JSON object per decision, with the full verbatim params, verdict, and
// reason — nothing truncated or dropped.
func TestAppendEmitsOneJSONObjectPerDecision(t *testing.T) {
	var sink bytes.Buffer
	w := NewWriter(&sink, WithClock(fixedClock(t)))

	first := decision()
	if err := w.Append(first); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	second := Record{
		Mode: ModeSafe, Tool: "read_file",
		Params:  map[string]any{"path": "main.go"},
		Verdict: VerdictAllow, Reason: "rule-match", Subagent: "coder", Isolation: IsolationContainer,
	}
	if err := w.Append(second); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(sink.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit log has %d lines, want one per decision: %q", len(lines), sink.String())
	}

	var got Record
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("line 1 is not one JSON object: %v", err)
	}
	want := decision()
	want.Timestamp = fixedClock(t)()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("record round-trip = %+v, want %+v (params must be verbatim)", got, want)
	}
	if got.Params["args"].([]any)[1] != 1.0 {
		t.Errorf("numeric param changed on the way through: %#v", got.Params["args"])
	}

	var tail map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &tail); err != nil {
		t.Fatalf("line 2 is not one JSON object: %v", err)
	}
	for key, want := range map[string]any{
		"tool": "read_file", "verdict": "allow", "reason": "rule-match",
		"mode": "safe", "subagent": "coder", "isolation": "container",
	} {
		if tail[key] != want {
			t.Errorf("line 2 %s = %v, want %v", key, tail[key], want)
		}
	}
}

// TestAppendNormalizesParamsAndStamps pins the two writer-side edits: a zero
// timestamp is stamped, and a parameterless call still carries an object.
func TestAppendNormalizesParamsAndStamps(t *testing.T) {
	var sink bytes.Buffer
	w := NewWriter(&sink, WithClock(fixedClock(t)))

	if err := w.Append(Record{Tool: "glob", Verdict: VerdictAllow}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if err := w.Append(Record{
		Timestamp: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
		Tool:      "grep", Verdict: VerdictDeny,
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(sink.String(), "\n"), "\n")
	var stamped, explicit Record
	if err := json.Unmarshal([]byte(lines[0]), &stamped); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &explicit); err != nil {
		t.Fatal(err)
	}
	if !stamped.Timestamp.Equal(fixedClock(t)()) {
		t.Errorf("stamped timestamp = %s, want the writer clock", stamped.Timestamp)
	}
	if stamped.Params == nil {
		t.Error("params = null, want an object so the line is the full call")
	}
	if !explicit.Timestamp.Equal(time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("explicit timestamp = %s, want it preserved", explicit.Timestamp)
	}
}

// failingSink fails every write after limit successes, and can be healed.
type failingSink struct {
	mu     sync.Mutex
	limit  int
	writes int
	healed bool
}

func (f *failingSink) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.healed || f.writes > f.limit {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

// TestAppendFailsClosed is the fail-closed acceptance: a write failure
// surfaces to the caller, and the writer stays poisoned afterwards — a hole
// in the trail never silently heals, so an unlogged action cannot run behind
// a recovered writer.
func TestAppendFailsClosed(t *testing.T) {
	sink := &failingSink{limit: 1}
	w := NewWriter(sink, WithClock(fixedClock(t)))

	if err := w.Append(decision()); err != nil {
		t.Fatalf("first Append() error = %v, want success", err)
	}

	err := w.Append(decision())
	if err == nil {
		t.Fatal("Append() after a failed write = nil error, want the write failure")
	}
	if !strings.Contains(err.Error(), "disk full") {
		t.Errorf("Append() error = %v, want the underlying write failure", err)
	}

	sink.mu.Lock()
	sink.healed = true
	sink.mu.Unlock()
	if err := w.Append(decision()); err == nil {
		t.Error("Append() after a healed sink = nil error, want the poisoned writer to keep refusing")
	}
}

// shortSink writes a truncated line and reports success, the way a broken
// pipe or a full page cache can.
type shortSink struct{}

func (shortSink) Write(p []byte) (int, error) { return len(p) / 2, nil }

// TestAppendRejectsShortWrites pins the last hole in the trail: a partial
// line is as damaging as a missing one.
func TestAppendRejectsShortWrites(t *testing.T) {
	w := NewWriter(shortSink{}, WithClock(fixedClock(t)))
	err := w.Append(decision())
	if err == nil {
		t.Fatal("Append() over a short write = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "short write") {
		t.Errorf("Append() error = %v, want a short-write refusal", err)
	}
	if err := w.Append(decision()); err == nil {
		t.Error("Append() after a short write = nil error, want a poisoned writer")
	}
}

// TestAppendEncodeFailureDoesNotPoison distinguishes a caller bug (params
// that cannot be JSON-encoded) from a damaged trail: the call is denied, but
// the writer keeps logging.
func TestAppendEncodeFailureDoesNotPoison(t *testing.T) {
	var sink bytes.Buffer
	w := NewWriter(&sink, WithClock(fixedClock(t)))

	err := w.Append(Record{Tool: "bash", Params: map[string]any{"fn": func() {}}, Verdict: VerdictAllow})
	if err == nil {
		t.Fatal("Append(unencodable params) = nil error, want an encode failure")
	}
	if err := w.Append(decision()); err != nil {
		t.Errorf("Append() after an encode failure = %v, want success", err)
	}
}

// TestNewWriterWithoutSinkRefuses keeps the fail-closed contract even for a
// writer built with nowhere to write: no panic, no silent success.
func TestNewWriterWithoutSinkRefuses(t *testing.T) {
	w := NewWriter(nil, WithClock(fixedClock(t)))
	if err := w.Append(decision()); err == nil {
		t.Error("Append() with no sink = nil error, want a refusal")
	}
}

// TestAppendAfterCloseRefuses pins shutdown semantics.
func TestAppendAfterCloseRefuses(t *testing.T) {
	var sink bytes.Buffer
	w := NewWriter(&sink, WithClock(fixedClock(t)))

	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close() error = %v, want idempotence", err)
	}
	if err := w.Append(decision()); err == nil {
		t.Error("Append() after Close() = nil error, want a refusal")
	}
}

// TestOpenSessionCreatesTheAuditFile covers §7.5's per-session JSONL: the
// name, the operator-only mode, and a trail that reads back line by line.
func TestOpenSessionCreatesTheAuditFile(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenSession(dir, WithClock(fixedClock(t)))
	if err != nil {
		t.Fatalf("OpenSession() error = %v", err)
	}
	want := filepath.Join(dir, "styx-audit-20260930T120000Z.jsonl")
	if w.Path() != want {
		t.Errorf("Path() = %q, want %q", w.Path(), want)
	}
	if err := w.Append(decision()); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	info, err := os.Stat(want)
	if err != nil {
		t.Fatalf("session log missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("session log mode = %o, want 600 (operator-owned, §7.5)", perm)
	}

	data, err := os.ReadFile(want) //nolint:gosec // test-controlled temp path.
	if err != nil {
		t.Fatalf("read session log: %v", err)
	}
	var rec Record
	if err := json.Unmarshal(bytes.TrimSpace(data), &rec); err != nil {
		t.Fatalf("session log is not one JSON object per line: %v", err)
	}
	if rec.Tool != "bash" || rec.Verdict != VerdictHardDeny || rec.Reason != "roe" {
		t.Errorf("round-trip record = %+v, want the decision verbatim", rec)
	}
}

// TestOpenSessionRefusesAnUnwritableDirectory pins the other half of fail
// closed: no session file means no engagement session.
func TestOpenSessionRefusesAnUnwritableDirectory(t *testing.T) {
	if _, err := OpenSession(filepath.Join(t.TempDir(), "missing", "dir"), WithClock(fixedClock(t))); err == nil {
		t.Error("OpenSession(missing dir) = nil error, want a refusal")
	}
}

// TestAppendIsConcurrencySafe exercises the session's interleaving prompts and
// subagent calls under the race detector.
func TestAppendIsConcurrencySafe(t *testing.T) {
	var sink bytes.Buffer
	w := NewWriter(&sink, WithClock(fixedClock(t)))

	const writers = 32
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Append(decision()); err != nil {
				t.Errorf("Append() error = %v", err)
			}
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSuffix(sink.String(), "\n"), "\n")
	if len(lines) != writers {
		t.Fatalf("audit log has %d lines, want %d", len(lines), writers)
	}
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("line %d is not valid JSON: %q", i, line)
		}
	}
}
