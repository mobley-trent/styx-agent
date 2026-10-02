package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Verdict is the audit-facing outcome of one decision (§7.5). It is broader
// than the policy engine's verdict: when the engine prompts, the trail records
// how the operator resolved the prompt.
type Verdict string

const (
	// VerdictAllow runs without asking (engagement in-scope, or a rule-table
	// allow).
	VerdictAllow Verdict = "allow"
	// VerdictPrompt was put to the operator (§6.4).
	VerdictPrompt Verdict = "prompt"
	// VerdictAllowOnce is a prompt the operator allowed once.
	VerdictAllowOnce Verdict = "allow-once"
	// VerdictAllowSession is a prompt the operator allowed for the session.
	VerdictAllowSession Verdict = "allow-session"
	// VerdictAllowPlan is a call an approved plan pre-authorized for the turn
	// (§9.2): no per-step prompt was shown.
	VerdictAllowPlan Verdict = "allow-plan"
	// VerdictDeny is a refusal, including a prompt the operator denied.
	VerdictDeny Verdict = "deny"
	// VerdictHardDeny is a refusal the operator was never asked about: an ROE
	// violation or a hard rule-table deny (§6.2, §6.3).
	VerdictHardDeny Verdict = "hard-deny"
)

// Mode is the harness operating mode recorded per decision (§7.5).
type Mode string

const (
	// ModeSafe is the default mode.
	ModeSafe Mode = "safe"
	// ModeEngagement is the explicitly authorized mode, active only after
	// passing the engagement gate.
	ModeEngagement Mode = "engagement"
)

// Isolation is the enforcement level a decision executed under (§7.5, §5.2).
// Degraded isolation is always visible in the trail — never silent.
type Isolation string

const (
	// IsolationContainer is per-session container execution with egress
	// programmed from the pinned scope.
	IsolationContainer Isolation = "container"
	// IsolationDegraded is container execution without host-edge egress
	// enforcement: no external network, harness-mediated egress only.
	IsolationDegraded Isolation = "degraded-isolation"
)

// Record is one audit line: one decision, as the forensic record of what the
// agent attempted (§7.5).
type Record struct {
	// Timestamp is when the decision was recorded. A zero value is stamped by
	// the writer's clock.
	Timestamp time.Time `json:"timestamp"`
	// Mode is the harness mode in force when the call was decided.
	Mode Mode `json:"mode"`
	// Tool is the invoked tool's name.
	Tool string `json:"tool"`
	// Params is the call's full parameter object, verbatim — never truncated
	// and never redacted.
	Params map[string]any `json:"params"`
	// Verdict is the decision, including how a prompt was resolved.
	Verdict Verdict `json:"verdict"`
	// Reason is why, in the policy engine's audit-facing vocabulary
	// (in-scope, out-of-scope, roe, rule-match, default-table).
	Reason string `json:"reason,omitempty"`
	// Subagent attributes the call to the subagent run that made it, empty
	// for the main loop (§4.2).
	Subagent string `json:"subagent,omitempty"`
	// Isolation is the enforcement level in force for the call.
	Isolation Isolation `json:"isolation,omitempty"`
}

// Writer appends one JSON object per decision to a per-session audit JSONL
// (§7.5). It is safe for concurrent use.
//
// Fail closed is the whole contract: every failure is returned to the caller —
// which must then deny the tool call — and once a record could not be written
// the writer stays poisoned. A session with a hole in its audit trail never
// silently resumes logging, so an unlogged action cannot slip through behind a
// writer that quietly recovered.
type Writer struct {
	mu     sync.Mutex
	w      io.Writer
	sync   func() error
	path   string
	clock  func() time.Time
	failed error
	closed bool
}

// Option configures a Writer.
type Option func(*Writer)

// WithClock sets the clock the writer stamps records with. Production uses
// time.Now; tests pin it.
func WithClock(now func() time.Time) Option {
	return func(w *Writer) {
		if now != nil {
			w.clock = now
		}
	}
}

// NewWriter writes records to an arbitrary sink. Callers that own the sink's
// durability (a file, a socket) keep the fail-closed contract by returning
// every write error. A nil sink becomes an always-failing sink, so the
// fail-closed contract holds instead of panicking.
func NewWriter(sink io.Writer, opts ...Option) *Writer {
	if sink == nil {
		sink = errSink{}
	}
	w := &Writer{w: sink, clock: time.Now}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// errSink is the sink of a writer constructed without one.
type errSink struct{}

// Write always fails: an audit writer with nowhere to write denies every
// call.
func (errSink) Write([]byte) (int, error) { return 0, errors.New("audit: no sink") }

// OpenSession creates this session's audit file in dir —
// `styx-audit-<timestamp>.jsonl`, operator-owned and mode 0600 (§7.5) — and
// returns a writer appending to it. The file is created, never truncated: an
// existing trail is never destroyed.
func OpenSession(dir string, opts ...Option) (*Writer, error) {
	w := NewWriter(nil, opts...)
	path := filepath.Join(dir, SessionFileName(w.clock()))

	//nolint:gosec // the session directory is operator-supplied; the name is derived, not tainted.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open session log: %w", err)
	}
	w.w = f
	w.sync = f.Sync
	w.path = path
	return w, nil
}

// Path is the session file this writer appends to, empty for writers built on
// an injected sink.
func (w *Writer) Path() string { return w.path }

// Append writes one record and returns only once the decision is persisted. A
// non-nil error means the caller must deny the tool call: the decision is not
// in the forensic record (§7.5).
//
// The record is stamped from the writer's clock when its timestamp is zero,
// and its Params are normalized to a JSON object so every line carries the
// full call, even for a parameterless tool.
func (w *Writer) Append(rec Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("audit: writer is closed")
	}
	if w.failed != nil {
		return fmt.Errorf("audit: audit trail is incomplete, refusing to log: %w", w.failed)
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = w.clock()
	}
	if rec.Params == nil {
		rec.Params = map[string]any{}
	}

	line, err := json.Marshal(rec)
	if err != nil {
		// A record that cannot be encoded is a caller bug, not a damaged
		// trail: report it without poisoning the writer.
		return fmt.Errorf("audit: encode record for tool %q: %w", rec.Tool, err)
	}
	record := append(line, '\n')
	n, err := w.w.Write(record)
	if err != nil {
		return w.poison(fmt.Errorf("audit: write record for tool %q: %w", rec.Tool, err))
	}
	if n != len(record) {
		// A short write leaves a torn line in the forensic record: deny and
		// stay poisoned, exactly like an outright failure.
		return w.poison(fmt.Errorf("audit: short write for tool %q: %d of %d bytes", rec.Tool, n, len(record)))
	}
	if w.sync != nil {
		if err := w.sync(); err != nil {
			return w.poison(fmt.Errorf("audit: persist record for tool %q: %w", rec.Tool, err))
		}
	}
	return nil
}

// Close releases the session file, if the writer owns one. It is idempotent.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if c, ok := w.w.(io.Closer); ok {
		if err := c.Close(); err != nil {
			return fmt.Errorf("audit: close session log: %w", err)
		}
	}
	return nil
}

// poison records the first I/O failure and returns the wrapped error the
// caller must act on. Afterwards every Append fails — see the fail-closed
// contract on Writer.
func (w *Writer) poison(err error) error {
	if w.failed == nil {
		w.failed = err
	}
	return err
}

// SessionFileName is the audit file name for a session start timestamp
// (`styx-audit-<timestamp>.jsonl`, §7.5). OpenSession builds the session path
// from it, and it is exported so discovery tools recognize a trail without
// duplicating the format.
func SessionFileName(t time.Time) string {
	return "styx-audit-" + t.UTC().Format("20060102T150405Z") + ".jsonl"
}
