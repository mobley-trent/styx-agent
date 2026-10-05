// Package sessions implements session persistence: the append-only session
// JSONL store and resume support.
//
// Boundary rule: sessions is a durable log of what happened — it renders
// nothing and decides nothing; the TUI and agent loop are its consumers.
package sessions

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mobley-trent/styx-agent/internal/diff"
)

// Kind discriminates a session event (§4.3). The set is additive: readers
// tolerate unknown kinds and unknown keys (the same-major compatibility
// contract, §10.1).
type Kind string

const (
	// KindUser is a human turn.
	KindUser Kind = "user"
	// KindAssistant is one completed model turn: its final text, its
	// reasoning, and the tool calls it requested.
	KindAssistant Kind = "assistant"
	// KindToolCall is a tool call the loop admitted past validation and the
	// policy gate, with the verdict it ran under.
	KindToolCall Kind = "tool_call"
	// KindToolResult is a tool call's result, truncated as captured.
	KindToolResult Kind = "tool_result"
	// KindCompaction is a compaction event (§4.5).
	KindCompaction Kind = "compaction"
	// KindEngagement is an engagement gate activation (§7.2).
	KindEngagement Kind = "engagement"
	// KindError is a turn-aborting failure (§4.4).
	KindError Kind = "error"
	// KindDiff is a staged write's rendered diff (§9.2).
	KindDiff Kind = "diff"
	// KindPlan is a proposed plan block (§9.2).
	KindPlan Kind = "plan"
	// KindIsolation reports the session container's isolation level (§5.2,
	// §9.5): the one-time banner when the session starts, degraded or
	// enforced. It is never silent.
	KindIsolation Kind = "isolation"
	// KindSubagent brackets one subagent run (§4.2). The start event carries
	// the role and task; the report event carries the run's final report. The
	// subagent's own inner events carry the same Subagent role, so the TUI can
	// render one collapsible block per run and the JSONL records the whole
	// transcript.
	KindSubagent Kind = "subagent"
	// KindMCP reports one MCP server's connection lifecycle (§5.5): connecting,
	// ready with its tool count, failed with a reason, or closed. It is how a
	// server launch, a crash, or a disconnect becomes visible rather than
	// silent.
	KindMCP Kind = "mcp"
	// KindUsage reports one model turn's token accounting (§3.1, §9.1). It is
	// persisted so the session's cost is reconstructable from its own log, and
	// it is what the status bar's spend readout is folded from.
	KindUsage Kind = "usage"
	// KindUpdate reports that a newer styx release is available (§12.3). It is
	// emitted at most once per session by the opt-out notifier and carries the
	// upgrade hint in Detail.
	KindUpdate Kind = "update"

	// KindTextDelta is a live streaming fragment of final-answer text. It is
	// rendered but not persisted: the assembled KindAssistant event carries
	// the same content, and "nothing renders that isn't also persisted" holds
	// because the deltas are a transient view of a persisted message.
	KindTextDelta Kind = "text_delta"
	// KindReasoningDelta is a live streaming fragment of reasoning_content;
	// like KindTextDelta it is render-only (§3.3).
	KindReasoningDelta Kind = "reasoning_delta"
)

// Preserved reports whether an event belongs in the durable JSONL. Streaming
// deltas are the only render-only events.
func (k Kind) Preserved() bool {
	return k != KindTextDelta && k != KindReasoningDelta
}

// PlanStep is one action a plan block proposes, and a plan's pre-authorization
// matches against (§9.2).
//
// A step matches a tool call when the tool names match exactly and every
// parameter in Params equals the call's corresponding parameter (an omitted or
// empty Params matches any call to that tool). Matching never widens a hard
// deny or a scope check.
type PlanStep struct {
	// Tool is the tool the step authorizes.
	Tool string `json:"tool"`
	// Params are the parameter values the step authorizes; empty means any.
	Params map[string]any `json:"params,omitempty"`
}

// ToolCallRef is one tool call attached to an assistant event.
type ToolCallRef struct {
	// ID is the model's tool-call ID.
	ID string `json:"id,omitempty"`
	// Name is the invoked tool.
	Name string `json:"name,omitempty"`
	// Arguments is the raw arguments string exactly as the model emitted it.
	Arguments string `json:"arguments,omitempty"`
}

// Event is one entry on the session event bus (§4.3). It is both what the TUI
// renders live and what the session JSONL persists; a zero Time is stamped by
// the writer's clock.
type Event struct {
	// Time is when the event occurred.
	Time time.Time `json:"time"`
	// Kind discriminates the payload.
	Kind Kind `json:"kind"`
	// Turn is the loop turn the event belongs to (1-based; 0 when N/A).
	Turn int `json:"turn,omitempty"`

	// Text is a message's content, a delta fragment, or a compaction detail.
	Text string `json:"text,omitempty"`
	// Reasoning is an assistant turn's reasoning_content (§3.3).
	Reasoning string `json:"reasoning,omitempty"`
	// Calls are the tool calls an assistant turn requested (assistant). They
	// are kept so a resumed conversation replays the model's own calls
	// verbatim, with their results answering by ID (§10.1).
	Calls []ToolCallRef `json:"calls,omitempty"`

	// Tool is the invoked tool's name (tool_call / tool_result).
	Tool string `json:"tool,omitempty"`
	// CallID is the model's tool-call ID, pairing a result to its call.
	CallID string `json:"call_id,omitempty"`
	// Params is the call's verbatim parameter object (tool_call).
	Params map[string]any `json:"params,omitempty"`
	// Arguments is the call's raw arguments string exactly as the model
	// emitted it (tool_call). It is what a resumed conversation replays to
	// the model, so it is kept verbatim alongside the decoded Params.
	Arguments string `json:"arguments,omitempty"`
	// Verdict is the policy/audit verdict the call ran under (tool_call).
	Verdict string `json:"verdict,omitempty"`
	// Reason is why the verdict was reached (tool_call).
	Reason string `json:"reason,omitempty"`
	// Result is the tool's output as returned to the model (tool_result).
	Result string `json:"result,omitempty"`
	// Truncated reports that Result was cut at capture (§4.5).
	Truncated bool `json:"truncated,omitempty"`
	// Failure is a tool-level failure message (tool_result) or the
	// turn-aborting error (error).
	Failure string `json:"failure,omitempty"`

	// Path is the file a diff touches (diff).
	Path string `json:"path,omitempty"`
	// Diff is the structured line diff (diff).
	Diff *diff.FileDiff `json:"diff,omitempty"`
	// Steps are the actions a plan block proposes (plan).
	Steps []PlanStep `json:"steps,omitempty"`

	// Engagement is the engagement file's label (engagement activation).
	Engagement string `json:"engagement,omitempty"`
	// Detail is a free-form note (compaction).
	Detail string `json:"detail,omitempty"`
	// Subagent attributes the event to the role of the subagent run that
	// produced it, empty for the main loop (§4.2). On a KindSubagent event it
	// names the run being bracketed.
	Subagent string `json:"subagent,omitempty"`
	// RunID identifies one subagent run within its role, so two concurrent
	// runs of the same preset never fold together in the UI or the JSONL.
	// Empty for the main loop.
	RunID string `json:"run_id,omitempty"`
	// Isolation is the container enforcement level an isolation event
	// reports (isolation): "container" or "degraded-isolation".
	Isolation string `json:"isolation,omitempty"`
	// Server is the MCP server an mcp event concerns (mcp).
	Server string `json:"server,omitempty"`
	// Status is an MCP server's lifecycle state (mcp): connecting, ready,
	// failed, or closed.
	Status string `json:"status,omitempty"`

	// PromptTokens, CompletionTokens, CacheHitTokens, and CacheMissTokens are a
	// model turn's usage (usage). The cache split drives cost tracking (§3.1).
	PromptTokens     int `json:"prompt_tokens,omitempty"`
	CompletionTokens int `json:"completion_tokens,omitempty"`
	CacheHitTokens   int `json:"cache_hit_tokens,omitempty"`
	CacheMissTokens  int `json:"cache_miss_tokens,omitempty"`
	// Model is the pinned model ID that produced a usage event (usage). It is
	// stamped at request time so a mid-session /model swap never misprices an
	// in-flight turn.
	Model string `json:"model,omitempty"`
}

// DefaultRoot is the session store root (§10.1):
// $XDG_DATA_HOME/styx/sessions, else ~/.local/share/styx/sessions.
func DefaultRoot() string {
	if dir := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dir != "" {
		return filepath.Join(dir, "styx", "sessions")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "share", "styx", "sessions")
}

// Store is a session directory: one append-only JSONL file per session, under
// one subdirectory per project (§10.1).
type Store struct {
	root  string
	now   func() time.Time
	nonce func() (string, error)
}

// Option configures a Store.
type Option func(*Store)

// WithClock sets the clock sessions are named and stamped with. Tests pin it.
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// NewStore builds a store rooted at root. An empty root means DefaultRoot;
// an unresolvable default root (no home directory) is reported by Open.
func NewStore(root string, opts ...Option) *Store {
	if strings.TrimSpace(root) == "" {
		root = DefaultRoot()
	}
	s := &Store{root: root, now: time.Now, nonce: randomNonce}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Root is the store's root directory.
func (s *Store) Root() string { return s.root }

// ProjectKey is the per-project directory name for a project path (§10.1:
// sessions live under <project>). It is the directory's base name plus a short
// hash of its absolute path, so two checkouts named alike never share a log.
func ProjectKey(projectDir string) string {
	abs, err := filepath.Abs(projectDir)
	if err != nil {
		abs = projectDir
	}
	sum := sha256.Sum256([]byte(filepath.Clean(abs)))
	base := sanitizeKey(filepath.Base(filepath.Clean(abs)))
	return base + "-" + hex.EncodeToString(sum[:4])
}

// sanitizeKey reduces a path component to characters safe in a file name.
func sanitizeKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "project"
	}
	return out
}

// randomNonce returns a short random suffix, so two sessions opened in the
// same second never collide.
func randomNonce() (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// Open starts a new session for projectDir, creating its file. The file is
// created, never truncated, and mode 0600.
func (s *Store) Open(projectDir string) (*Session, error) {
	if strings.TrimSpace(s.root) == "" {
		return nil, errors.New("sessions: no session store root (no home directory)")
	}
	nonce, err := s.nonce()
	if err != nil {
		return nil, fmt.Errorf("sessions: generate session id: %w", err)
	}
	id := s.now().UTC().Format("20060102T150405Z") + "-" + nonce
	return s.open(projectDir, id)
}

// Resume re-opens an existing session for appending. It fails for an unknown
// id or a path that escapes the store.
func (s *Store) Resume(projectDir, id string) (*Session, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("sessions: session id is required")
	}
	if strings.ContainsAny(id, `/\`) || id == "." || id == ".." {
		return nil, fmt.Errorf("sessions: invalid session id %q", id)
	}
	path := s.path(projectDir, id)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("sessions: resume %s: %w", id, err)
	}
	sess := &Session{id: id, path: path, clock: s.now}
	f, err := openSessionFile(path)
	if err != nil {
		return nil, fmt.Errorf("sessions: open session %s: %w", id, err)
	}
	sess.f = f
	return sess, nil
}

// open creates a session with the given id.
func (s *Store) open(projectDir, id string) (*Session, error) {
	path := s.path(projectDir, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("sessions: create session directory: %w", err)
	}
	f, err := openSessionFile(path)
	if err != nil {
		return nil, fmt.Errorf("sessions: create session %s: %w", id, err)
	}
	return &Session{id: id, path: path, f: f, clock: s.now}, nil
}

// openSessionFile opens a session log for appending, creating it if needed.
// The path is built from the store root and a validated session id, never from
// caller-supplied path material.
//
//nolint:gosec // the path is derived, not tainted.
func openSessionFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

// path is the file path for a session id.
func (s *Store) path(projectDir, id string) string {
	return filepath.Join(s.root, ProjectKey(projectDir), id+".jsonl")
}

// Summary describes a past session for the /resume picker (§10.1).
type Summary struct {
	// ID is the session's identifier (its file name without extension).
	ID string
	// Path is the session file.
	Path string
	// Started is the first event's timestamp.
	Started time.Time
	// Updated is the last event's timestamp.
	Updated time.Time
	// Prompts is every human turn, in order — what the picker previews.
	Prompts []string
	// Turns counts persisted events.
	Turns int
}

// FirstPrompt is the session's opening human turn, for one-line previews.
func (s Summary) FirstPrompt() string {
	if len(s.Prompts) == 0 {
		return ""
	}
	return s.Prompts[0]
}

// List returns the project's past sessions, newest first. A project with no
// sessions yet is not an error.
func (s *Store) List(projectDir string) ([]Summary, error) {
	if strings.TrimSpace(s.root) == "" {
		return nil, errors.New("sessions: no session store root (no home directory)")
	}
	dir := filepath.Join(s.root, ProjectKey(projectDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("sessions: list %s: %w", dir, err)
	}

	var out []Summary
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".jsonl")
		events, err := s.Replay(projectDir, id)
		if err != nil {
			// A damaged session must not hide the rest of the picker.
			continue
		}
		if len(events) == 0 {
			// A session opened but never used (the one this process holds)
			// is not worth offering to resume.
			continue
		}
		out = append(out, summarize(id, filepath.Join(dir, entry.Name()), events))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Updated.Equal(out[j].Updated) {
			return out[i].ID > out[j].ID
		}
		return out[i].Updated.After(out[j].Updated)
	})
	return out, nil
}

// summarize folds a session's events into its picker entry.
func summarize(id, path string, events []Event) Summary {
	sum := Summary{ID: id, Path: path, Turns: len(events)}
	for i, ev := range events {
		if i == 0 {
			sum.Started = ev.Time
		}
		if ev.Time.After(sum.Updated) {
			sum.Updated = ev.Time
		}
		if ev.Kind == KindUser && strings.TrimSpace(ev.Text) != "" {
			sum.Prompts = append(sum.Prompts, ev.Text)
		}
	}
	return sum
}

// Replay reads one session's events, oldest first. Unknown keys and unknown
// event kinds are preserved as zero-valued fields, never an error (§10.1).
// A torn final line (a crash mid-append) is dropped rather than failing the
// whole session.
func (s *Store) Replay(projectDir, id string) ([]Event, error) {
	path := s.path(projectDir, id)
	//nolint:gosec // the path is derived from a validated id under the store root.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sessions: replay %s: %w", id, err)
	}

	lines := strings.Split(string(data), "\n")
	// Append-only writes end every record with a newline. A final line with
	// no newline is a torn append (a crash mid-write): drop it instead of
	// failing the whole session.
	if n := len(lines); n > 0 && lines[n-1] != "" {
		lines = lines[:n-1]
	}

	var events []Event
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return events, fmt.Errorf("sessions: corrupt event at %s:%d: %w", id, i+1, err)
		}
		events = append(events, ev)
	}
	return events, nil
}

// Session is one append-only session log. It is safe for concurrent use.
type Session struct {
	id    string
	path  string
	clock func() time.Time

	mu     sync.Mutex
	f      *os.File
	closed bool
}

// ID is the session's identifier.
func (s *Session) ID() string { return s.id }

// Path is the session's file.
func (s *Session) Path() string { return s.path }

// Append writes one event, stamping a zero timestamp from the session's clock.
// Render-only events (streaming deltas) are not written: the assembled
// message event carries their content (§10.1).
func (s *Session) Append(ev Event) error {
	if !ev.Kind.Preserved() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("sessions: session is closed")
	}
	if ev.Time.IsZero() {
		ev.Time = s.clock()
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("sessions: encode event %q: %w", ev.Kind, err)
	}
	record := append(line, '\n')
	if _, err := s.f.Write(record); err != nil {
		return fmt.Errorf("sessions: write event %q: %w", ev.Kind, err)
	}
	return nil
}

// Record is Append in bus-handler form: the shape the loop's event bus calls.
// It drops render-only events and reports a write failure.
func (s *Session) Record(ev Event) error { return s.Append(ev) }

// Close flushes and releases the session file. It is idempotent.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.f == nil {
		return nil
	}
	if err := s.f.Close(); err != nil {
		return fmt.Errorf("sessions: close %s: %w", s.path, err)
	}
	return nil
}

// ReadAll is a convenience for tests and tools: every event in a session file.
func ReadAll(r io.Reader) ([]Event, error) {
	var events []Event
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return events, err
		}
		events = append(events, ev)
	}
	return events, scanner.Err()
}
