package containerlayer

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Capture bounds (§4.5): a segment closes at 8 MiB and the next opens; a body
// over 256 KiB is elided from the record with its size and digests kept.
const (
	// DefaultSegmentBytes is the size a capture segment rotates at.
	DefaultSegmentBytes int64 = 8 << 20
	// DefaultBodyBytes is the largest body a record keeps verbatim.
	DefaultBodyBytes int64 = 256 << 10

	captureFileMode = 0o600
	captureDirMode  = 0o700
)

// Refusal kinds. Callers branch on these, never on message text.
var (
	// ErrCaptureFailed is a capture that could not be written. It is
	// fail-closed (§8): the exchange it belongs to is refused rather than
	// passing uncaptured, and the capture stays poisoned so no later exchange
	// passes either.
	ErrCaptureFailed = errors.New("containerlayer: capture write failed, refusing the exchange")
	// ErrExchangeNotFound is a replay of an id the capture does not hold.
	ErrExchangeNotFound = errors.New("containerlayer: no captured exchange")
	// ErrBodyElided is a replay of a body the capture elided: it refuses
	// rather than sending a truncated one (§4.5).
	ErrBodyElided = errors.New("containerlayer: body was elided at capture")
	// ErrReplayHeaders is a replay whose headers_json is not a JSON object of
	// strings.
	ErrReplayHeaders = errors.New("containerlayer: replay headers must be a JSON object of strings")
)

// Header is one captured header field. A slice, not a map, because a response
// may carry the same name several times (Set-Cookie) and order is evidence.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Body is one captured message body. A body larger than the capture's bound is
// stored as size plus digest, never as a truncated payload.
type Body struct {
	Encoding string `json:"encoding,omitempty"`
	Data     string `json:"data,omitempty"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256,omitempty"`
	Elided   bool   `json:"elided,omitempty"`
}

// Exchange is one request/response pair, as it went over the wire (§4.5). The
// bytes are real: redaction happens where the capture becomes model context,
// never here, so replay-as-captured still authenticates.
type Exchange struct {
	Kind   string    `json:"kind"`
	ID     string    `json:"id"`
	Time   time.Time `json:"time"`
	Method string    `json:"method"`
	URL    string    `json:"url"`
	Host   string    `json:"host,omitempty"`
	Scheme string    `json:"scheme,omitempty"`

	Status          int      `json:"status,omitempty"`
	RequestHeaders  []Header `json:"request_headers,omitempty"`
	ResponseHeaders []Header `json:"response_headers,omitempty"`
	RequestBody     Body     `json:"request_body"`
	ResponseBody    Body     `json:"response_body"`
	DurationMS      int64    `json:"duration_ms,omitempty"`

	// Denied marks a request the proxy refused on scope (§4.3), and Reason is
	// the closed-set reason it refused with.
	Denied bool   `json:"denied,omitempty"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
	// ReplayOf names the exchange a replay re-sent, empty for captured
	// traffic that was not a replay.
	ReplayOf string `json:"replay_of,omitempty"`
}

// Exchange kinds a record can carry.
const (
	kindExchange = "exchange"
	kindGap      = "gap"
)

// Gap is an explicit discontinuity (§4.5): a proxy restart, so a reader never
// mistakes missing exchanges for exchanges that never happened.
type Gap struct {
	Kind   string    `json:"kind"`
	Time   time.Time `json:"time"`
	Reason string    `json:"reason"`
	Detail string    `json:"detail,omitempty"`
}

// Receipt names where an exchange can be cited: its segment file and id, read
// as capture-<n>.jsonl#<id> (§4.5).
type Receipt struct {
	Segment string `json:"segment"`
	ID      string `json:"id"`
}

// String renders the receipt as an evidence reference.
func (r Receipt) String() string { return r.Segment + "#" + r.ID }

// CaptureOptions configures OpenCapture.
type CaptureOptions struct {
	// Dir is the session's capture directory,
	// .styx/out/captures/<session>. Required.
	Dir string
	// SegmentBytes is the rotation bound; zero means DefaultSegmentBytes.
	SegmentBytes int64
	// BodyBytes is the largest body kept verbatim; zero means DefaultBodyBytes.
	BodyBytes int64
	// Now stamps records; nil means time.Now.
	Now func() time.Time
	// Open is the segment-file seam. Nil opens files in Dir; tests replace it
	// to simulate a full disk.
	Open func(path string) (io.WriteCloser, error)
}

// Capture is one session's recorded exchange stream. It is safe for concurrent
// use and never silently discontinuous: reopening a directory that already
// holds segments writes a gap, and a failed write poisons it so no later
// exchange passes uncaptured (§4.5, §8).
type Capture struct {
	dir      string
	segBytes int64
	bodyMax  int64
	now      func() time.Time
	open     func(path string) (io.WriteCloser, error)

	mu      sync.Mutex
	segment int
	w       io.WriteCloser
	size    int64
	index   map[string]Exchange
	ids     []string
	failed  error
	closed  bool
}

// OpenCapture opens — or continues — the capture for one session. A directory
// that already holds segments is a restart: the new segment's first record is
// a gap naming the time, so the stream is never silently discontinuous.
func OpenCapture(opts CaptureOptions) (*Capture, error) {
	dir := strings.TrimSpace(opts.Dir)
	if dir == "" {
		return nil, errors.New("containerlayer: a capture needs a directory")
	}
	c := &Capture{
		dir:      dir,
		segBytes: opts.SegmentBytes,
		bodyMax:  opts.BodyBytes,
		now:      opts.Now,
		open:     opts.Open,
		index:    map[string]Exchange{},
	}
	if c.segBytes <= 0 {
		c.segBytes = DefaultSegmentBytes
	}
	if c.bodyMax <= 0 {
		c.bodyMax = DefaultBodyBytes
	}
	if c.now == nil {
		c.now = time.Now
	}
	//nolint:gosec // the directory is the session's artifact path, not model output.
	if err := os.MkdirAll(dir, captureDirMode); err != nil {
		return nil, fmt.Errorf("containerlayer: create capture directory %s: %w", dir, err)
	}

	segments, err := captureSegments(dir)
	if err != nil {
		return nil, err
	}
	restarted := len(segments) > 0
	if restarted {
		c.segment = segments[len(segments)-1]
	} else {
		c.segment = 1
	}
	if err := c.loadIndex(segments); err != nil {
		return nil, err
	}
	if err := c.openSegment(c.segment); err != nil {
		return nil, err
	}
	if restarted {
		if err := c.writeGap("proxy restart", ""); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Dir is the capture directory.
func (c *Capture) Dir() string { return c.dir }

// Segment is the file name of the segment exchanges are being written to.
func (c *Capture) Segment() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return captureFileName(c.segment)
}

// Ready reports whether the capture can accept another exchange, rotating
// first when the open segment is full. It is the pre-flight that makes a full
// disk refuse an exchange before it is sent (§8).
func (c *Capture) Ready() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed != nil {
		return c.failed
	}
	if c.closed {
		return fmt.Errorf("%w: capture is closed", ErrCaptureFailed)
	}
	if c.size >= c.segBytes {
		if err := c.rotateLocked(); err != nil {
			return c.poison(err)
		}
	}
	return nil
}

// Write appends one exchange and returns the receipt that cites it. The
// receipt names the segment the record landed in, so a rotation is visible to
// the caller (§4.5).
func (c *Capture) Write(ex Exchange) (Receipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.failed != nil {
		return Receipt{}, c.failed
	}
	if c.closed {
		return Receipt{}, fmt.Errorf("%w: capture is closed", ErrCaptureFailed)
	}
	ex.Kind = kindExchange
	if ex.ID == "" {
		ex.ID = newExchangeID()
	}
	if ex.Time.IsZero() {
		ex.Time = c.now()
	}
	line, err := json.Marshal(ex)
	if err != nil {
		return Receipt{}, fmt.Errorf("containerlayer: encode captured exchange: %w", err)
	}
	if err := c.writeLocked(append(line, '\n')); err != nil {
		return Receipt{}, err
	}
	c.index[ex.ID] = ex
	c.ids = append(c.ids, ex.ID)
	return Receipt{Segment: captureFileName(c.segment), ID: ex.ID}, nil
}

// Gap records an explicit discontinuity in the stream (§4.5): a restart, so a
// reader knows the capture does not claim to be continuous.
func (c *Capture) Gap(reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeGap(reason, "")
}

// Get returns one exchange as the model-facing view sees it (§4.6): the
// credential-bearing headers and query values are replaced by a marker, while
// the bytes on disk keep the real values. An unknown id is a named error.
func (c *Capture) Get(id string) (Exchange, error) {
	ex, err := c.raw(id)
	if err != nil {
		return Exchange{}, err
	}
	return RedactExchange(ex), nil
}

// Exchanges returns every captured exchange, newest first, as the model-facing
// view sees them — the shape proxy_history renders (§4.6, §9).
func (c *Capture) Exchanges() []Exchange {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Exchange, 0, len(c.ids))
	for i := len(c.ids) - 1; i >= 0; i-- {
		if ex, ok := c.index[c.ids[i]]; ok {
			out = append(out, RedactExchange(ex))
		}
	}
	return out
}

// raw returns an exchange with its real bytes, for replay. It is deliberately
// unexported: only the proxy re-sends a captured credential, never a caller.
func (c *Capture) raw(id string) (Exchange, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ex, ok := c.index[id]
	if !ok {
		return Exchange{}, fmt.Errorf("%w: %q", ErrExchangeNotFound, id)
	}
	return cloneExchange(ex), nil
}

// Close releases the open segment. It is idempotent.
func (c *Capture) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.w == nil {
		return nil
	}
	w := c.w
	c.w = nil
	if err := w.Close(); err != nil {
		return fmt.Errorf("containerlayer: close capture segment: %w", err)
	}
	return nil
}

// keepLimit is the largest prefix a record keeps plus the one byte that proves
// a body passed the bound.
func (c *Capture) keepLimit() int64 { return c.bodyMax + 1 }

// writeGap writes one gap record under the capture's lock.
func (c *Capture) writeGap(reason, detail string) error {
	if c.failed != nil {
		return c.failed
	}
	line, err := json.Marshal(Gap{Kind: kindGap, Time: c.now(), Reason: reason, Detail: detail})
	if err != nil {
		return fmt.Errorf("containerlayer: encode capture gap: %w", err)
	}
	return c.writeLocked(append(line, '\n'))
}

// writeLocked appends one JSONL record, rotating first when it would cross the
// segment bound. Every failure poisons the capture: a hole is never silently
// resumed.
func (c *Capture) writeLocked(line []byte) error {
	if c.w == nil {
		return fmt.Errorf("%w: no open segment", ErrCaptureFailed)
	}
	if c.size > 0 && c.size+int64(len(line)) > c.segBytes {
		if err := c.rotateLocked(); err != nil {
			return c.poison(err)
		}
	}
	n, err := c.w.Write(line)
	if err != nil {
		return c.poison(fmt.Errorf("write %s: %w", captureFileName(c.segment), err))
	}
	if n != len(line) {
		return c.poison(fmt.Errorf("short write to %s: %d of %d bytes", captureFileName(c.segment), n, len(line)))
	}
	c.size += int64(n)
	return nil
}

// rotateLocked closes the current segment and opens the next one.
func (c *Capture) rotateLocked() error {
	if c.w != nil {
		if err := c.w.Close(); err != nil {
			return fmt.Errorf("close %s: %w", captureFileName(c.segment), err)
		}
		c.w = nil
	}
	c.segment++
	c.size = 0
	return c.openSegment(c.segment)
}

// openSegment opens — creating if needed — one segment for appending.
func (c *Capture) openSegment(n int) error {
	path := filepath.Join(c.dir, captureFileName(n))
	if c.open != nil {
		w, err := c.open(path)
		if err != nil {
			return fmt.Errorf("containerlayer: open capture segment %s: %w", path, err)
		}
		c.w = w
		c.size = 0
		return nil
	}
	//nolint:gosec // the path is derived from the session's artifact directory.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, captureFileMode)
	if err != nil {
		return fmt.Errorf("containerlayer: open capture segment %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("containerlayer: inspect capture segment %s: %w", path, err)
	}
	c.w = f
	c.size = info.Size()
	return nil
}

// loadIndex reads the exchanges already on disk, so a restart keeps replay and
// the model-facing views useful. A torn or unreadable line is skipped: the
// bytes stay on disk as evidence, it just cannot be cited by id.
func (c *Capture) loadIndex(segments []int) error {
	if c.open != nil {
		// A replaced segment-file seam means the files are the test's business.
		return nil
	}
	for _, n := range segments {
		path := filepath.Join(c.dir, captureFileName(n))
		//nolint:gosec // the path is derived from the session's artifact directory.
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("containerlayer: read capture segment %s: %w", path, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), int(c.segBytes)+64*1024)
		for scanner.Scan() {
			var ex Exchange
			if err := json.Unmarshal(scanner.Bytes(), &ex); err != nil || ex.Kind != kindExchange || ex.ID == "" {
				continue
			}
			c.index[ex.ID] = ex
			c.ids = append(c.ids, ex.ID)
		}
		err = scanner.Err()
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("containerlayer: read capture segment %s: %w", path, err)
		}
	}
	return nil
}

// poison records the first I/O failure and returns the error the caller must
// act on. Afterwards every write fails, so no exchange passes uncaptured.
func (c *Capture) poison(err error) error {
	if c.failed == nil {
		c.failed = fmt.Errorf("%w: %w", ErrCaptureFailed, err)
	}
	return c.failed
}

// captureSegments lists the segment numbers present in dir, ascending.
func captureSegments(dir string) ([]int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("containerlayer: read capture directory %s: %w", dir, err)
	}
	var segments []int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(entry.Name(), "capture-%d.jsonl", &n); err == nil && n > 0 && captureFileName(n) == entry.Name() {
			segments = append(segments, n)
		}
	}
	sort.Ints(segments)
	return segments, nil
}

// captureFileName is a segment's name: capture-<n>.jsonl (§4.5).
func captureFileName(n int) string { return fmt.Sprintf("capture-%d.jsonl", n) }

// CapturePath is the session's capture directory under the project's artifact
// tree (§4.5, §10.4): <project>/.styx/out/captures/<session>. Captures are
// evidence and are never auto-pruned; removal is the operator's act.
func CapturePath(projectDir, session string) string {
	return filepath.Join(projectDir, ".styx", "out", "captures", filepath.Base(strings.TrimSpace(session)))
}

// newExchangeID mints an unpredictable exchange id, so a capture reference is
// not guessable and does not leak ordering.
func newExchangeID() string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("x%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}

// cloneExchange deep-copies the slices a caller could otherwise mutate.
func cloneExchange(ex Exchange) Exchange {
	out := ex
	out.RequestHeaders = cloneHeaders(ex.RequestHeaders)
	out.ResponseHeaders = cloneHeaders(ex.ResponseHeaders)
	return out
}

// cloneHeaders copies a header slice.
func cloneHeaders(in []Header) []Header {
	if in == nil {
		return nil
	}
	return append([]Header(nil), in...)
}

// headersOf flattens an http.Header into the capture's ordered form.
func headersOf(h http.Header) []Header {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Header, 0, len(h))
	for _, name := range names {
		for _, value := range h[name] {
			out = append(out, Header{Name: name, Value: value})
		}
	}
	return out
}

// headerOf rebuilds an http.Header from captured fields.
func headerOf(hs []Header) http.Header {
	h := make(http.Header, len(hs))
	for _, f := range hs {
		h.Add(f.Name, f.Value)
	}
	return h
}

// bodyRecorder streams a body onward while keeping the prefix a record stores
// and the digest and size a bounded record needs (§4.5). It never truncates
// what it passes through.
type bodyRecorder struct {
	src       io.Reader
	keepLimit int64
	digest    hash.Hash
	kept      []byte
	size      int64
}

// newBodyRecorder wraps src, keeping at most keepLimit bytes.
func newBodyRecorder(src io.Reader, keepLimit int64) *bodyRecorder {
	return &bodyRecorder{src: src, keepLimit: keepLimit, digest: sha256.New()}
}

// Read records what it reads and returns it unchanged.
func (b *bodyRecorder) Read(p []byte) (int, error) {
	n, err := b.src.Read(p)
	if n > 0 {
		b.digest.Write(p[:n])
		b.size += int64(n)
		if room := b.keepLimit - int64(len(b.kept)); room > 0 {
			take := int64(n)
			if take > room {
				take = room
			}
			b.kept = append(b.kept, p[:take]...)
		}
	}
	return n, err
}

// keptBytes is the prefix read so far, at most keepLimit bytes.
func (b *bodyRecorder) keptBytes() []byte { return b.kept }

// body renders the captured body: verbatim under the bound, size and digest
// over it.
func (b *bodyRecorder) body(limit int64) Body {
	body := Body{Size: b.size, SHA256: hex.EncodeToString(b.digest.Sum(nil))}
	if b.size > limit {
		body.Elided = true
		return body
	}
	body.Encoding = "base64"
	body.Data = base64.StdEncoding.EncodeToString(b.kept)
	return body
}

// relayBody is a response body read once before it is relayed: what the
// capture keeps, what it elided, and a source the client can then be served
// from. A body over the verbatim bound spills into the capture directory, so
// the record can be written before any byte reaches the client — an exchange
// that cannot be recorded is never relayed, however large it is (§8).
type relayBody struct {
	rec   *bodyRecorder
	spill *os.File
}

// body renders the captured body.
func (b *relayBody) body(limit int64) Body { return b.rec.body(limit) }

// reader serves the body that was read, from memory or from the spill file.
func (b *relayBody) reader() (io.Reader, error) {
	if b.spill == nil {
		return bytes.NewReader(b.rec.keptBytes()), nil
	}
	if _, err := b.spill.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("containerlayer: rewind spooled response body: %w", err)
	}
	return b.spill, nil
}

// close removes the spill file, if there is one.
func (b *relayBody) close() {
	if b.spill == nil {
		return
	}
	name := b.spill.Name()
	_ = b.spill.Close()
	_ = os.Remove(name)
	b.spill = nil
}

// readRelayBody reads a whole response body, spilling it into dir when it
// passes the verbatim bound. Reading it all is what buys the fail-closed
// ordering: the digest a bounded record keeps is only known once the last byte
// has been seen, and the client must not start receiving an exchange that is
// not yet in the record.
func readRelayBody(dir string, body io.Reader, keepLimit int64) (*relayBody, error) {
	if body == nil {
		return &relayBody{rec: newBodyRecorder(bytes.NewReader(nil), keepLimit)}, nil
	}
	rec := newBodyRecorder(body, keepLimit)
	small, err := readUpTo(rec, keepLimit)
	if err != nil {
		return nil, fmt.Errorf("containerlayer: read response body: %w", err)
	}
	relay := &relayBody{rec: rec}
	if small {
		return relay, nil
	}
	//nolint:gosec // the directory is the session's capture directory.
	spill, err := os.CreateTemp(dir, ".body-*")
	if err != nil {
		return nil, fmt.Errorf("containerlayer: spool response body: %w", err)
	}
	relay.spill = spill
	if _, err := spill.Write(rec.keptBytes()); err != nil {
		relay.close()
		return nil, fmt.Errorf("containerlayer: spool response body: %w", err)
	}
	if _, err := io.Copy(spill, rec); err != nil {
		relay.close()
		return nil, fmt.Errorf("containerlayer: spool response body: %w", err)
	}
	return relay, nil
}

// recordingBody is a request body that records what the transport forwards,
// while still closing the original.
type recordingBody struct {
	*bodyRecorder
	src io.Closer
}

// Close closes the underlying request body.
func (b *recordingBody) Close() error { return b.src.Close() }

// readUpTo reads until n bytes have been seen or the source ends. It reports
// whether the source ended first, which is how the proxy knows a body stayed
// under the capture's bound.
func readUpTo(rec *bodyRecorder, n int64) (bool, error) {
	buf := make([]byte, 32*1024)
	for rec.size < n {
		chunk := n - rec.size
		if chunk > int64(len(buf)) {
			chunk = int64(len(buf))
		}
		_, err := rec.Read(buf[:chunk])
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
	}
	return false, nil
}
