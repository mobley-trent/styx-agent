package containerlayer

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingAuditor keeps the proxy decisions a test wants to inspect.
type recordingAuditor struct {
	mu     sync.Mutex
	events []ProxyEvent
	err    error
}

func (r *recordingAuditor) RecordProxyEvent(ev ProxyEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, ev)
	return nil
}

func (r *recordingAuditor) ofKind(kind ProxyEventKind) []ProxyEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []ProxyEvent
	for _, ev := range r.events {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

// interceptFixture is a started interception proxy with a loopback TLS target.
type interceptFixture struct {
	proxy   *EgressProxy
	ca      *CA
	capture *Capture
	auditor *recordingAuditor
}

// newInterceptFixture builds and starts an interception proxy. mutate, when
// set, adjusts the capture and proxy options before they are used.
func newInterceptFixture(t *testing.T, target *httptest.Server, mutate func(*CaptureOptions, *EgressProxyOptions)) *interceptFixture {
	t.Helper()
	ca, err := OpenCA(CAOptions{Root: t.TempDir(), ProjectDir: "/work/acme", Engagement: "acme-q4"})
	if err != nil {
		t.Fatalf("OpenCA() = %v", err)
	}
	auditor := &recordingAuditor{}
	captureOpts := CaptureOptions{Dir: filepath.Join(t.TempDir(), "captures", "session-1")}
	proxyOpts := EgressProxyOptions{
		Addr:      "127.0.0.1:0",
		Check:     allowChecker("127.0.0.1"),
		Intercept: &InterceptOptions{CA: ca},
		Auditor:   auditor,
	}
	if mutate != nil {
		mutate(&captureOpts, &proxyOpts)
	}
	capture, err := OpenCapture(captureOpts)
	if err != nil {
		t.Fatalf("OpenCapture() = %v", err)
	}
	proxyOpts.Intercept.Capture = capture
	if proxyOpts.Intercept.CA == nil {
		proxyOpts.Intercept.CA = ca
	}
	if target != nil {
		pool := x509.NewCertPool()
		pool.AddCert(target.Certificate())
		proxyOpts.Intercept.UpstreamTLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	proxy, err := NewEgressProxy(proxyOpts)
	if err != nil {
		t.Fatalf("NewEgressProxy() = %v", err)
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	t.Cleanup(func() {
		_ = proxy.Close()
		_ = capture.Close()
	})
	return &interceptFixture{proxy: proxy, ca: ca, capture: capture, auditor: auditor}
}

// client builds a client that reaches the target through the proxy and trusts
// exactly the proxy's CA.
func (f *interceptFixture) client(t *testing.T) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(f.proxy.URL())
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS12},
		},
		Timeout: 10 * time.Second,
	}
}

func TestInterceptPassesInScopeAndCaptures(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "in-scope payload")
	}))
	defer target.Close()
	f := newInterceptFixture(t, target, nil)

	resp, err := f.client(t).Get(target.URL + "/hello")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "in-scope payload" {
		t.Fatalf("response = %d %q, want 200 %q", resp.StatusCode, body, "in-scope payload")
	}

	exs := f.capture.Exchanges()
	if len(exs) != 1 {
		t.Fatalf("captured exchanges = %d, want 1", len(exs))
	}
	ex := exs[0]
	if ex.Method != http.MethodGet || ex.Status != http.StatusOK || !strings.HasSuffix(ex.URL, "/hello") {
		t.Errorf("exchange = %s %s %d, want GET .../hello 200", ex.Method, ex.URL, ex.Status)
	}
	if got := decodedBody(t, ex.ResponseBody); got != "in-scope payload" {
		t.Errorf("captured response body = %q, want %q", got, "in-scope payload")
	}
	if f.proxy.CurrentSegment() != "capture-1.jsonl" {
		t.Errorf("current segment = %q, want capture-1.jsonl", f.proxy.CurrentSegment())
	}

	// Lifecycle and initial CA creation are decisions, so they are audited.
	if got := f.auditor.ofKind(EventProxyStart); len(got) != 1 {
		t.Errorf("proxy-start events = %d, want 1", len(got))
	}
	if got := f.auditor.ofKind(EventCACreated); len(got) != 1 || got[0].Detail == "" {
		t.Errorf("ca-create events = %+v, want one naming the certificate", got)
	}
}

func TestInterceptRefusesOutOfScopeAndAudits(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "never reached off scope")
	}))
	defer target.Close()
	f := newInterceptFixture(t, target, nil)
	client := f.client(t)

	// A CONNECT to an unpinned address is refused before any TLS handshake,
	// so the client sees a plaintext 403 rather than a handshake failure.
	if _, err := client.Get("https://127.0.0.2:8443/secret"); err == nil {
		t.Error("Get(out-of-scope CONNECT) = nil, want a refusal")
	}
	// An absolute-URI forward is refused with the structured body.
	resp, err := client.Get("http://127.0.0.2:8080/elsewhere")
	if err != nil {
		t.Fatalf("Get(out-of-scope forward) = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("out-of-scope response = %d, want 403", resp.StatusCode)
	}
	var denial proxyDenial
	if err := json.NewDecoder(resp.Body).Decode(&denial); err != nil {
		t.Fatalf("decode denial: %v", err)
	}
	if denial.Error != "out-of-scope" || denial.Reason != "out-of-scope" || denial.Host != "127.0.0.2" {
		t.Errorf("denial = %+v, want an out-of-scope refusal naming 127.0.0.2", denial)
	}

	denials := f.auditor.ofKind(EventScopeDenial)
	if len(denials) != 2 {
		t.Fatalf("scope-denial events = %d, want 2 (CONNECT and forward)", len(denials))
	}
	for _, ev := range denials {
		if ev.Reason != "out-of-scope" || ev.Host != "127.0.0.2" {
			t.Errorf("denial event = %+v, want out-of-scope on 127.0.0.2", ev)
		}
	}

	var capturedDenials int
	for _, ex := range f.capture.Exchanges() {
		if ex.Denied {
			capturedDenials++
			if ex.Reason != "out-of-scope" || ex.Status != http.StatusForbidden {
				t.Errorf("captured denial = %+v, want 403 out-of-scope", ex)
			}
		}
	}
	if capturedDenials != 2 {
		t.Errorf("captured denials = %d, want 2", capturedDenials)
	}
}

func TestInterceptRefusesOutOfScopeRedirectHop(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/page" {
			w.Header().Set("Location", "http://127.0.0.2:8080/secret")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "in-scope page")
	}))
	defer target.Close()
	f := newInterceptFixture(t, target, nil)
	client := f.client(t)

	// The hop is followed, and refused: the browser sees why, not a truncated
	// document.
	resp, err := client.Get(target.URL + "/page")
	if err != nil {
		t.Fatalf("Get(/page) = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("redirected hop = %d, want 403", resp.StatusCode)
	}

	// The in-scope page still loads: the denial closed only its own hop.
	ok, err := client.Get(target.URL + "/safe")
	if err != nil {
		t.Fatalf("Get(/safe) = %v", err)
	}
	defer func() { _ = ok.Body.Close() }()
	body, _ := io.ReadAll(ok.Body)
	if ok.StatusCode != http.StatusOK || string(body) != "in-scope page" {
		t.Errorf("in-scope page after a denied hop = %d %q, want 200", ok.StatusCode, body)
	}
}

func TestCaptureRedactsModelViewButKeepsDisk(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "session=set-cookie-value")
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()
	f := newInterceptFixture(t, target, nil)

	req, err := http.NewRequest(http.MethodGet, target.URL+"/login?token=abc123&page=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer s3cret")
	req.Header.Set("Cookie", "sid=cookie-value")
	resp, err := f.client(t).Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	_ = resp.Body.Close()

	exs := f.capture.Exchanges()
	if len(exs) != 1 {
		t.Fatalf("captured exchanges = %d, want 1", len(exs))
	}
	ex := exs[0]
	// The model-facing view: no credential survives.
	for _, header := range []struct {
		list []Header
		name string
	}{
		{ex.RequestHeaders, "Authorization"},
		{ex.RequestHeaders, "Cookie"},
		{ex.ResponseHeaders, "Set-Cookie"},
	} {
		value, ok := headerValue(header.list, header.name)
		if !ok || value != Redacted {
			t.Errorf("%s in model view = %q (present=%v), want %q", header.name, value, ok, Redacted)
		}
	}
	if strings.Contains(ex.URL, "abc123") || !strings.Contains(ex.URL, "page=2") {
		t.Errorf("model-facing URL = %q, want ?token redacted and ?page kept", ex.URL)
	}

	// The bytes on disk are real, which is what keeps replay authenticated.
	data, err := os.ReadFile(filepath.Join(f.capture.Dir(), "capture-1.jsonl"))
	if err != nil {
		t.Fatalf("read capture: %v", err)
	}
	for _, want := range []string{"Bearer s3cret", "sid=cookie-value", "set-cookie-value", "token=abc123"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("capture on disk does not hold %q", want)
		}
	}
}

func TestReplayAsCapturedStillAuthenticates(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "denied")
			return
		}
		_, _ = io.WriteString(w, "authed")
	}))
	defer target.Close()
	f := newInterceptFixture(t, target, nil)

	req, err := http.NewRequest(http.MethodGet, target.URL+"/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer s3cret")
	resp, err := f.client(t).Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	_ = resp.Body.Close()

	exs := f.capture.Exchanges()
	if len(exs) != 1 {
		t.Fatalf("captured exchanges = %d, want 1", len(exs))
	}
	id := exs[0].ID

	// Empty strings mean as captured: the real Authorization header is on
	// disk, so the replay still authenticates while the model never saw it.
	result, err := f.proxy.Replay(context.Background(), ReplayRequest{ID: id})
	if err != nil {
		t.Fatalf("Replay(as captured) = %v", err)
	}
	if result.Exchange.Status != http.StatusOK {
		t.Fatalf("replayed status = %d, want 200", result.Exchange.Status)
	}
	if got := decodedBody(t, result.Exchange.ResponseBody); got != "authed" {
		t.Errorf("replayed body = %q, want %q", got, "authed")
	}
	if value, _ := headerValue(result.Exchange.RequestHeaders, "Authorization"); value != Redacted {
		t.Errorf("replayed Authorization in model view = %q, want %q", value, Redacted)
	}
	if result.Receipt.String() != result.Receipt.Segment+"#"+result.Receipt.ID || result.Receipt.ID == "" {
		t.Errorf("receipt = %+v, want a citable segment#id", result.Receipt)
	}

	// Overrides: a changed destination is a fresh scope-checked request.
	overridden, err := f.proxy.Replay(context.Background(), ReplayRequest{ID: id, URL: target.URL + "/api?changed=1"})
	if err != nil {
		t.Fatalf("Replay(url override) = %v", err)
	}
	if !strings.Contains(overridden.Exchange.URL, "changed=1") || overridden.Exchange.Status != http.StatusOK {
		t.Errorf("url override = %s %d, want 200 on ?changed=1", overridden.Exchange.URL, overridden.Exchange.Status)
	}

	// A supplied header replaces the captured one and is used as given.
	wrong, err := f.proxy.Replay(context.Background(), ReplayRequest{ID: id, HeadersJSON: `{"Authorization":"Bearer wrong"}`})
	if err != nil {
		t.Fatalf("Replay(headers override) = %v", err)
	}
	if wrong.Exchange.Status != http.StatusUnauthorized {
		t.Errorf("replay with a different credential = %d, want 401", wrong.Exchange.Status)
	}
}

func TestReplayElidedBodyRefuses(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "accepted")
	}))
	defer target.Close()
	f := newInterceptFixture(t, target, func(capture *CaptureOptions, _ *EgressProxyOptions) {
		capture.BodyBytes = 1024
	})

	big := strings.Repeat("a", 4096)
	req, err := http.NewRequest(http.MethodPost, target.URL+"/upload", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.client(t).Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	_ = resp.Body.Close()

	exs := f.capture.Exchanges()
	if len(exs) != 1 {
		t.Fatalf("captured exchanges = %d, want 1", len(exs))
	}
	ex := exs[0]
	if !ex.RequestBody.Elided || ex.RequestBody.Size != int64(len(big)) || ex.RequestBody.Data != "" {
		t.Fatalf("captured request body = %+v, want an elided 4096-byte body", ex.RequestBody)
	}
	if _, err := f.proxy.Replay(context.Background(), ReplayRequest{ID: ex.ID}); !errors.Is(err, ErrBodyElided) {
		t.Errorf("Replay(elided body) = %v, want ErrBodyElided", err)
	}

	// Sending a body explicitly is allowed: it is a new request, not a
	// truncated replay.
	result, err := f.proxy.Replay(context.Background(), ReplayRequest{ID: ex.ID, Body: "small"})
	if err != nil {
		t.Fatalf("Replay(with a body) = %v", err)
	}
	if result.Exchange.Status != http.StatusOK || decodedBody(t, result.Exchange.RequestBody) != "small" {
		t.Errorf("replay = %d %q, want 200 with the sent body", result.Exchange.Status, decodedBody(t, result.Exchange.RequestBody))
	}
}

func TestReplayUnknownIDIsNamed(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()
	f := newInterceptFixture(t, target, nil)

	_, err := f.proxy.Replay(context.Background(), ReplayRequest{ID: "ex-missing"})
	if !errors.Is(err, ErrExchangeNotFound) {
		t.Fatalf("Replay(unknown id) = %v, want ErrExchangeNotFound", err)
	}
	if !strings.Contains(err.Error(), "ex-missing") {
		t.Errorf("error = %v, want it to name the id", err)
	}
}

func TestCaptureRotatesAtSegmentBound(t *testing.T) {
	capture, err := OpenCapture(CaptureOptions{
		Dir:          t.TempDir(),
		SegmentBytes: 4096,
	})
	if err != nil {
		t.Fatalf("OpenCapture() = %v", err)
	}
	defer func() { _ = capture.Close() }()

	var receipts []Receipt
	for i := 0; i < 6; i++ {
		receipt, err := capture.Write(Exchange{
			Method:      http.MethodGet,
			URL:         "https://example.test/" + strings.Repeat("p", 20),
			RequestBody: bodyOf([]byte(strings.Repeat("b", 600)), DefaultBodyBytes),
		})
		if err != nil {
			t.Fatalf("Write(%d) = %v", i, err)
		}
		receipts = append(receipts, receipt)
	}

	if receipts[0].Segment != "capture-1.jsonl" {
		t.Errorf("first receipt = %q, want capture-1.jsonl", receipts[0].Segment)
	}
	last := receipts[len(receipts)-1]
	if last.Segment != "capture-2.jsonl" {
		t.Errorf("last receipt = %q, want the rotated capture-2.jsonl", last.Segment)
	}
	if capture.Segment() != last.Segment {
		t.Errorf("current segment = %q, want the last receipt's %q", capture.Segment(), last.Segment)
	}
	for _, segment := range []string{"capture-1.jsonl", "capture-2.jsonl"} {
		if _, err := os.Stat(filepath.Join(capture.Dir(), segment)); err != nil {
			t.Errorf("segment %s missing: %v", segment, err)
		}
	}
}

func TestCaptureRestartWritesGap(t *testing.T) {
	dir := t.TempDir()
	first, err := OpenCapture(CaptureOptions{Dir: dir})
	if err != nil {
		t.Fatalf("OpenCapture() = %v", err)
	}
	receipt, err := first.Write(Exchange{Method: http.MethodGet, URL: "https://example.test/before"})
	if err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	second, err := OpenCapture(CaptureOptions{Dir: dir})
	if err != nil {
		t.Fatalf("reopen = %v", err)
	}
	defer func() { _ = second.Close() }()

	var gap *Gap
	for _, record := range readCaptureRecords(t, dir) {
		if record.Kind == kindGap {
			decoded := record.Gap
			gap = &decoded
		}
	}
	if gap == nil {
		t.Fatal("reopened capture has no gap record")
	}
	if gap.Reason != "proxy restart" || gap.Time.IsZero() {
		t.Errorf("gap = %+v, want a stamped proxy restart", gap)
	}
	// The earlier exchange is still addressable: the restart does not lose
	// the session's record.
	if _, err := second.Get(receipt.ID); err != nil {
		t.Errorf("Get(%q) after restart = %v, want the exchange", receipt.ID, err)
	}
}

func TestProxyRestartReusesListenerAndWritesGap(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "after restart")
	}))
	defer target.Close()
	f := newInterceptFixture(t, target, nil)
	before := f.proxy.URL()

	if err := f.proxy.Restart(); err != nil {
		t.Fatalf("Restart() = %v", err)
	}
	if after := f.proxy.URL(); after != before {
		t.Errorf("proxy URL after restart = %q, want the same listener %q", after, before)
	}
	if got := f.auditor.ofKind(EventProxyRestart); len(got) != 1 {
		t.Errorf("proxy-restart events = %d, want 1", len(got))
	}
	if got := f.auditor.ofKind(EventCACreated); len(got) != 1 {
		t.Errorf("ca-create events = %d, want still 1: the CA is reused", len(got))
	}
	var gaps int
	for _, record := range readCaptureRecords(t, f.capture.Dir()) {
		if record.Kind == kindGap {
			gaps++
		}
	}
	if gaps != 1 {
		t.Errorf("gap records = %d, want 1 after a restart", gaps)
	}

	// The proxy still serves through the new listener.
	client := f.client(t)
	resp, err := client.Get(target.URL + "/again")
	if err != nil {
		t.Fatalf("Get(after restart) = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "after restart" {
		t.Errorf("after restart = %d %q, want 200", resp.StatusCode, body)
	}
}

func TestLargeBodyIsElidedAndRelayed(t *testing.T) {
	payload := strings.Repeat("x", 64<<10)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer target.Close()
	f := newInterceptFixture(t, target, func(capture *CaptureOptions, _ *EgressProxyOptions) {
		capture.BodyBytes = 1024
	})

	resp, err := f.client(t).Get(target.URL + "/big")
	if err != nil {
		t.Fatalf("Get(/big) = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != payload {
		t.Fatalf("large response = %d with %d bytes, want 200 with the full %d-byte body", resp.StatusCode, len(body), len(payload))
	}

	exs := f.capture.Exchanges()
	if len(exs) != 1 {
		t.Fatalf("captured exchanges = %d, want 1", len(exs))
	}
	captured := exs[0].ResponseBody
	if !captured.Elided || captured.Data != "" {
		t.Errorf("captured body = %+v, want an elided body", captured)
	}
	if captured.Size != int64(len(payload)) {
		t.Errorf("captured size = %d, want %d", captured.Size, len(payload))
	}
	if want := fmt.Sprintf("%x", sha256.Sum256([]byte(payload))); captured.SHA256 != want {
		t.Errorf("captured digest = %q, want %q", captured.SHA256, want)
	}

	// The spill used to hold the body is gone once the exchange is relayed.
	entries, err := os.ReadDir(f.capture.Dir())
	if err != nil {
		t.Fatalf("read capture dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".body-") {
			t.Errorf("spill file %q was left behind", entry.Name())
		}
	}
}

func TestCaptureFailureRefusesExchange(t *testing.T) {
	payload := strings.Repeat("would leak uncaptured", 64)
	var hits int
	var mu sync.Mutex
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = io.WriteString(w, payload)
	}))
	defer target.Close()
	f := newInterceptFixture(t, target, func(capture *CaptureOptions, _ *EgressProxyOptions) {
		capture.BodyBytes = 16
		capture.Open = func(string) (io.WriteCloser, error) { return failingWriter{}, nil }
	})
	client := f.client(t)

	resp, err := client.Get(target.URL + "/first")
	if err != nil {
		t.Fatalf("Get(first) = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("first response = %d, want the exchange refused", resp.StatusCode)
	}
	var failure proxyDenial
	if err := json.NewDecoder(resp.Body).Decode(&failure); err != nil {
		t.Fatalf("decode capture failure: %v", err)
	}
	if failure.Error != "capture-unavailable" || !strings.Contains(failure.Detail, "no space") {
		t.Errorf("capture failure = %+v, want a named full-disk cause", failure)
	}
	if strings.Contains(failure.Detail, payload[:16]) {
		t.Error("the refusal quoted the relayed body; a large response must not reach the client first")
	}

	// The capture is poisoned: the next exchange is refused before it leaves
	// the host, so nothing passes uncaptured.
	resp2, err := client.Get(target.URL + "/second")
	if err != nil {
		t.Fatalf("Get(second) = %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusBadGateway {
		t.Errorf("second response = %d, want refused", resp2.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Errorf("target hits = %d, want 1: the poisoned capture refuses before the dial", hits)
	}
}

func TestCapturePathIsUnderTheArtifactTree(t *testing.T) {
	got := CapturePath("/work/acme", "20261114T120000Z-abcd")
	want := filepath.Join("/work/acme", ".styx", "out", "captures", "20261114T120000Z-abcd")
	if got != want {
		t.Errorf("CapturePath() = %q, want %q", got, want)
	}
	if traversal := CapturePath("/work/acme", "../../etc"); strings.Contains(traversal, "..") {
		t.Errorf("CapturePath(traversal) = %q, want a confined path", traversal)
	}
}

func TestOpenCAIsPerEngagementAndPrivate(t *testing.T) {
	root := t.TempDir()
	opts := CAOptions{Root: root, ProjectDir: "/work/acme", Engagement: "acme-q4"}
	ca, err := OpenCA(opts)
	if err != nil {
		t.Fatalf("OpenCA() = %v", err)
	}
	if !ca.Created() {
		t.Error("first OpenCA did not report creating the CA")
	}
	certPEM := ca.CertPEM()
	x509Cert, err := x509.ParseCertificate(pemBlock(t, certPEM))
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	if !x509Cert.IsCA {
		t.Error("CA certificate is not a CA")
	}
	info, err := os.Stat(ca.KeyPath())
	if err != nil {
		t.Fatalf("stat CA key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("CA key mode = %o, want 600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(ca.Dir())
	if err != nil {
		t.Fatalf("stat PKI dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("PKI dir mode = %o, want 700", dirInfo.Mode().Perm())
	}

	reused, err := OpenCA(opts)
	if err != nil {
		t.Fatalf("second OpenCA() = %v", err)
	}
	if reused.Created() {
		t.Error("second OpenCA reported creating the CA, want reuse")
	}
	if string(reused.CertPEM()) != string(certPEM) {
		t.Error("reopened CA is a different certificate")
	}

	other, err := OpenCA(CAOptions{Root: root, ProjectDir: "/work/acme", Engagement: "other-engagement"})
	if err != nil {
		t.Fatalf("OpenCA(other engagement) = %v", err)
	}
	if other.Dir() == ca.Dir() {
		t.Error("two engagements share a PKI directory")
	}

	leaf, err := ca.Leaf("127.0.0.1")
	if err != nil {
		t.Fatalf("Leaf() = %v", err)
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := leafCert.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: "127.0.0.1"}); err != nil {
		t.Errorf("leaf does not verify for 127.0.0.1: %v", err)
	}
}

// failingWriter simulates a capture segment that cannot be written: a full
// disk.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }
func (failingWriter) Close() error              { return nil }

// captureRecord is one decoded line of a capture file, for assertions that
// care about the stream's shape rather than an exchange.
type captureRecord struct {
	Kind string
	Gap  Gap
}

// readCaptureRecords decodes every record in the session's segments.
func readCaptureRecords(t *testing.T, dir string) []captureRecord {
	t.Helper()
	segments, err := captureSegments(dir)
	if err != nil {
		t.Fatalf("list segments: %v", err)
	}
	var out []captureRecord
	for _, n := range segments {
		//nolint:gosec // the path is the capture directory the test created.
		data, err := os.ReadFile(filepath.Join(dir, captureFileName(n)))
		if err != nil {
			t.Fatalf("read segment: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var kind struct {
				Kind string `json:"kind"`
			}
			if err := json.Unmarshal([]byte(line), &kind); err != nil {
				t.Fatalf("decode record: %v", err)
			}
			record := captureRecord{Kind: kind.Kind}
			if kind.Kind == kindGap {
				if err := json.Unmarshal([]byte(line), &record.Gap); err != nil {
					t.Fatalf("decode gap: %v", err)
				}
			}
			out = append(out, record)
		}
	}
	return out
}

// decodedBody decodes a captured body's payload.
func decodedBody(t *testing.T, body Body) string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil {
		t.Fatalf("decode captured body: %v", err)
	}
	return string(data)
}

// headerValue returns the first value captured for a header name.
func headerValue(headers []Header, name string) (string, bool) {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value, true
		}
	}
	return "", false
}

// pemBlock decodes the single PEM block of a payload.
func pemBlock(t *testing.T, data []byte) []byte {
	t.Helper()
	block, rest := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block")
	}
	if len(rest) != 0 {
		t.Fatal("unexpected trailing PEM data")
	}
	return block.Bytes
}

// TestTunnelModeKeepsNoCapture pins the safe-mode shape: without Intercept
// there is no capture and no MITM, so a tunnel stays plain (§4.2).
func TestTunnelModeKeepsNoCapture(t *testing.T) {
	proxy := testProxy(t, allowChecker("127.0.0.1"))
	if proxy.Capture() != nil || proxy.CurrentSegment() != "" {
		t.Error("a plain tunnel reports a capture; safe mode keeps none")
	}
}
