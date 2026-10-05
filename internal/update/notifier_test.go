package update

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// countingFetcher records how many times it was called and replays a fixed
// body or error.
type countingFetcher struct {
	calls int32
	body  string
	err   error
}

func (f *countingFetcher) Fetch(context.Context, string) ([]byte, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.body), nil
}

func TestNotifierSingleFetch(t *testing.T) {
	fetcher := &countingFetcher{body: `{"tag_name":"v0.2.0","html_url":"https://example/release"}`}
	n := NewNotifier("v0.1.0", fetcher)

	rel, newer, err := n.Check(context.Background())
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if rel.Version != "v0.2.0" || rel.URL != "https://example/release" {
		t.Fatalf("Check() release = %+v", rel)
	}
	if !newer {
		t.Fatal("Check() newer = false, want true")
	}

	// A second check must not hit the network again: the notifier makes at
	// most one fetch per process (§12.3).
	if _, newer, err := n.Check(context.Background()); err != nil || !newer {
		t.Fatalf("second Check() = newer %v, err %v", newer, err)
	}
	if got := atomic.LoadInt32(&fetcher.calls); got != 1 {
		t.Fatalf("fetcher called %d times, want 1", got)
	}
}

func TestNotifierNotNewer(t *testing.T) {
	fetcher := &countingFetcher{body: `{"tag_name":"v0.1.0"}`}
	n := NewNotifier("v0.1.0", fetcher)
	_, newer, err := n.Check(context.Background())
	if err != nil || newer {
		t.Fatalf("Check() = newer %v, err %v; want false, nil", newer, err)
	}
}

func TestNotifierFetchErrorCached(t *testing.T) {
	fetcher := &countingFetcher{err: errors.New("boom")}
	n := NewNotifier("v0.1.0", fetcher)
	if _, _, err := n.Check(context.Background()); err == nil {
		t.Fatal("Check() error = nil, want error")
	}
	if _, _, err := n.Check(context.Background()); err == nil {
		t.Fatal("second Check() error = nil, want cached error")
	}
	if got := atomic.LoadInt32(&fetcher.calls); got != 1 {
		t.Fatalf("fetcher called %d times, want 1", got)
	}
}

func TestNotifierBadJSON(t *testing.T) {
	fetcher := &countingFetcher{body: `not json`}
	n := NewNotifier("v0.1.0", fetcher)
	if _, _, err := n.Check(context.Background()); err == nil {
		t.Fatal("Check() error = nil, want decode error")
	}
}

func TestHTTPFetcher(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(`{"tag_name":"v0.2.0"}`))
	}))
	defer srv.Close()

	body, err := HTTPFetcher{}.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if strings.TrimSpace(string(body)) != `{"tag_name":"v0.2.0"}` {
		t.Fatalf("Fetch() body = %q", body)
	}
	if gotUA != userAgent {
		t.Fatalf("User-Agent = %q, want %q", gotUA, userAgent)
	}
}

func TestHTTPFetcherErrorsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := (HTTPFetcher{}).Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("Fetch() error = nil, want non-200 error")
	}
}

func TestHTTPFetcherLimitsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 1000)))
	}))
	defer srv.Close()

	body, err := (HTTPFetcher{MaxBytes: 100}).Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if len(body) > 100 {
		t.Fatalf("Fetch() returned %d bytes, want <= 100", len(body))
	}
}
