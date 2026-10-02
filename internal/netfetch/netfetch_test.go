package netfetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// fakeResolver maps names to addresses; anything else is NXDOMAIN.
type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]netip.Addr, error) {
	addrs, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return addrs, nil
}

// fakeScope is membership by exact address string.
type fakeScope map[string]bool

func (f fakeScope) InScope(addr string) bool { return f[addr] }

// recordingRunner captures the command it was asked to run.
type recordingRunner struct {
	name string
	args []string
	out  string
	err  error
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.name = name
	r.args = append([]string(nil), args...)
	return r.out, r.err
}

func TestFetchPinsToResolvedInScopeAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// The Host header stays the requested name even though the socket
		// dialed the pinned loopback address.
		//nolint:gosec // a test echoing the request host back to itself.
		_, _ = w.Write([]byte("host=" + req.Host))
	}))
	defer server.Close()
	port := strings.TrimPrefix(server.URL, "http://127.0.0.1:")

	f := New(Options{
		Scope:    fakeScope{"127.0.0.1": true},
		Resolver: fakeResolver{"allowed.example": {netip.MustParseAddr("127.0.0.1")}},
	})
	body, err := f.Fetch(context.Background(), "http://allowed.example:"+port+"/status")
	if err != nil {
		t.Fatalf("Fetch() = %v", err)
	}
	if !strings.Contains(body, "host=allowed.example") {
		t.Errorf("body = %q, want the request to carry the original Host", body)
	}
}

func TestFetchRefusesOutOfScopeDestination(t *testing.T) {
	f := New(Options{
		Scope:    fakeScope{"127.0.0.1": true},
		Resolver: fakeResolver{"outside.example": {netip.MustParseAddr("203.0.113.9")}},
	})
	_, err := f.Fetch(context.Background(), "http://outside.example/")
	if err == nil || !strings.Contains(err.Error(), "outside the engagement scope") {
		t.Fatalf("Fetch(out-of-scope) = %v, want a scope refusal", err)
	}
}

func TestFetchRefusesMixedResolution(t *testing.T) {
	f := New(Options{
		Scope: fakeScope{"127.0.0.1": true},
		Resolver: fakeResolver{"mixed.example": {
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("203.0.113.9"),
		}},
	})
	if _, err := f.Fetch(context.Background(), "http://mixed.example/"); err == nil {
		t.Fatal("Fetch(mixed resolution) = nil error, want a refusal (no partially trusted answers)")
	}
}

func TestFetchRefusesRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	f := New(Options{})
	if _, err := f.Fetch(context.Background(), server.URL); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("Fetch(redirect) = %v, want a redirect refusal", err)
	}
}

func TestFetchRefusesNonHTTPScheme(t *testing.T) {
	f := New(Options{})
	if _, err := f.Fetch(context.Background(), "ftp://example.com/file"); err == nil {
		t.Fatal("Fetch(ftp) = nil error, want a scheme refusal")
	}
}

func TestFetchSafeModeNeedsNoResolver(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	f := New(Options{Resolver: fakeResolver{}}) // no scope: the policy prompt is the guard
	body, err := f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Fetch() = %v", err)
	}
	if !strings.Contains(body, "ok") {
		t.Errorf("body = %q, want the server body", body)
	}
}

func TestFetchTruncatesLargeBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 500)))
	}))
	defer server.Close()

	f := New(Options{MaxBytes: 100})
	body, err := f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Fetch() = %v", err)
	}
	if !strings.Contains(body, "body truncated at 100 bytes") {
		t.Errorf("body = %q, want a truncation marker", body)
	}
}

func TestLogsScopeChecksAndRunsSSH(t *testing.T) {
	runner := &recordingRunner{out: "log output\n"}
	f := New(Options{
		Scope:    fakeScope{"192.0.2.44": true},
		Resolver: fakeResolver{"web01.acme.example": {netip.MustParseAddr("192.0.2.44")}},
		Runner:   runner,
	})

	out, err := f.Logs(context.Background(), "web01.acme.example", []string{"tail", "-n", "50", "/var/log/syslog"})
	if err != nil {
		t.Fatalf("Logs() = %v", err)
	}
	if out != "log output\n" {
		t.Errorf("Logs() = %q", out)
	}
	if runner.name != "ssh" {
		t.Errorf("runner name = %q, want ssh", runner.name)
	}
	if !contains(runner.args, "web01.acme.example") || !contains(runner.args, "/var/log/syslog") {
		t.Errorf("ssh args = %v, want the target and command", runner.args)
	}
}

func TestLogsRefusesOutOfScopeTarget(t *testing.T) {
	runner := &recordingRunner{}
	f := New(Options{
		Scope:    fakeScope{"192.0.2.44": true},
		Resolver: fakeResolver{"evil.example": {netip.MustParseAddr("203.0.113.9")}},
		Runner:   runner,
	})
	if _, err := f.Logs(context.Background(), "evil.example", []string{"cat", "/var/log/syslog"}); err == nil {
		t.Fatal("Logs(out-of-scope) = nil error, want a scope refusal")
	}
	if runner.name != "" {
		t.Errorf("the runner was invoked despite the refusal: %s %v", runner.name, runner.args)
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
