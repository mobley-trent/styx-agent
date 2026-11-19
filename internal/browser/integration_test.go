package browser

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestBrowserDriverAgainstChromium exercises the real launch flags, the token
// gate, CDP, the aria snapshot, a click, typing, a screenshot, and a download
// against the host's pinned Chromium. It is opt-in because it needs a browser:
//
//	STYX_BROWSER_INTEGRATION=1 go test ./internal/browser -run Integration -v
//
// Its origin and proxy are loopback stubs, so it never touches a real target.
func TestBrowserDriverAgainstChromium(t *testing.T) {
	if os.Getenv("STYX_BROWSER_INTEGRATION") == "" {
		t.Skip("set STYX_BROWSER_INTEGRATION=1 to drive the host's pinned Chromium")
	}
	ctx := context.Background()
	binary, err := Resolve(ctx, ResolveOptions{})
	if err != nil {
		t.Skipf("no pinned Chromium on this host: %v", err)
	}

	var proxyHits int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/next":
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, `<html><head><title>Second</title></head>
				<body><h1>Second page</h1><a href="/">Back</a></body></html>`)
		case "/auth-check":
			w.Header().Set("Content-Type", "text/html")
			state := "cookie missing"
			if cookie, err := r.Cookie("session"); err == nil && cookie.Value != "" {
				state = "cookie present"
			}
			_, _ = fmt.Fprintf(w, `<html><head><title>Auth</title></head><body><h1>%s</h1></body></html>`, state)
		case "/download":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Disposition", `attachment; filename="../../evil.txt"`)
			_, _ = fmt.Fprint(w, "downloaded evidence")
		default:
			//nolint:gosec // the test origin is plain HTTP, so a Secure cookie would never be sent.
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    "topsecret",
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, `<html><head><title>Integration</title></head><body>
				<h1>Integration page</h1>
				<a href="/next">Next</a>
				<form action="/next" method="get">
					<label for="email">Email</label>
					<input id="email" name="email" placeholder="you@example.test">
					<button type="submit">Send</button>
				</form>
				<a href="/download">Download</a>
			</body></html>`)
		}
	}))
	defer origin.Close()
	proxy := newForwardProxy(t, &proxyHits)
	defer proxy.Close()

	// The profile lives in a non-hidden directory under the project: a
	// sandboxed browser (snap) cannot write to a hidden path or to its own
	// private /tmp.
	project, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("project root: %v", err)
	}
	profileRoot, err := os.MkdirTemp(project, "browser-integration-")
	if err != nil {
		t.Fatalf("profile root: %v", err)
	}
	defer func() { _ = os.RemoveAll(profileRoot) }()

	manager := New(Options{
		ProjectDir: project,
		Session:    "browser-integration",
		Engagement: "browser-integration",
		Root:       profileRoot,
		ProxyURL:   func(context.Context) (string, error) { return proxy.URL, nil },
		ResolveBinary: func(context.Context) (Binary, error) {
			return binary, nil
		},
	})
	defer func() { _ = manager.Close() }()

	state, err := manager.Navigate(ctx, origin.URL)
	if err != nil {
		t.Fatalf("Navigate() = %v\nbrowser log:\n%s", err, managerLog(manager))
	}
	if state.Title != "Integration" {
		t.Errorf("Title = %q, want Integration", state.Title)
	}
	if atomic.LoadInt32(&proxyHits) == 0 {
		t.Error("the proxy saw no request; the browser did not use --proxy-server")
	}

	snapshot, err := manager.Read(ctx, "", 0)
	if err != nil {
		t.Fatalf("Read() = %v", err)
	}
	if !strings.Contains(snapshot, `heading "Integration page"`) {
		t.Fatalf("snapshot = %q, want the page's heading", snapshot)
	}
	if strings.Contains(snapshot, "topsecret") {
		t.Errorf("snapshot leaked the cookie value: %q", snapshot)
	}

	// The page's own cookie is sent while the browser is alive. The check
	// speaks only whether it is present, never its value.
	if _, err := manager.Navigate(ctx, origin.URL+"/auth-check"); err != nil {
		t.Fatalf("Navigate(auth-check) = %v", err)
	}
	if snapshot, err = manager.Read(ctx, "", 0); err != nil {
		t.Fatalf("Read(auth-check) = %v", err)
	}
	if !strings.Contains(snapshot, "cookie present") {
		t.Fatalf("live auth-check = %q, want the page's cookie to be sent", snapshot)
	}
	if _, err := manager.Navigate(ctx, origin.URL); err != nil {
		t.Fatalf("Navigate(home) = %v", err)
	}
	if snapshot, err = manager.Read(ctx, "", 0); err != nil {
		t.Fatalf("Read(home) = %v", err)
	}

	next := handleFor(t, snapshot, `link "Next"`)
	if _, err := manager.Click(ctx, next); err != nil {
		t.Fatalf("Click(Next) = %v", err)
	}
	if snapshot, err = manager.Read(ctx, "", 0); err != nil {
		t.Fatalf("Read() after click = %v", err)
	}
	if !strings.Contains(snapshot, `heading "Second page"`) {
		t.Fatalf("snapshot after click = %q, want the second page", snapshot)
	}

	if _, err := manager.Navigate(ctx, origin.URL); err != nil {
		t.Fatalf("Navigate(back) = %v", err)
	}
	if snapshot, err = manager.Read(ctx, "", 0); err != nil {
		t.Fatalf("Read() after navigate = %v", err)
	}
	email := handleFor(t, snapshot, `textbox "Email"`)
	if _, err := manager.TypeText(ctx, email, "agent@example.test", true); err != nil {
		t.Fatalf("TypeText(submit) = %v", err)
	}
	if snapshot, err = manager.Read(ctx, "", 0); err != nil {
		t.Fatalf("Read() after submit = %v", err)
	}
	if !strings.Contains(snapshot, `heading "Second page"`) {
		t.Fatalf("snapshot after submit = %q, want the form's GET target", snapshot)
	}

	shot, err := manager.Screenshot(ctx, false)
	if err != nil {
		t.Fatalf("Screenshot() = %v", err)
	}
	if shot.Path != ".styx/out/browser/browser-integration/shot-1.png" {
		t.Errorf("Screenshot path = %q", shot.Path)
	}
	png, err := os.ReadFile(filepath.Join(project, shot.Path)) //nolint:gosec // the test built the path from its own artifact result.
	if err != nil {
		t.Fatalf("read screenshot: %v", err)
	}
	if len(png) < 8 || string(png[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Errorf("screenshot is not a PNG (first bytes %q)", png[:min(len(png), 8)])
	}
	defer func() {
		_ = os.RemoveAll(filepath.Join(project, ".styx", "out", "browser", "browser-integration"))
		_ = os.RemoveAll(filepath.Join(project, ".styx", "out", "downloads", "browser-integration"))
	}()

	// A killed browser relaunches with the same profile, so the engagement's
	// login survives a crash (§8). The auth check speaks only whether the
	// cookie is present, never its value. Chromium commits its cookie store
	// asynchronously, so wait for the profile to hold the login before the
	// abrupt kill — that is the state a running browser leaves behind.
	manager.mu.Lock()
	live := manager.live
	manager.mu.Unlock()
	// Chromium commits its cookie store on a timer; give the login time to
	// reach disk, which is the state a crash can preserve.
	time.Sleep(35 * time.Second)
	if live == nil {
		t.Fatal("no browser is running to kill")
	}
	if err := live.proc.Kill(); err != nil {
		t.Fatalf("kill the browser: %v", err)
	}
	select {
	case <-live.proc.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the killed browser did not exit")
	}
	if _, err := manager.Navigate(ctx, origin.URL+"/auth-check"); err != nil {
		t.Fatalf("Navigate() after a crash = %v", err)
	}
	if snapshot, err = manager.Read(ctx, "", 0); err != nil {
		t.Fatalf("Read() after a crash = %v", err)
	}
	if !strings.Contains(snapshot, "cookie present") {
		t.Fatalf("snapshot after a crash = %q, want the persisted login", snapshot)
	}

	if _, err := manager.Navigate(ctx, origin.URL); err != nil {
		t.Fatalf("Navigate(home) = %v", err)
	}
	if snapshot, err = manager.Read(ctx, "", 0); err != nil {
		t.Fatalf("Read() = %v", err)
	}
	download := handleFor(t, snapshot, `link "Download"`)
	artifact, err := manager.Download(ctx, download)
	if err != nil {
		t.Fatalf("Download() = %v", err)
	}
	// Chromium sanitizes the server's suggestion before reporting it, and the
	// harness keeps only its basename: whichever form arrives, the artifact is
	// one contained file in the session's download directory (§3.4).
	if artifact.Filename != filepath.Base(artifact.Path) {
		t.Errorf("download path = %q, want the announced filename %q", artifact.Path, artifact.Filename)
	}
	if strings.Contains(artifact.Filename, "/") || artifact.Filename == ".." || artifact.Filename == "." {
		t.Errorf("download filename = %q, want one safe basename", artifact.Filename)
	}
	if filepath.Clean(artifact.Path) != artifact.Path || !strings.HasPrefix(artifact.Path, ".styx/out/downloads/browser-integration/") {
		t.Errorf("download path = %q, want it inside the session's download directory", artifact.Path)
	}
	body, err := os.ReadFile(filepath.Join(project, artifact.Path)) //nolint:gosec // the test built the path from its own artifact result.
	if err != nil {
		t.Fatalf("read download: %v", err)
	}
	if string(body) != "downloaded evidence" {
		t.Errorf("download body = %q", body)
	}
}

// handleFor parses a handle number out of a rendered snapshot line.
func handleFor(t *testing.T, snapshot, want string) string {
	t.Helper()
	pattern := regexp.MustCompile(`\[(\d+)\] ` + regexp.QuoteMeta(want))
	match := pattern.FindStringSubmatch(snapshot)
	if len(match) < 2 {
		t.Fatalf("snapshot has no %q handle:\n%s", want, snapshot)
	}
	if _, err := strconv.Atoi(match[1]); err != nil {
		t.Fatalf("handle %q is not a number", match[1])
	}
	return match[1]
}

// newForwardProxy is a minimal forward proxy: absolute-form requests are
// round-tripped, and CONNECT is tunnelled. It counts the requests it carries so
// a test can prove the browser's egress went through it.
func newForwardProxy(t *testing.T, hits *int32) *httptest.Server {
	t.Helper()
	transport := &http.Transport{Proxy: nil}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			upstream, err := net.DialTimeout("tcp", r.Host, 10*time.Second) //nolint:gosec // a test proxy dials the upstream it was asked for.
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer func() { _ = upstream.Close() }()
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijacker", http.StatusInternalServerError)
				return
			}
			client, _, err := hijacker.Hijack()
			if err != nil {
				return
			}
			defer func() { _ = client.Close() }()
			_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
			go func() { _, _ = io.Copy(upstream, client) }()
			_, _ = io.Copy(client, upstream)
			return
		}

		atomic.AddInt32(hits, 1)
		out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body) //nolint:gosec // a forward proxy forwards the request it was given.
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		out.Header = r.Header.Clone()
		for _, header := range []string{"Proxy-Connection", "Proxy-Authorization"} {
			out.Header.Del(header)
		}
		resp, err := transport.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
}

// managerLog returns the running browser's diagnostics, if any.
func managerLog(m *Manager) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live == nil || m.live.proc == nil {
		return "(no browser running)"
	}
	return m.live.proc.Log()
}
