package browser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeBrowserProcess is one fake browser process.
type fakeBrowserProcess struct {
	done chan struct{}
	once sync.Once
	log  string
}

func (p *fakeBrowserProcess) Done() <-chan struct{} { return p.done }
func (p *fakeBrowserProcess) Err() error            { return nil }
func (p *fakeBrowserProcess) Log() string           { return p.log }

// Kill implements Process.
func (p *fakeBrowserProcess) Kill() error {
	p.once.Do(func() { close(p.done) })
	return nil
}

// crash simulates a browser death that no harness call caused.
func (p *fakeBrowserProcess) crash() { _ = p.Kill() }

// fakeStarter starts fake processes that publish a DevTools port in the
// profile they were handed.
type fakeStarter struct {
	mu    sync.Mutex
	paths []string
	args  [][]string
	procs []*fakeBrowserProcess
}

// Start implements Starter.
func (s *fakeStarter) Start(_ context.Context, path string, args []string) (Process, error) {
	dir := ""
	for _, arg := range args {
		if strings.HasPrefix(arg, "--user-data-dir=") {
			dir = strings.TrimPrefix(arg, "--user-data-dir=")
		}
	}
	if dir == "" {
		return nil, errors.New("fake starter: no profile directory in the args")
	}
	if err := os.WriteFile(filepath.Join(dir, "DevToolsActivePort"), []byte("9222\n/devtools/browser/fake\n"), 0o600); err != nil {
		return nil, err
	}
	proc := &fakeBrowserProcess{done: make(chan struct{})}
	s.mu.Lock()
	s.paths = append(s.paths, path)
	s.args = append(s.args, append([]string(nil), args...))
	s.procs = append(s.procs, proc)
	s.mu.Unlock()
	return proc, nil
}

func (s *fakeStarter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.args)
}

func (s *fakeStarter) argsAt(i int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.args[i]...)
}

func (s *fakeStarter) procAt(i int) *fakeBrowserProcess {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.procs[i]
}

// fakeDialer records CDP admissions and returns canned connections.
type fakeDialer struct {
	mu      sync.Mutex
	urls    []string
	newConn func(index int) (Conn, error)
}

// Dial implements Dialer.
func (d *fakeDialer) Dial(_ context.Context, wsURL string) (Conn, error) {
	d.mu.Lock()
	index := len(d.urls)
	d.urls = append(d.urls, wsURL)
	newConn := d.newConn
	d.mu.Unlock()
	if newConn == nil {
		return nil, errors.New("fake dialer: no connection factory")
	}
	return newConn(index)
}

func (d *fakeDialer) admission(i int) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.urls[i]
}

// newTestManager builds a manager over fakes in a temporary profile root.
func newTestManager(t *testing.T, project, session, engagement string, starter *fakeStarter, dialer *fakeDialer) *Manager {
	t.Helper()
	if dialer.newConn == nil {
		dialer.newConn = func(int) (Conn, error) {
			return pageConn(t, map[string]any{"url": "http://10.0.0.5/home", "title": "Home", "nodes": loginNodes()}), nil
		}
	}
	manager := New(Options{
		ProjectDir: project,
		Session:    session,
		Engagement: engagement,
		Root:       t.TempDir(),
		ProxyURL: func(context.Context) (string, error) {
			return "http://127.0.0.1:3128", nil
		},
		Starter: starter,
		Dialer:  dialer,
		ResolveBinary: func(context.Context) (Binary, error) {
			return Binary{Path: "/fake/chromium", Version: pinVersion}, nil
		},
	})
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

func TestManagerLaunchesThroughTheProxyAndGate(t *testing.T) {
	starter, dialer := &fakeStarter{}, &fakeDialer{}
	manager := newTestManager(t, t.TempDir(), "sess-1", "q4", starter, dialer)

	state, err := manager.Navigate(context.Background(), "http://10.0.0.5/home")
	if err != nil {
		t.Fatalf("Navigate() = %v", err)
	}
	if state.URL != "http://10.0.0.5/home" {
		t.Errorf("Navigate() = %+v", state)
	}
	if starter.count() != 1 {
		t.Fatalf("launches = %d, want one lazy launch", starter.count())
	}
	if !slices.Contains(starter.argsAt(0), "--proxy-server=http://127.0.0.1:3128") {
		t.Errorf("args = %v, want the harness proxy", starter.argsAt(0))
	}
	wsURL := dialer.admission(0)
	if !strings.Contains(wsURL, "/devtools/browser/fake") {
		t.Errorf("CDP URL = %q, want the browser's published path", wsURL)
	}
	if !strings.Contains(wsURL, "token=") {
		t.Errorf("CDP URL = %q, want the per-launch token", wsURL)
	}
	if !strings.HasPrefix(wsURL, "ws://127.0.0.1:") {
		t.Errorf("CDP URL = %q, want the loopback gate", wsURL)
	}
	if !manager.Running() {
		t.Error("Running() = false after a successful launch")
	}
}

func TestManagerRefusesASecondConcurrentSession(t *testing.T) {
	project := t.TempDir()
	root := t.TempDir()
	held, err := OpenProfile(ProfileOptions{Root: root, ProjectDir: project, Engagement: "q4", Session: "alpha"})
	if err != nil {
		t.Fatalf("OpenProfile() = %v", err)
	}
	if err := held.Lock(); err != nil {
		t.Fatalf("Lock() = %v", err)
	}
	defer func() { _ = held.Close() }()

	starter, dialer := &fakeStarter{}, &fakeDialer{}
	manager := New(Options{
		ProjectDir: project,
		Session:    "beta",
		Engagement: "q4",
		Root:       root,
		ProxyURL:   func(context.Context) (string, error) { return "http://127.0.0.1:3128", nil },
		Starter:    starter,
		Dialer:     dialer,
		ResolveBinary: func(context.Context) (Binary, error) {
			return Binary{Path: "/fake/chromium", Version: pinVersion}, nil
		},
	})
	defer func() { _ = manager.Close() }()

	_, err = manager.Navigate(context.Background(), "http://10.0.0.5/")
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("Navigate() = %v, want ErrLocked", err)
	}
	if !strings.Contains(err.Error(), "alpha") {
		t.Errorf("error = %v, want it to name the locking session", err)
	}
	if starter.count() != 0 {
		t.Errorf("launches = %d, want the refused session to launch nothing", starter.count())
	}
}

func TestManagerRelaunchesAKilledBrowserWithItsProfile(t *testing.T) {
	starter, dialer := &fakeStarter{}, &fakeDialer{}
	manager := newTestManager(t, t.TempDir(), "sess-1", "q4", starter, dialer)
	if _, err := manager.Navigate(context.Background(), "http://10.0.0.5/one"); err != nil {
		t.Fatalf("first Navigate() = %v", err)
	}

	var profileDir string
	for _, arg := range starter.argsAt(0) {
		if strings.HasPrefix(arg, "--user-data-dir=") {
			profileDir = strings.TrimPrefix(arg, "--user-data-dir=")
		}
	}
	cookies := filepath.Join(profileDir, "Cookies")
	if err := os.WriteFile(cookies, []byte("session=abc"), 0o600); err != nil {
		t.Fatalf("write cookies: %v", err)
	}

	starter.procAt(0).crash()
	if manager.Running() {
		t.Error("Running() = true after the browser died")
	}

	if _, err := manager.Navigate(context.Background(), "http://10.0.0.5/two"); err != nil {
		t.Fatalf("Navigate() after a crash = %v", err)
	}
	if starter.count() != 2 {
		t.Fatalf("launches = %d, want a relaunch on the next call", starter.count())
	}
	second := starter.argsAt(1)
	if !slices.Contains(second, "--user-data-dir="+profileDir) {
		t.Errorf("relaunch args = %v, want the same profile %q", second, profileDir)
	}
	if _, err := os.Stat(cookies); err != nil {
		t.Errorf("the engagement's cookies did not survive the relaunch: %v", err)
	}
}

func TestManagerTransportErrorReleasesTheProfileLock(t *testing.T) {
	starter := &fakeStarter{}
	dialer := &fakeDialer{}
	dialer.newConn = func(index int) (Conn, error) {
		conn := pageConn(t, map[string]any{"url": "http://10.0.0.5/", "nodes": loginNodes()})
		if index == 0 {
			conn.reply = func(method string, _ map[string]any) (any, error) {
				if method == "Runtime.evaluate" {
					return nil, fmt.Errorf("%w: the renderer went away", ErrTransport)
				}
				return nil, nil
			}
		}
		return conn, nil
	}
	manager := newTestManager(t, t.TempDir(), "sess-1", "q4", starter, dialer)

	_, err := manager.Read(context.Background(), "", 0)
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("Read() = %v, want ErrTransport", err)
	}
	manager.mu.Lock()
	profile := manager.profile
	manager.mu.Unlock()
	if profile == nil {
		t.Fatal("the manager dropped the profile it needs for a relaunch")
	}
	if _, err := os.Stat(filepath.Join(profile.Dir(), ".lock")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the profile lock survived a transport failure: %v", err)
	}
	if _, err := manager.Read(context.Background(), "", 0); err != nil {
		t.Fatalf("Read() after the transport failure = %v", err)
	}
	if starter.count() != 2 {
		t.Errorf("launches = %d, want a relaunch after the failure", starter.count())
	}
}

func TestManagerRefusesWithoutAProxy(t *testing.T) {
	starter, dialer := &fakeStarter{}, &fakeDialer{}
	manager := New(Options{
		ProjectDir: t.TempDir(),
		Session:    "sess-1",
		Engagement: "q4",
		Root:       t.TempDir(),
		ProxyURL:   func(context.Context) (string, error) { return "", nil },
		Starter:    starter,
		Dialer:     dialer,
		ResolveBinary: func(context.Context) (Binary, error) {
			return Binary{Path: "/fake/chromium", Version: pinVersion}, nil
		},
	})
	defer func() { _ = manager.Close() }()

	_, err := manager.Navigate(context.Background(), "http://10.0.0.5/")
	if !errors.Is(err, ErrNoProxy) {
		t.Fatalf("Navigate() = %v, want ErrNoProxy", err)
	}
	if starter.count() != 0 {
		t.Errorf("launches = %d, want no browser without a proxy", starter.count())
	}
}

func TestManagerSafeModeProfileIsRemovedAtClose(t *testing.T) {
	starter, dialer := &fakeStarter{}, &fakeDialer{}
	manager := newTestManager(t, t.TempDir(), "sess-1", "", starter, dialer)
	if _, err := manager.Navigate(context.Background(), "http://10.0.0.5/"); err != nil {
		t.Fatalf("Navigate() = %v", err)
	}
	var profileDir string
	for _, arg := range starter.argsAt(0) {
		if strings.HasPrefix(arg, "--user-data-dir=") {
			profileDir = strings.TrimPrefix(arg, "--user-data-dir=")
		}
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if _, err := os.Stat(profileDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the safe-mode profile survives session end: %v", err)
	}
}

func TestManagerArtifactsAreProjectRelative(t *testing.T) {
	project := t.TempDir()
	starter, dialer := &fakeStarter{}, &fakeDialer{}
	manager := newTestManager(t, project, "sess-1", "q4", starter, dialer)

	artifact, err := manager.Screenshot(context.Background(), false)
	if err != nil {
		t.Fatalf("Screenshot() = %v", err)
	}
	if artifact.Path != ".styx/out/browser/sess-1/shot-1.png" {
		t.Errorf("Screenshot path = %q, want the workspace-relative artifact path", artifact.Path)
	}
	if _, err := os.Stat(filepath.Join(project, artifact.Path)); err != nil {
		t.Errorf("the screenshot is not under the project: %v", err)
	}
}
