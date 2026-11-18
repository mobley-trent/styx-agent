package browser

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// devToolsReadyTimeout bounds the wait for Chromium to publish its CDP port.
const devToolsReadyTimeout = 20 * time.Second

// maxProcessLog bounds the browser's captured stderr. It is diagnostic only and
// is never returned as tool content beyond a failed launch's cause.
const maxProcessLog = 8 << 10

// Starter launches the browser process. It is the process seam: production runs
// a subprocess, and tests substitute a fake that publishes a DevTools port.
type Starter interface {
	Start(ctx context.Context, path string, args []string) (Process, error)
}

// Process is one launched browser.
type Process interface {
	// Done is closed when the process exits.
	Done() <-chan struct{}
	// Err reports the exit error after Done closes.
	Err() error
	// Kill terminates the process. It is safe to call after exit.
	Kill() error
	// Log returns the process's captured diagnostics.
	Log() string
}

// Options configures a Manager.
type Options struct {
	// ProjectDir is the project root; artifacts live under its `.styx/out/`.
	ProjectDir string
	// Session is the session id that names the artifact directories.
	Session string
	// Engagement scopes the profile. Empty means safe mode, which uses an
	// ephemeral profile (§5).
	Engagement string
	// Root overrides the profile root (tests).
	Root string
	// ProxyURL resolves the harness proxy. The browser dials nothing else, so
	// an empty URL is a refusal (§3.1). It is called on every launch, so the
	// harness can bring its egress path up lazily.
	ProxyURL func(ctx context.Context) (string, error)
	// CASPKI resolves the engagement CA's SPKI pin for the browser's command
	// line (§4.4). Nil means no CA is in play (safe mode).
	CASPKI func(ctx context.Context) (string, error)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Starter is the process seam; nil runs a real subprocess.
	Starter Starter
	// Dialer is the CDP seam; nil speaks WebSocket through the gate.
	Dialer Dialer
	// ResolveBinary is the prerequisite seam; nil runs Resolve.
	ResolveBinary func(ctx context.Context) (Binary, error)
}

// Manager is one session's browser (§7): lazy start, one page, and relaunch
// with the same profile after a crash. It is safe for concurrent use; calls are
// serialized because there is one active page.
type Manager struct {
	opts Options

	mu      sync.Mutex
	closed  bool
	binary  Binary
	profile *Profile
	live    *liveSession
}

// liveSession is a running browser and its CDP connection.
type liveSession struct {
	proc Process
	gate *gate
	conn Conn
	page *Page
}

// New builds a manager. It touches no browser until the first call.
func New(opts Options) *Manager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Starter == nil {
		opts.Starter = execStarter{}
	}
	if opts.Dialer == nil {
		opts.Dialer = wsDialer{}
	}
	if opts.ResolveBinary == nil {
		opts.ResolveBinary = func(ctx context.Context) (Binary, error) {
			return Resolve(ctx, ResolveOptions{})
		}
	}
	return &Manager{opts: opts}
}

// Running reports whether a browser process is live. It is what the status bar
// reads, so a running browser is never invisible (§9.1).
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live == nil {
		return false
	}
	select {
	case <-m.live.proc.Done():
		return false
	default:
		return true
	}
}

// Navigate loads a URL in the active page.
func (m *Manager) Navigate(ctx context.Context, rawURL string) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	page, err := m.ensureLocked(ctx)
	if err != nil {
		return State{}, err
	}
	state, err := page.Navigate(ctx, rawURL)
	if err != nil {
		return State{}, m.failLocked(err)
	}
	return state, nil
}

// Read returns the bounded aria snapshot of the page or one element.
func (m *Manager) Read(ctx context.Context, handle string, maxChars int) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	page, err := m.ensureLocked(ctx)
	if err != nil {
		return "", err
	}
	text, err := page.Read(ctx, handle, maxChars)
	if err != nil {
		return "", m.failLocked(err)
	}
	return text, nil
}

// Click activates the element a handle addresses.
func (m *Manager) Click(ctx context.Context, handle string) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	page, err := m.ensureLocked(ctx)
	if err != nil {
		return State{}, err
	}
	state, err := page.Click(ctx, handle)
	if err != nil {
		return State{}, m.failLocked(err)
	}
	return state, nil
}

// TypeText types into an element and optionally submits.
func (m *Manager) TypeText(ctx context.Context, handle, text string, submit bool) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	page, err := m.ensureLocked(ctx)
	if err != nil {
		return State{}, err
	}
	state, err := page.TypeText(ctx, handle, text, submit)
	if err != nil {
		return State{}, m.failLocked(err)
	}
	return state, nil
}

// Screenshot writes a PNG artifact into the session's screenshot directory.
func (m *Manager) Screenshot(ctx context.Context, fullPage bool) (Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	page, err := m.ensureLocked(ctx)
	if err != nil {
		return Artifact{}, err
	}
	dir := ScreenshotDir(m.opts.ProjectDir, m.opts.Session)
	path, err := NextScreenshotPath(dir)
	if err != nil {
		return Artifact{}, err
	}
	artifact, err := page.Screenshot(ctx, path, fullPage)
	if err != nil {
		return Artifact{}, m.failLocked(err)
	}
	artifact.Path = m.relative(artifact.Path)
	return artifact, nil
}

// Download activates a download element and saves the file into the session's
// download directory.
func (m *Manager) Download(ctx context.Context, handle string) (Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	page, err := m.ensureLocked(ctx)
	if err != nil {
		return Artifact{}, err
	}
	artifact, err := page.Download(ctx, handle, DownloadDir(m.opts.ProjectDir, m.opts.Session))
	if err != nil {
		return Artifact{}, m.failLocked(err)
	}
	artifact.Path = m.relative(artifact.Path)
	return artifact, nil
}

// Close stops the browser and releases the profile. An engagement profile stays
// on disk; a safe-mode profile is deleted (§5).
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	var errs []error
	if m.live != nil {
		errs = append(errs, m.dropLocked())
	}
	if m.profile != nil {
		errs = append(errs, m.profile.Close())
		m.profile = nil
	}
	return errors.Join(errs...)
}

// ensureLocked returns the active page, launching or relaunching the browser
// when needed. A browser that died between calls is relaunched here, with the
// same profile, so a crash never costs the engagement's login (§8).
func (m *Manager) ensureLocked(ctx context.Context) (*Page, error) {
	if m.closed {
		return nil, errors.New("browser: the session's browser is closed")
	}
	if m.live != nil {
		select {
		case <-m.live.proc.Done():
			_ = m.dropLocked()
		default:
			return m.live.page, nil
		}
	}

	if m.opts.ProxyURL == nil {
		return nil, fmt.Errorf("%w: the browser needs the harness proxy, and no proxy was configured", ErrNoProxy)
	}
	proxy, err := m.opts.ProxyURL(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(proxy) == "" {
		return nil, fmt.Errorf("%w: the session has no proxy listener to point the browser at", ErrNoProxy)
	}

	if m.binary.Path == "" {
		binary, err := m.opts.ResolveBinary(ctx)
		if err != nil {
			return nil, err
		}
		m.binary = binary
	}
	if m.profile == nil {
		profile, err := OpenProfile(ProfileOptions{
			Root:       m.opts.Root,
			ProjectDir: m.opts.ProjectDir,
			Engagement: m.opts.Engagement,
			Session:    m.opts.Session,
			Now:        m.opts.Now,
		})
		if err != nil {
			return nil, err
		}
		m.profile = profile
	}
	if err := m.profile.Lock(); err != nil {
		return nil, err
	}

	spki := ""
	if m.opts.CASPKI != nil {
		pin, err := m.opts.CASPKI(ctx)
		if err != nil {
			_ = m.profile.Unlock()
			return nil, err
		}
		spki = pin
	}

	admission, err := newGate()
	if err != nil {
		_ = m.profile.Unlock()
		return nil, err
	}
	args, err := Args(Launch{
		Binary:     m.binary.Path,
		ProfileDir: m.profile.Dir(),
		ProxyURL:   proxy,
		CASPKI:     spki,
	})
	if err != nil {
		_ = admission.Close()
		_ = m.profile.Unlock()
		return nil, err
	}

	// A relaunch reuses the profile, and the previous run's DevToolsActivePort
	// names a listener that is gone: remove it, so the file polled below is the
	// new run's and not a dead endpoint.
	_ = os.Remove(filepath.Join(m.profile.Dir(), "DevToolsActivePort"))

	proc, err := m.opts.Starter.Start(ctx, m.binary.Path, args)
	if err != nil {
		_ = admission.Close()
		_ = m.profile.Unlock()
		return nil, fmt.Errorf("browser: launch %s: %w", m.binary.Path, err)
	}
	port, browserPath, err := waitDevToolsPort(m.profile.Dir(), proc)
	if err != nil {
		_ = proc.Kill()
		_ = admission.Close()
		_ = m.profile.Unlock()
		return nil, err
	}
	admission.SetTarget("127.0.0.1:" + port)

	wsURL := fmt.Sprintf("ws://%s%s?token=%s", admission.Addr(), browserPath, url.QueryEscape(admission.Token()))
	conn, err := m.opts.Dialer.Dial(ctx, wsURL)
	if err != nil {
		_ = proc.Kill()
		_ = admission.Close()
		_ = m.profile.Unlock()
		return nil, err
	}
	page, err := Attach(ctx, conn)
	if err != nil {
		_ = conn.Close()
		_ = proc.Kill()
		_ = admission.Close()
		_ = m.profile.Unlock()
		return nil, fmt.Errorf("browser: attach to the page: %w", err)
	}

	m.live = &liveSession{proc: proc, gate: admission, conn: conn, page: page}
	return page, nil
}

// failLocked turns a transport failure into the named error and releases the
// profile, so the next call can relaunch with it (§8). Any other tool error
// leaves the browser running.
func (m *Manager) failLocked(err error) error {
	if !errors.Is(err, ErrTransport) {
		return err
	}
	_ = m.dropLocked()
	return err
}

// dropLocked tears down a dead browser and releases the profile lock. A live
// browser is asked to close first, so its profile — cookies included — is
// flushed before the process is gone (§5).
func (m *Manager) dropLocked() error {
	live := m.live
	m.live = nil
	var errs []error
	if live != nil {
		stopBrowser(live)
		if live.conn != nil {
			errs = append(errs, live.conn.Close())
		}
		if live.proc != nil {
			errs = append(errs, live.proc.Kill())
		}
		if live.gate != nil {
			errs = append(errs, live.gate.Close())
		}
	}
	if m.profile != nil {
		errs = append(errs, m.profile.Unlock())
	}
	return errors.Join(errs...)
}

// stopBrowser asks Chromium to close gracefully and waits briefly for it. A
// browser that is already gone is left alone; one that ignores the request is
// killed by the caller.
func stopBrowser(live *liveSession) {
	if live.proc == nil {
		return
	}
	select {
	case <-live.proc.Done():
		return
	default:
	}
	if live.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = live.conn.Call(ctx, "", "Browser.close", map[string]any{}, nil)
		cancel()
	}
	select {
	case <-live.proc.Done():
	case <-time.After(500 * time.Millisecond):
	}
}

// relative renders an artifact path relative to the project, the form findings
// evidence uses.
func (m *Manager) relative(path string) string {
	if strings.TrimSpace(m.opts.ProjectDir) == "" {
		return path
	}
	rel, err := filepath.Rel(m.opts.ProjectDir, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return path
	}
	return filepath.ToSlash(rel)
}

// waitDevToolsPort waits for Chromium to publish its CDP port and WebSocket
// path in the profile's DevToolsActivePort file. The port stays off the command
// line, so it is not visible to another local process reading argv.
func waitDevToolsPort(profileDir string, proc Process) (string, string, error) {
	path := filepath.Join(profileDir, "DevToolsActivePort")
	deadline := time.Now().Add(devToolsReadyTimeout)
	for {
		//nolint:gosec // the path is the harness-owned profile directory.
		data, err := os.ReadFile(path)
		if err == nil {
			if port, wsPath, ok := parseDevToolsActivePort(string(data)); ok {
				return port, wsPath, nil
			}
		}
		select {
		case <-proc.Done():
			log := strings.TrimSpace(proc.Log())
			if log != "" {
				return "", "", fmt.Errorf("browser: the browser exited before publishing its CDP port: %s", lastLines(log, 1200))
			}
			return "", "", errors.New("browser: the browser exited before publishing its CDP port")
		case <-time.After(25 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			_ = proc.Kill()
			return "", "", fmt.Errorf("browser: the browser did not publish its CDP port within %s", devToolsReadyTimeout)
		}
	}
}

// parseDevToolsActivePort reads the two-line file: the port, then the browser's
// WebSocket path.
func parseDevToolsActivePort(raw string) (string, string, bool) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	if len(lines) < 2 {
		return "", "", false
	}
	port := strings.TrimSpace(lines[0])
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return "", "", false
	}
	wsPath := strings.TrimSpace(lines[1])
	if !strings.HasPrefix(wsPath, "/") {
		return "", "", false
	}
	return port, wsPath, true
}

// lastLines keeps a failed launch's diagnostic bounded and readable.
func lastLines(log string, limit int) string {
	log = strings.TrimSpace(log)
	if len(log) <= limit {
		return log
	}
	return "…" + log[len(log)-limit:]
}

// execStarter runs the browser as a subprocess with its diagnostics captured.
type execStarter struct{}

// Start implements Starter.
//
//nolint:gosec // the binary is the resolved prerequisite and the args are harness-built.
func (execStarter) Start(_ context.Context, path string, args []string) (Process, error) {
	cmd := exec.Command(path, args...)
	log := &ringLog{limit: maxProcessLog}
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &execProcess{cmd: cmd, log: log, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

// execProcess is a running browser subprocess.
type execProcess struct {
	cmd  *exec.Cmd
	log  *ringLog
	done chan struct{}
	err  error
	once sync.Once
}

// Done implements Process.
func (p *execProcess) Done() <-chan struct{} { return p.done }

// Err implements Process.
func (p *execProcess) Err() error { return p.err }

// Kill implements Process. A browser that already exited is not an error.
func (p *execProcess) Kill() error {
	var err error
	p.once.Do(func() {
		if p.cmd.Process != nil {
			err = p.cmd.Process.Kill()
			if errors.Is(err, os.ErrProcessDone) {
				err = nil
			}
		}
	})
	return err
}

// Log implements Process.
func (p *execProcess) Log() string { return p.log.String() }

// ringLog is a bounded process log. A browser can be noisy, and the harness
// only needs the tail that explains a failed launch.
type ringLog struct {
	mu    sync.Mutex
	limit int
	buf   []byte
}

// Write appends to the bounded log.
func (l *ringLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	if len(l.buf) > l.limit {
		l.buf = append([]byte(nil), l.buf[len(l.buf)-l.limit:]...)
	}
	return len(p), nil
}

// String returns the retained log.
func (l *ringLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(l.buf)
}
