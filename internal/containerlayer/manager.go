package containerlayer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
)

// errNoRuntimeFactory is returned when a manager is asked to start without a
// way to build a runtime.
var errNoRuntimeFactory = errors.New("containerlayer: no container runtime factory configured")

// SessionInfo describes a started session, for the one-time surfacing the spec
// requires (§5.2, §9.5): the status bar reads Isolation, the stream shows the
// banner, the audit trail records the level.
type SessionInfo struct {
	// Isolation is the enforcement level the session established.
	Isolation Isolation
	// Degraded reports whether egress is harness-mediated rather than
	// enforced at the host edge.
	Degraded bool
	// ProxyURL is the fallback proxy's URL when degraded, else empty.
	ProxyURL string
}

// Manager lazily starts the session container on first exec and tears it down
// on Close. Lazy start keeps a plain safe-mode session from touching Docker
// until the model actually runs something, and lets the app surface the
// isolation level at exactly the moment it becomes real.
type Manager struct {
	opts ManagerOptions

	mu        sync.Mutex
	rt        Runtime
	session   *Session
	startErr  error
	isolation Isolation
	info      SessionInfo
}

// ManagerOptions configures a Manager.
type ManagerOptions struct {
	// RuntimeFactory builds the container runtime on first use. Required.
	RuntimeFactory func() (Runtime, error)
	// Image, Workspace, ContainerWorkspace, Allowed, Firewall, FirewallRunner,
	// and ProxyAddr are passed to the started session.
	Image              string
	Workspace          string
	ContainerWorkspace string
	Allowed            []netip.Prefix
	Pins               []NamePin
	Firewall           Firewall
	FirewallRunner     Runner
	ProxyAddr          string
	DNSAddr            string
	// OnStart is called once after the session starts, so the app can surface
	// the isolation level (banner, status, audit).
	OnStart func(SessionInfo)
}

// NewManager builds a manager. It does not touch a runtime until first Start.
func NewManager(opts ManagerOptions) *Manager {
	return &Manager{opts: opts, isolation: IsolationUnavailable}
}

// Start brings the session up if it is not already running, and is idempotent.
// A failed start is cached, so a broken runtime is reported once, not retried
// on every exec.
func (m *Manager) Start(ctx context.Context) (*Session, error) {
	// The lock spans the start so two concurrent execs cannot race into two
	// containers. The callback is invoked after unlocking, so it can read the
	// manager without deadlocking.
	m.mu.Lock()
	if m.session != nil {
		session := m.session
		m.mu.Unlock()
		return session, nil
	}
	if m.startErr != nil {
		err := m.startErr
		m.mu.Unlock()
		return nil, err
	}

	session, rt, err := m.start(ctx, m.opts)
	if err != nil {
		m.startErr = err
		m.isolation = IsolationUnavailable
		m.mu.Unlock()
		if rt != nil {
			_ = rt.Close()
		}
		return nil, err
	}
	m.rt = rt
	m.session = session
	m.isolation = session.Isolation()
	m.info = SessionInfo{
		Isolation: session.Isolation(),
		Degraded:  session.Isolation() == IsolationDegraded,
		ProxyURL:  session.ProxyURL(),
	}
	info, onStart := m.info, m.opts.OnStart
	m.mu.Unlock()

	if onStart != nil {
		onStart(info)
	}
	return session, nil
}

// start builds the runtime and session. It runs outside the manager's lock so
// a slow container start does not serialize unrelated reads.
func (m *Manager) start(ctx context.Context, opts ManagerOptions) (*Session, Runtime, error) {
	if opts.RuntimeFactory == nil {
		return nil, nil, errNoRuntimeFactory
	}
	rt, err := opts.RuntimeFactory()
	if err != nil {
		return nil, nil, err
	}
	session, err := StartSession(ctx, SessionOptions{
		Runtime:            rt,
		Image:              opts.Image,
		Name:               newSessionSeed(),
		Workspace:          opts.Workspace,
		ContainerWorkspace: opts.ContainerWorkspace,
		Allowed:            opts.Allowed,
		Pins:               opts.Pins,
		Firewall:           opts.Firewall,
		FirewallRunner:     opts.FirewallRunner,
		ProxyAddr:          opts.ProxyAddr,
		DNSAddr:            opts.DNSAddr,
	})
	if err != nil {
		return nil, rt, err
	}
	return session, rt, nil
}

// Shell runs a shell command, starting the session if needed.
func (m *Manager) Shell(ctx context.Context, command string) (string, error) {
	session, err := m.Start(ctx)
	if err != nil {
		return "", err
	}
	return session.Shell(ctx, command)
}

// Code runs a code snippet, starting the session if needed.
func (m *Manager) Code(ctx context.Context, lang, code string) (string, error) {
	session, err := m.Start(ctx)
	if err != nil {
		return "", err
	}
	return session.Code(ctx, lang, code)
}

// Isolation is the current enforcement level. Before start it reports
// IsolationUnavailable; after a failed start it stays unavailable — never a
// silent "container".
func (m *Manager) Isolation() Isolation {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isolation
}

// Info returns the started session's info, or an unavailable one before start.
func (m *Manager) Info() SessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.info
}

// Close tears the session and runtime down. It is idempotent.
func (m *Manager) Close() error {
	m.mu.Lock()
	session, rt := m.session, m.rt
	m.session, m.rt = nil, nil
	m.mu.Unlock()

	var errs []error
	if session != nil {
		if err := session.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if rt != nil {
		if err := rt.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// newSessionSeed returns a fresh unpredictable seed, so two sessions never
// share a network, bridge, table, or container name.
func newSessionSeed() string {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fall back to a fixed marker; session names may collide but the
		// harness still refuses to run unenforced.
		return "styx-session"
	}
	return hex.EncodeToString(buf[:])
}
