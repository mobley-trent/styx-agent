package browser

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// ProfileOptions describes the profile a browser run uses (§5).
type ProfileOptions struct {
	// Root is the browser profile root; empty means DefaultProfileRoot.
	Root string
	// ProjectDir is the project root. Its component is derived exactly as the
	// session and state stores derive theirs, so two checkouts named alike
	// never share a profile.
	ProjectDir string
	// Engagement is the engagement name. Empty means safe mode, which has no
	// engagement to scope a profile to.
	Engagement string
	// Session is the session id recorded in the lockfile. It is provenance,
	// never model-supplied.
	Session string
	// Now stamps the lock; nil means time.Now.
	Now func() time.Time
}

// DefaultProfileRoot is the browser profile root (§5):
// $XDG_DATA_HOME/styx/browsers, else ~/.local/share/styx/browsers — beside the
// session and engagement stores, never inside the repo. It returns "" when no
// home directory is known.
func DefaultProfileRoot() string {
	if dir := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dir != "" {
		return filepath.Join(dir, "styx", "browsers")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "share", "styx", "browsers")
}

// ProfileDir is an engagement browse profile's path (§5):
// <root>/<project>/<engagement>. It is exported so the harness can report the
// path it guards without opening the profile.
func ProfileDir(root, projectDir, engagement string) string {
	return filepath.Join(root, sessions.ProjectKey(projectDir), engagementstate.EngagementKey(engagement))
}

// Profile is one browser profile directory. An engagement profile is guarded by
// a pid-checked lockfile: one writer, and a second writer is refused with the
// locking session named (§5, spec §10.6). A safe-mode profile is ephemeral and
// removed when the session ends; it carries no lock because nothing else can
// name it.
type Profile struct {
	dir       string
	ephemeral bool
	session   string
	now       func() time.Time

	mu     sync.Mutex
	locked bool
}

// OpenProfile creates (or reuses) the profile directory. It takes no lock:
// Lock is what claims the writer role, and a relaunch after a crash re-locks
// the same profile so cookies survive.
func OpenProfile(opts ProfileOptions) (*Profile, error) {
	root := strings.TrimSpace(opts.Root)
	if root == "" {
		root = DefaultProfileRoot()
	}
	if root == "" {
		return nil, errors.New("browser: no profile root (no home directory)")
	}
	if strings.TrimSpace(opts.ProjectDir) == "" {
		return nil, errors.New("browser: a profile needs the project directory")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("browser: create profile root %s: %w", root, err)
	}

	p := &Profile{session: strings.TrimSpace(opts.Session), now: now}
	engagement := strings.TrimSpace(opts.Engagement)
	if engagement == "" {
		// Safe mode: no engagement to scope a profile to, so it is ephemeral
		// and deleted at session end (§5).
		dir, err := os.MkdirTemp(root, "safe-")
		if err != nil {
			return nil, fmt.Errorf("browser: create an ephemeral profile: %w", err)
		}
		//nolint:gosec // 0700 is the restrictive mode for a profile directory.
		if err := os.Chmod(dir, 0o700); err != nil {
			_ = os.RemoveAll(dir)
			return nil, fmt.Errorf("browser: restrict the ephemeral profile: %w", err)
		}
		p.dir, p.ephemeral = dir, true
		return p, nil
	}

	dir := ProfileDir(root, opts.ProjectDir, engagement)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("browser: create profile %s: %w", dir, err)
	}
	//nolint:gosec // 0700 is the restrictive mode for a profile directory.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("browser: restrict profile %s: %w", dir, err)
	}
	p.dir = dir
	return p, nil
}

// Dir is the profile's directory.
func (p *Profile) Dir() string { return p.dir }

// Ephemeral reports whether Close deletes the profile.
func (p *Profile) Ephemeral() bool { return p.ephemeral }

// Lock claims the profile's writer role. A live holder leaves the profile
// refused rather than shared; a stale holder (a process that is gone, or this
// session's own leftover) is reclaimed.
func (p *Profile) Lock() error {
	if p.ephemeral {
		p.mu.Lock()
		p.locked = true
		p.mu.Unlock()
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.locked {
		return nil
	}
	path := p.lockPath()
	for attempt := 0; attempt < 2; attempt++ {
		//nolint:gosec // the path is derived from the profile root and sanitized names.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			record := lockRecord{PID: os.Getpid(), Session: p.session, At: p.now().UTC()}
			encoded, encErr := encodeLock(record)
			if encErr == nil {
				_, encErr = f.Write(encoded)
			}
			closeErr := f.Close()
			if encErr != nil || closeErr != nil {
				_ = os.Remove(path)
				return errors.Join(encErr, closeErr)
			}
			p.locked = true
			return nil
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("browser: lock profile %s: %w", path, err)
		}

		holder, readErr := readProfileLock(path)
		if readErr != nil {
			// An unreadable lockfile is not a holder we can honor: treat it as
			// stale rather than block every future session on it.
			_ = os.Remove(path)
			continue
		}
		if processAlive(holder.PID) && !p.ownsLock(holder) {
			return fmt.Errorf("%w: held by %s; another session is browsing this engagement's profile",
				ErrLocked, describeHolder(holder))
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("browser: reclaim stale lock %s: %w", path, removeErr)
		}
	}
	return fmt.Errorf("%w: another session", ErrLocked)
}

// Unlock releases the writer role. It is idempotent.
func (p *Profile) Unlock() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.locked {
		return nil
	}
	p.locked = false
	if p.ephemeral {
		return nil
	}
	path := p.lockPath()
	holder, err := readProfileLock(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("browser: release profile lock %s: %w", path, err)
	}
	if !p.ownsLock(holder) {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("browser: release profile lock %s: %w", path, err)
	}
	return nil
}

// Close releases the lock and removes an ephemeral profile. An engagement
// profile stays: its cookies are the engagement's, not the session's (§5).
func (p *Profile) Close() error {
	err := p.Unlock()
	if !p.ephemeral {
		return err
	}
	if removeErr := os.RemoveAll(p.dir); removeErr != nil {
		return errors.Join(err, fmt.Errorf("browser: remove ephemeral profile %s: %w", p.dir, removeErr))
	}
	return err
}

// lockPath is the lockfile inside the profile.
func (p *Profile) lockPath() string { return filepath.Join(p.dir, ".lock") }

// ownsLock reports whether a lockfile describes this session: the same process
// and the same session id. A lock this process holds for a different session
// belongs to another store and is honored like any other.
func (p *Profile) ownsLock(record lockRecord) bool {
	return record.PID == os.Getpid() && record.Session == p.session
}

// readProfileLock reads a lockfile's holder.
func readProfileLock(path string) (lockRecord, error) {
	//nolint:gosec // the path is derived from the profile root.
	data, err := os.ReadFile(path)
	if err != nil {
		return lockRecord{}, err
	}
	var record lockRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return lockRecord{}, err
	}
	return record, nil
}

// describeHolder renders a lock holder for the refusal message.
func describeHolder(record lockRecord) string {
	who := "pid " + fmt.Sprint(record.PID)
	if record.Session != "" {
		who = "session " + record.Session + " (pid " + fmt.Sprint(record.PID) + ")"
	}
	return who
}

// processAlive reports whether a pid names a running process. Signal 0 is the
// existence and permission check; EPERM means it exists under another user.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return errors.Is(err, syscall.EPERM)
	}
	return true
}
