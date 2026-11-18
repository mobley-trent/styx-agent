package browser

import "errors"

// The browser layer's named failures. Every one is visible at the tool
// boundary (docs/browser-and-proxy.md §8): nothing here is silently downgraded
// to a missing capability or a stale page.
var (
	// ErrPrerequisite is a missing or wrong pinned browser build (§3.1). The
	// capability is unavailable for the session; everything else still works.
	ErrPrerequisite = errors.New("browser: the pinned browser prerequisite is not met")
	// ErrStaleHandle is a handle the current snapshot did not expose, or one
	// whose element is gone. The message always tells the model to take a
	// fresh snapshot (§3.2).
	ErrStaleHandle = errors.New("browser: stale handle")
	// ErrLocked is a profile another live session holds. One writer only; the
	// message names the locking session (§5, spec §10.6).
	ErrLocked = errors.New("browser: the browser profile is locked")
	// ErrTransport is a CDP failure: the browser died, the connection broke,
	// or the renderer went away. The next call relaunches with the profile
	// intact and the lock released (§8).
	ErrTransport = errors.New("browser: CDP transport failed")
	// ErrNoProxy is a launch with no proxy listener to point at. The browser's
	// only egress path is the harness proxy (§3.1), so this is a refusal, not
	// a direct connection.
	ErrNoProxy = errors.New("browser: no proxy listener is available")
)
