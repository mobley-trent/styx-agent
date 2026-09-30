package policy

import (
	"errors"
	"fmt"
	"time"
)

// Mode is the harness operating mode (§6.2).
type Mode string

const (
	// ModeSafe is the default mode: permissive reads, guarded
	// writes/exec/network.
	ModeSafe Mode = "safe"
	// ModeEngagement is the explicitly authorized mode, unlocked only through
	// the engagement gate. The flag alone widens nothing.
	ModeEngagement Mode = "engagement"
)

// Valid reports whether the mode is one of the two defined modes.
func (m Mode) Valid() bool { return m == ModeSafe || m == ModeEngagement }

// TimeWindow is the engagement file's ROE time window (§7.1): outside the
// window, network/exec actions are denied regardless of scope. Start and End
// are "HH:MM" wall-clock strings; TZ is an IANA location name (default UTC
// when omitted).
type TimeWindow struct {
	Start string
	End   string
	TZ    string
}

// ROE is the machine-checked rules-of-engagement limit set (§6.3). Zero
// value: no engagement — nothing widened, nothing limited.
type ROE struct {
	// ExploitAllowed is the master gate for exploit-class tooling.
	ExploitAllowed bool
	// DestructiveForbidden hard-denies destructive-tagged calls.
	DestructiveForbidden bool
	// TimeWindow optionally bounds network/exec to a daily window.
	TimeWindow *TimeWindow
}

// Check evaluates a call against the ROE hard limits. A nil ROE means no
// engagement is active: nothing is limited (and nothing widened — the engine
// never consults ROE in safe mode). A non-nil error is a hard deny whose
// message is the audit trail; it is never promptable (§6.2).
//
// The ROE limits bind by call class: exploit-class calls need
// ExploitAllowed; destructive-tagged calls fail when DestructiveForbidden;
// network/exec calls must land inside the time window. Plain read-only tools
// trip none of these limits.
func (r *ROE) Check(call Call, now time.Time) error {
	if r == nil {
		return nil
	}
	if call.ExploitClass && !r.ExploitAllowed {
		return errors.New("ROE: exploit_allowed is false — exploit-class tooling is hard-denied")
	}
	if call.Destructive && r.DestructiveForbidden {
		return errors.New("ROE: destructive_forbidden is true — destructive-tagged calls are hard-denied")
	}
	if call.NetworkOrExec() && r.TimeWindow != nil {
		if inWindow, err := r.TimeWindow.contains(now); err != nil {
			return fmt.Errorf("ROE: unusable time_window: %w", err)
		} else if !inWindow {
			return fmt.Errorf("ROE: outside time_window %s–%s (%s)",
				r.TimeWindow.Start, r.TimeWindow.End, r.TimeWindow.tzName())
		}
	}
	return nil
}

// NetworkOrExec reports whether the call is a network or exec action — the
// class the time_window limit binds (§6.3: "network/exec outside the window
// denied regardless of scope"). A call counts when it carries concrete
// targets (network), is tagged exploit-class (inherently execution-shaped),
// or invokes an exec tool; read-only file tools do not.
func (c Call) NetworkOrExec() bool {
	if len(c.ScopeTargets) > 0 || c.ExploitClass {
		return true
	}
	switch c.Tool {
	case "bash", "code_exec":
		return true
	default:
		return false
	}
}

// contains reports whether now falls inside the window in its timezone. A
// window crossing midnight (start > end) spans [start, end) across 00:00.
func (w *TimeWindow) contains(now time.Time) (bool, error) {
	midnight, err := w.location()
	if err != nil {
		return false, err
	}
	local := now.In(midnight)
	if err := w.validate(); err != nil {
		return false, err
	}
	cur := local.Hour()*60 + local.Minute()
	start := mustMinutes(w.Start)
	end := mustMinutes(w.End)
	if start == end {
		return true, nil // degenerate window: treat as all day
	}
	if start < end {
		return cur >= start && cur < end, nil
	}
	return cur >= start || cur < end, nil // crosses midnight
}

// validate checks the window's fields parse; contains calls it after the
// location load so errors surface in a stable order.
func (w *TimeWindow) validate() error {
	if _, err := parseHM(w.Start); err != nil {
		return fmt.Errorf("start %q: %w", w.Start, err)
	}
	if _, err := parseHM(w.End); err != nil {
		return fmt.Errorf("end %q: %w", w.End, err)
	}
	return nil
}

// location resolves the window's timezone, defaulting to UTC when TZ is
// absent (§7.1).
func (w *TimeWindow) location() (*time.Location, error) {
	name := w.tzName()
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("time_window tz %q: %w", name, err)
	}
	return loc, nil
}

// tzName returns the configured zone name, or UTC when unset.
func (w *TimeWindow) tzName() string {
	if w.TZ == "" {
		return "UTC"
	}
	return w.TZ
}

// parseHM parses an "HH:MM" wall-clock string into minutes since midnight.
// time.Parse's "15:04" layout validates ranges itself (00–23, 00–59).
func parseHM(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, fmt.Errorf("invalid HH:MM: %w", err)
	}
	return t.Hour()*60 + t.Minute(), nil
}

// mustMinutes parses a pre-validated "HH:MM" string; callers validate first.
func mustMinutes(s string) int {
	m, err := parseHM(s)
	if err != nil {
		panic(fmt.Sprintf("policy: internal error parsing %q: %v", s, err))
	}
	return m
}
