package app

import (
	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/containerlayer"
	"github.com/mobley-trent/styx-agent/internal/engagement"
	"github.com/mobley-trent/styx-agent/internal/policy"
)

// This file is the harness's half of the interception proxy's decisions
// (docs/browser-and-proxy.md §9): the container layer emits lifecycle, CA
// custody, and scope-denial events; the audit trail records them as decisions.
// Traffic is the capture's business, never the audit's.

// proxyAuditor implements containerlayer.Auditor over the session audit trail.
type proxyAuditor struct{ h *Harness }

// RecordProxyEvent implements containerlayer.Auditor.
func (a proxyAuditor) RecordProxyEvent(ev containerlayer.ProxyEvent) error {
	if a.h.audit == nil {
		return nil
	}
	verdict := audit.VerdictAllow
	reason := string(ev.Kind)
	if ev.Kind == containerlayer.EventScopeDenial {
		// A denial is a refusal, and the closed-set reason is the one the
		// capture and the 403 carry (§4.3).
		verdict = audit.VerdictDeny
		reason = "out-of-scope"
	}
	if ev.Reason == "failed" {
		verdict = audit.VerdictDeny
		reason = string(ev.Kind) + "-failed"
	}

	params := map[string]any{"event": string(ev.Kind)}
	for key, value := range map[string]string{
		"listener": ev.Listener,
		"host":     ev.Host,
		"reason":   ev.Reason,
		"detail":   ev.Detail,
	} {
		if value != "" {
			params[key] = value
		}
	}
	// No isolation level here on purpose: start events are recorded while the
	// session is still coming up, so a level read would both be premature and
	// deadlock against the manager's start lock. The level is surfaced where it
	// exists — the session banner, the status bar, and the tool-call records.
	return a.h.audit.Append(audit.Record{
		Mode:    a.mode(),
		Tool:    "proxy",
		Params:  params,
		Verdict: verdict,
		Reason:  reason,
	})
}

// interception wires the engagement's interception proxy
// (docs/browser-and-proxy.md §4.4, §4.5): one CA per engagement, created on
// first use and reused for its life, and one capture per session. Safe mode
// returns nil — no pinned scope to enforce, nothing to attribute a capture to.
func (h *Harness) interception(eng *engagement.Engagement) (*containerlayer.InterceptionOptions, error) {
	if eng == nil {
		return nil, nil
	}
	ca, err := containerlayer.OpenCA(containerlayer.CAOptions{
		ProjectDir: h.WorkDir,
		Engagement: eng.Name(),
		Now:        h.now,
	})
	if err != nil {
		return nil, err
	}
	session := h.SessionID()
	if session == "" {
		session = "session"
	}
	return &containerlayer.InterceptionOptions{
		CA:         ca,
		CaptureDir: containerlayer.CapturePath(h.WorkDir, session),
		Now:        h.now,
	}, nil
}

// mode is the operating mode the decision was taken under.
func (a proxyAuditor) mode() audit.Mode {
	a.h.mu.Lock()
	defer a.h.mu.Unlock()
	if a.h.Mode == policy.ModeEngagement {
		return audit.ModeEngagement
	}
	return audit.ModeSafe
}
