package containerlayer

import "time"

// ProxyEventKind is the closed vocabulary of proxy decisions the audit trail
// records (§9). The audit records decisions, not traffic: the capture is the
// traffic record, and it is an artifact under .styx/out/.
type ProxyEventKind string

const (
	// EventProxyStart is the proxy listening for a session.
	EventProxyStart ProxyEventKind = "proxy-start"
	// EventProxyRestart is the proxy stopping and listening again on the same
	// address, reusing the engagement's CA.
	EventProxyRestart ProxyEventKind = "proxy-restart"
	// EventProxyStop is the proxy no longer listening.
	EventProxyStop ProxyEventKind = "proxy-stop"
	// EventCACreated is the first use of an engagement's certification
	// authority (§4.4).
	EventCACreated ProxyEventKind = "ca-create"
	// EventScopeDenial is a proxied request refused on scope (§4.3). It is
	// never a prompt: a tunnel has no in-flight call to raise a card on.
	EventScopeDenial ProxyEventKind = "scope-denial"
)

// ProxyEvent is one proxy decision, for the audit trail. It carries no
// credential and no header value: a denial names the destination, never the
// traffic (§9).
type ProxyEvent struct {
	// Kind is the decision the event records.
	Kind ProxyEventKind `json:"kind"`
	// Time is when the decision was made; a zero value is stamped by the
	// recorder.
	Time time.Time `json:"time"`
	// Listener is the proxy's address, for lifecycle events.
	Listener string `json:"listener,omitempty"`
	// Host is the destination a denial refused.
	Host string `json:"host,omitempty"`
	// Reason is the closed-set reason, "out-of-scope" for a scope denial.
	Reason string `json:"reason,omitempty"`
	// Detail is the diagnostic: the cause, or the CA's path for a creation.
	Detail string `json:"detail,omitempty"`
}

// Auditor records proxy decisions in the session's audit trail (§9). A
// non-nil error fails the decision it belongs to: a lifecycle event that
// cannot be recorded refuses to start, and a denial stays a denial.
type Auditor interface {
	RecordProxyEvent(ProxyEvent) error
}

// recordEvent records one decision when an auditor is configured.
func (p *EgressProxy) recordEvent(ev ProxyEvent) error {
	if p.auditor == nil {
		return nil
	}
	if ev.Time.IsZero() {
		ev.Time = p.now()
	}
	return p.auditor.RecordProxyEvent(ev)
}

// now is the proxy's clock, so a test can pin it.
func (p *EgressProxy) now() time.Time {
	if p.intercept != nil && p.intercept.now != nil {
		return p.intercept.now()
	}
	return time.Now()
}
