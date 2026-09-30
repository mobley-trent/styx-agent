package policy

// Call is the tool call the engine evaluates: the tool name plus the call's
// full parameter object. Params are arbitrary JSON-style values (the decoded
// arguments object); the engine addresses them with JSON-pointer paths.
type Call struct {
	// Tool is the invoked tool's name ("bash", "web_fetch", an MCP tool name).
	Tool string
	// Params is the call's full parameter object (JSON-compatible values).
	Params map[string]any
	// ScopeTargets are the network/exec targets the call intends to touch,
	// resolved by the caller (§7.2: every network call's real destination is
	// re-resolved before the engine sees it). Pure file tools pass none.
	ScopeTargets []Target
	// Destructive marks the call as destructive-tagged (§8.3: RE sample
	// detonation, rm-class exec). Only the tool registry sets this; the
	// engine never infers it from parameters.
	Destructive bool
	// ExploitClass marks the call as exploit-class tooling (§6.3), tagged by
	// the tool registry the same way.
	ExploitClass bool
}

// Target is one concrete network/exec destination a call intends to touch.
// The engine treats it opaquely: engagement decides membership.
type Target struct {
	// Addr is the concrete destination: an IP literal, a hostname, or
	// host:port. Comparison semantics live in the engagement scope.
	Addr string
}
