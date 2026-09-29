// Package subagent implements dispatch_subagent: role-preset registry and
// the isolated-context subagent runs dispatched as an ordinary tool.
//
// Boundary rule: subagent runs happen inside the main agent loop, never as a
// separate orchestrator; one nesting level, and every subagent tool call
// passes the same policy engine.
package subagent
