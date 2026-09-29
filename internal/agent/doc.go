// Package agent implements the agent loop: the single hand-rolled cycle of
// system-prompt assembly, model call, tool dispatch, and tool results,
// bounded by turn caps.
//
// Boundary rule: agent depends on the ModelClient interface (declared beside
// the loop), never on the concrete model client; all tool calls pass through
// the policy engine, and subagents run inside this loop as tools.
package agent
