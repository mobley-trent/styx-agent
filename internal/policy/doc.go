// Package policy implements the policy engine, the single choke point of the
// safety model: rule table, JSON-pointer globs, ROE limits, and verdicts.
//
// Boundary rule: policy is pure. It imports nothing from tui, model, or
// agent. The engine is a total function — (tool call, mode, scope, rule
// table, clock) → verdict — so tests stay table-driven and fast.
package policy
