// Package diff computes line-oriented diffs between two versions of a file
// and renders them in unified form.
//
// Boundary rule: diff is pure — no I/O, no policy, no styling. The agent
// computes diffs, the session log persists the structured lines, and the TUI
// applies its own presentation (§9.2).
package diff
