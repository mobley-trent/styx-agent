// Package tui implements the terminal UI: the Bubble Tea program, streaming
// chat view, status bar, permission-prompt cards, and plan blocks.
//
// Rendering model (ADR-0001): committed transcript lines are printed once into
// the terminal's own scrollback and are immutable; only a fixed bottom live
// region — still-live subagent blocks, the streaming partial, the live prompt
// card, the input line, and the status bar — is re-rendered per frame. The
// view never uses AltScreen, so the terminal owns scrolling and search.
//
// Boundary rule: tui renders events and collects decisions; it never talks to
// the model, executes tools, or contains policy logic — every permission
// decision still resolves through the policy engine.
package tui
