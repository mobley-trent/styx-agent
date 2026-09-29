// Package app wires styx-agent startup: config load, engagement gate
// activation, and TUI boot.
//
// Boundary rule: app is composition only. It connects config, engagement,
// policy, agent, model, and tui into a running harness; it owns no logic of
// its own and defines no shared types.
package app
