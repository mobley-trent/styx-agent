// Package memory implements project memory: STYX.md loading and the
// timestamped engagement-notes appender.
//
// Boundary rule: memory reads and appends structured records only; it never
// invents content on the model's behalf and never touches engagement scope
// or policy state.
package memory
