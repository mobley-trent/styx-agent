// Package sessions implements session persistence: the append-only session
// JSONL store and resume support.
//
// Boundary rule: sessions is a durable log of what happened — it renders
// nothing and decides nothing; the TUI and agent loop are its consumers.
package sessions
