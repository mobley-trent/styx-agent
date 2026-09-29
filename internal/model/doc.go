// Package model is the single wire seam of the harness: the ModelClient
// interface, the openai-go client pointed at DeepSeek, and the cache layout.
//
// Boundary rule: ModelClient is the ONLY path from the agent loop to the
// wire. The loop depends on the interface, never on this package's concrete
// client; tests bind fakes and the stub server here.
package model
