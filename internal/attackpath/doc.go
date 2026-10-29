// Package attackpath computes costed attack paths over engagement state
// (docs/attack-paths.md): given the access an engagement already holds and a
// target host or service the model names, it returns the cheapest distinct
// routes, ranked by an integer cost model derived from the stored enums.
//
// The package is pure, behind one entry point — Compute. It holds no store
// handle and performs no IO, no clock reads, and no randomness, so the same
// snapshot always produces byte-identical output. The tool layer loads the
// snapshot and hands it in; the store never depends on this package.
//
// Paths are a projection of the record, never a second record: the capability
// steps are derived on read from the stored edges, and nothing is written,
// cached, or scheduled (ADR-0006).
package attackpath
