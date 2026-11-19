// Package diffscope turns a change into a narrowed authorization pool
// (docs/api-spec-targets.md §5, docs/headless-ci.md §11.2–§11.3).
//
// The computation answers one question before the first turn: which targets
// does this diff declare? It reads the changed files a PR touched, keeps the
// ones that are API declarations by extension *and* format key, loads each
// through the same loader `api_spec_load` uses — harness-side, writing no state
// — and intersects the hosts they declare with the engagement's pool. It never
// unions with the pool and never adds a target (ADR-0007).
//
// Three properties are structural:
//
//   - **Declarations, never literals.** A changed file declares only through a
//     format the harness already understands; targets scraped from source are
//     not targets.
//   - **A broken declaration refuses the run.** A changed file that carries a
//     format key but will not load is a refusal naming the file and the parse
//     error, not a silent skip: a run narrowed from a document it could not
//     read has tested nothing or everything while claiming that document's
//     scope. A file that declares nothing contributes nothing instead.
//   - **Operations inform, hosts narrow.** The operations the diff changed on
//     the narrowed hosts reach the run as context that authorizes nothing,
//     because host level is the one granularity the gate, the container edge,
//     and the audit enforce identically.
package diffscope
