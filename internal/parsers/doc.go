// Package parsers implements the parser-backed tool contracts
// (docs/parser-tool-contracts.md, #75, ADR-0005): the six harness-owned tools
// that turn one scanner's raw output into typed engagement-state writes.
//
// The shape is fixed by the contract:
//
//	artifact bytes → per-format extractor → typed candidate records
//	  → one atomic §6 op batch (upsert_entity | upsert_finding | attach_evidence | add_edge)
//	  → parse receipt
//
// Six formats, one per scanner (Names): nmap XML (`-oX`), nuclei JSON Lines,
// the sqlmap per-target log, gobuster text output, CrackMapExec / NetExec
// per-target output, and legacy BloodHound collector JSON. Each extractor
// recognizes a documented, deliberately narrow pattern set — the exact lines and
// elements listed in each extractor's doc comment — and reports everything else
// as a skipped record with a reason rather than guessing (§7: strict, atomic,
// non-fatal, never-silent).
//
// Three properties are structural rather than conventional:
//
//   - The parser is the only component that maps scanner output onto state ops,
//     and it runs harness-side (ADR-0005): the raw CLI runs in the session
//     container, the artifact round-trips through the shared workspace, and the
//     parser is the trust boundary that turns untrusted bytes into typed state.
//   - The write batch is atomic and harness-stamped. The model supplies only a
//     path; provenance comes from the store, and no parser escalates a finding's
//     status or verification (§5: a parser may set confidence, never verified).
//   - References resolve to the records the parse writes. A batch may name the
//     ids it creates (engagementstate.Store honors a free supplied id), so the
//     edges and evidence that follow the records they describe resolve inside
//     one commit, and a re-detected record is written and referenced under the
//     id the store already holds.
//
// Artifacts live in `.styx/out/` (§3) — a convention the harness prepares and
// watches (see Tracker), never a constraint: a parser accepts any
// workspace-confined path.
package parsers
