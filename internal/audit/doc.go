// Package audit implements the per-session audit log: the JSONL writer with
// fail-closed semantics.
//
// Boundary rule: audit records every policy verdict verbatim before
// execution; a failed audit write denies the call — fail closed, no
// exceptions.
package audit
