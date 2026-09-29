# internal/testdata — shared test fixtures

Shared, data-only fixtures for the styx-agent test suite: scrubbed,
versioned transcript fixtures (`transcripts/`), stub-server cases, and
prompt golden snapshots.

**Boundary rule:** this directory is data only — no executable code, ever.
Go tooling ignores `testdata` directories by design, which enforces the
rule mechanically. Model- and policy-facing content (prompt sections,
skill-pack workflow text, fixtures) lives here or in `embed`-ded data
files, never as Go string literals.

See docs/spec.md §2 and §11 for the layout and testing contract.
