# A findings export renders state, never the run

A CI reader wants two things that pull in opposite directions: records it can trust to describe the
engagement, and a log that describes *this run*. We decided that styx's findings export
(`vulnerabilities.json`, `vulnerabilities.csv`, `findings.sarif`) is **a rendering of engagement
state and nothing else**: identical state produces byte-identical artifacts, so a diff between two
exports means the security posture changed. Everything that belongs to the run — its clock, its
duration, its exit code, its turn count — is excluded, and stays where it already lives: the stderr
summary and the audit trail. This is ADR-0004's "the record lives outside the conversation"
discipline reaching a file: the store is the record, and an export is a view of it, taken at one
moment and never a second source of truth.

## Considered Options

- **A run-faithful export (generated-at timestamp, duration, exit code, invocation block).** The
  conventional scanner shape, and the one GitHub's SARIF tooling is built around. Rejected on two
  counts. Every field it adds makes the artifact differ between two runs over unchanged state, which
  destroys the only thing a CI diff can tell you; and the most tempting one cannot be filled
  honestly — the severity gate decides the exit code *after* the export is written, so a `--fail-on`
  verdict would have to be predicted or back-patched into the file.
- **Both: state-only records plus a separate run manifest.** Clean in principle, and rejected as two
  artifacts where one was asked for: a second file to name, write, upload, and keep in step, whose
  only content is facts already printed on stderr and persisted in the audit JSONL. The run's story
  is not lost by omitting it; it is already told.
- **GitHub-optimal SARIF: `security-severity` per rule, `primaryLocationLineHash` fingerprints,
  `invocations[].executionSuccessful`.** This buys better alert display and worse truth. Severity is
  per finding and `security-severity` is per rule, so a rule serving a `high` and a `medium` finding
  must publish a number that is wrong for one of them; the line hash needs a source line a host
  finding does not have; and `executionSuccessful` means "the tool ran", not "the scan found
  nothing". Rejected — the SARIF is offered, not contorted.
- **Render state only, and say so (chosen).** One deterministic artifact per format, the real
  structure in `properties`, exact fingerprints from the store's own natural key, and the
  consequences of dropping GitHub-specific affordances written down where a reader will meet them
  ([`docs/findings-export.md`](../findings-export.md) §4, §7).

## Consequences

- **Byte-identical exports are testable**, and become a golden-file test rather than an aspiration:
  same snapshot in, same bytes out, in all three formats.
- **The export can be written as early as the moment the run stops producing state** — before the
  gate, before the exit status — because it never needs to know either. Nothing about the write
  ordering can leak a verdict into a file.
- **CI consumers must key dedupe on styx's fingerprint** (`styxFindingV1`, derived from the store's
  natural key) rather than on GitHub's `primaryLocationLineHash`. A consumer that ignores it will see
  a host finding as new on every run; that is a documented cost, not a surprise.
- **GitHub code scanning may not display host findings at all**, since their locations are not
  repository files. The JSON export is the primary machine record; SARIF serves consumers that
  accept non-file results.
- **A timestamp a reader wants will be asked for again.** It is available in the audit JSONL and the
  stderr summary, and adding one to the export would supersede this ADR rather than extend it — the
  same bar ADR-0006 sets for making advisory paths actionable.
