# A severity gate is its own exit code over the export's own set

CI has to tell three outcomes apart — the scan ran and found nothing, the scan ran and found
something over the bar, and the scan did not finish — and styx's exit-code space could only express
two of them. We decided that **the severity gate gets its own code (`3`), a run blocked by denials
gets another (`4`), and `1`/`2` keep the meanings they already had**; that the gate reads the same
set the findings export carries, minus `risk_accepted`; and that the verdict is computed in process
over the same snapshot, so a written artifact and a lost verdict cannot coexist. A broken run always
outranks a verdict: crashing is never reported as "your scan found something".

## Considered Options

- **Fold the gate into `1`, alongside a failed run.** The no-new-codes option, and the one that
  defeats the purpose: a pipeline that gets `1` cannot tell "the target is vulnerable" from "the
  provider went away", and the two demand opposite responses — one fails a build on purpose, the
  other needs someone to look at the harness. Rejected.
- **Renumber usage errors to free `2` for the gate.** The roadmap sketched it that way. Rejected:
  `2` is already documented in `cmd/styx/main.go` and in every operator's shell history, and a usage
  error and a security verdict are not the same kind of event to trade places.
- **A gate that only counts `verified` findings, or weights severity by verification and
  confidence.** The tempting false-positive guard. Rejected because it is a silent downgrade — the
  same move `docs/findings-export.md` §7.4 refuses when it declines to let verification move a
  finding's rank — and here it ends with CI green on the finding nobody looked at. The gate keeps
  severity as the operator's judgement and *discloses* the evidence gap instead of pricing it away.
- **Reorder so a run's own findings are gated.** Friendlier to incremental pipelines, but it needs a
  run timestamp in the artifact, which ADR-0008 keeps out. The gate would read a set no export shows.
  Rejected for the same reason the export has one predicate.
- **Gate over its own exit code, over the export's set, in process (chosen).** Five codes, one
  predicate, one snapshot. `broken > gate failed > not clean > clean`, because a crash outranks a
  verdict and a blocked run outranks a clean one.

## Consequences

- **The exit-code space is now a public interface.** `0` clean, `1` broken, `2` usage, `3` gate
  failed, `4` not clean. A pipeline branches on those numbers, so changing one later supersedes this
  ADR rather than extending it — the same bar ADR-0003 and ADR-0006 set for their own boundaries.
- **A non-zero exit is no longer "the run failed".** `3` and `4` mean the run *succeeded* and its
  result was unwelcome. A CI step that treats any non-zero as an infrastructure failure will mislabel
  two of the five outcomes until it reads the codes.
- **`risk_accepted` is the documented way to keep a real finding out of the build.** It stays in the
  export — a reader is entitled to know the risk exists — and never fails a run. That makes the
  status field load-bearing for CI, so the store's transition rules are now part of the gate's
  contract.
- **Artifact and verdict cannot disagree.** One predicate in `internal/findingsexport`, read by both
  the export and the gate, and one snapshot read by both, so there is no ordering in which a file
  says one thing and the exit code another.
- **A scheduled pipeline stays red until someone acts.** Gating the cumulative store rather than the
  run is the deliberate cost of determinism: the same state yields the same verdict, which is what
  makes a gate reproducible at all.
- **The gate stays advisory in every other sense.** It reports and exits; it never mutates a finding,
  never re-ranks, never suppresses, and never writes a report.
