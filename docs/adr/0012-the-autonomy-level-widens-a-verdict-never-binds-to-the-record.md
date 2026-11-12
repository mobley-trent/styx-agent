# The autonomy level widens a verdict, never binds to the record

[ADR-0003](0003-autonomous-exploitation-boundary.md) asserted an operator-set "exploitation
autonomy level" that widens in-scope exploit approval and refused full autonomy. Implemented
against, that sentence had no lever: the policy engine already auto-allows every in-scope,
non-destructive call in engagement mode (`ReasonInScope`), so an exploit-class call carrying
targets was already prompt-free, and the only direction left to widen was the full autonomy the
same ADR refuses. Read the other way, the level could only be a *record* filter — approve an
exploit because a finding is in the plan, or because it is verified — which makes engagement
state, which the model partly writes, a thing that widens what runs.

We therefore make the level a **policy dial over a verdict**, and re-baseline exploitation
approval onto it: `exploit_allowed` stays the master gate, and `roe.exploitation_autonomy`
(`prompt`, the default, or `auto`) decides whether an in-scope, non-destructive, in-window
exploit-class call is approved or asks first. The level never reads the record, never names a
finding, and never reaches the cost model, so the ranked exploitation plan is identical at both
levels and ranking stays autonomy-blind.

## Considered Options

- **Record-scoped widen.** `auto` approves only exploits of findings that appear in the ranked
  plan, or only verified ones. Rejected: ADR-0006 already refused a pre-authorization driven by
  state for exactly this reason — the model writes the record, so it would be choosing what runs.
- **Full autonomy.** Engagement mode alone approves exploitation. Refused by ADR-0003 and the
  roadmap, and it deletes the safety boundary that is styx's reason to exist.
- **Level filters the plan, not the verdict.** Cheapest, and it leaves the engine untouched.
  Rejected: a `prompt` engagement may still exploit (it asks), so hiding those candidates would
  have the harness second-guess an operator who is allowed to say yes — and it makes the level
  decorative, which is the defect being fixed.
- **Level widens destructive in-scope exploitation.** Rejected: ADR-0003 keeps destructive actions
  prompting, and detonation is always an explicit operator decision (spec §8.3).
- **A new schema version.** Rejected: this is one optional key whose absent value is the
  restrictive one, so it neither fails open nor needs a migration that invalidates every
  committed engagement file.

## Consequences

- Existing engagement files that say `exploit_allowed: true` will now **prompt** for exploit-class
  calls until they also set `exploitation_autonomy: auto`. This is a real behavior change and one
  new verdict reason (`ReasonExploitApproval`), not a new verdict.
- Exploitation approval becomes a conscious, version-controlled operator act, and the level is
  visible where it matters: the prompt's ROE summary (goldens change) and the status bar.
- A non-interactive run can exploit **only** through the level, because every prompt is a
  `no-operator` denial (ADR-0007). The level is thus the single pre-authorization door for
  headless exploitation, and the run's identity line and audit entries name it.
- `auto` is audited per call like any in-scope action, so the widen is legible after the fact
  even though it is not promptable.
- Anything that wants the level to follow the record, or to become autonomous, has to supersede
  this ADR and ADR-0006 — not route around them with a flag.
