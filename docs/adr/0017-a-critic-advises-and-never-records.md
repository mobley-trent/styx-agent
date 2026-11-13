# A critic advises and never records

v1.3 adopts a `critic` preset (`docs/specialist-subagents.md`, #148): a specialist whose job is to
judge the engagement record — is this finding real, is its severity honest, are its status and
verification supported by the evidence attached, does the ranked plan reflect what the record makes
eligible. Engagement state already accepts subagent writes, with subagent provenance stamped on
every mutation, so the critic *could* fix what it condemns.

It does not. **The critic's allowlist is `state_query`, `attack_path_suggest`,
`exploit_plan_suggest`, and fs-read. It has no `state_update` at all — absent, not refused — and its
verdict returns as text the main loop reads and acts on.**

The reason is what a state mutation *means*. `docs/engagement-state.md` §2 makes the store an
observation record, and §5 makes verification depend on evidence with harness-stamped provenance.
A critic that called `set_status` or `set_verification` would be writing its own opinion into that
record as if it were an observation, stamped with the critic's provenance — and a later reader
(auditor, operator, report, exploit planner) would have no way to tell a defect the critic
*concluded* from a defect a tool *observed*. It would also collapse two decisions into one: whether
the finding is wrong, and whether the operator's record should change. Those are different, and the
second belongs to the agent that owns the run.

The advisory shape is also the one this project already chose for computed judgement: attack paths
and the ranked exploitation plan are suggestions the harness never schedules (ADR-0006), and a
critic is the same species — a second reading that informs the loop's next move without becoming
one.

## Considered Options

- **Read and write findings (severity, status, verification).** Fewer round trips, a record
  corrected in place, and one fewer hand-off. Rejected: it makes judgement become evidence with
  nobody in between, and it lets a run whose brief was "judge this" also be the run that rewrites
  what it judged — self-review with the forensic record as the medium.
- **Read-only, but handed a harness-rendered digest instead of querying.**
  `docs/engagement-state.md` §8 deliberately denies subagents the digest (they query and report),
  so this would add a second digest renderer for one role. Rejected: it also fixes what the critic
  may look at to whatever the orchestrator chose, which is the opposite of a second opinion.
- **A strict JSON verdict the harness validates.** Machine-checkable, but the verdict is a tool
  *result*, not a tool call, so strict mode never applies to it; the harness would be validating a
  subagent's prose for no enforcement benefit. Rejected in the design (§3, §10).
- **No critic at all.** The findings export, the report, and `exploit_plan_suggest` already render
  the record. Rejected by roadmap item 11, and by the real gap: nothing in the harness rereads a
  finding's severity against its evidence.

## Consequences

- **The loop writes, and provenance is right.** If the orchestrator agrees with a verdict, the main
  agent calls `state_update`; the finding's provenance says the main loop did it, which is true.
- **The verdict block is fixed text, unparsed** — a per-finding line with a recommended change, a
  reason, the evidence that settles it, and a confidence from the record's own enum; plus `## Clean`
  and `## Gaps` sections so an empty critique is explicit rather than silent.
- **A critic cannot resolve anything by itself**, including marking a finding `false_positive` — the
  smallest, most tempting edit is also the one the invariant most needs kept.
- **The role stays domain-general.** The blue team pack names it beside the red team pack, because
  both write the same engagement findings; it is still gated on an active engagement, since there is
  nothing to judge in safe mode.
- **Anything that gives the critic a pen** — even a narrow `set_verification` — supersedes this ADR,
  and would have to say how a reader distinguishes a critic's conclusion from an observation.
