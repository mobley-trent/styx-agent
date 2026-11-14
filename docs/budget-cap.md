# styx — the USD budget cap

Decided by [#117 Decide the USD budget cap](https://github.com/mobley-trent/styx-agent/issues/117)
(child of the map [Wayfinder: styx prototype → adoptable red-team agent](https://github.com/mobley-trent/styx-agent/issues/53)),
delivering the budget half of the roadmap's operating surface
([`docs/red-team-roadmap.md`](red-team-roadmap.md) §1, item 6).
Companion to [`docs/headless-ci.md`](headless-ci.md), which decides the run itself.
Keystone rationale: [`docs/adr/0010-a-budget-cap-is-measured-never-estimated.md`](adr/0010-a-budget-cap-is-measured-never-estimated.md).
**Implementation:** [#153](https://github.com/mobley-trent/styx-agent/issues/153) — `--max-budget`
shipped as decided here, with the arithmetic in `internal/budget`, the seam in `internal/agent`,
and the flag, startup refusal, and summary line in `cmd/styx` and `internal/app`.

The rest of that CI surface is decided beside this document and is deliberately **not** repeated
here: the run's shape, streams, and end conditions ([#113](https://github.com/mobley-trent/styx-agent/issues/113),
[`docs/headless-ci.md`](headless-ci.md)), the findings export
([#114](https://github.com/mobley-trent/styx-agent/issues/114), [`docs/findings-export.md`](findings-export.md)),
the severity gate and its exit codes ([`docs/headless-ci.md`](headless-ci.md) §8), diff scoping
([#116](https://github.com/mobley-trent/styx-agent/issues/116)), and the sandbox image
([#118](https://github.com/mobley-trent/styx-agent/issues/118),
[`docs/sandbox-image.md`](sandbox-image.md)).

## 1. Scope

One question: **how is a dollar ceiling measured and enforced by a harness that tracks tokens, not
money?** Three boundaries are fixed before any detail:

- **A price is never invented.** Every dollar the cap counts comes from a rate an operator can read
  and review, applied to tokens a provider actually reported.
- **A cap that cannot be measured is not a cap.** Where the money cannot be counted, a budgeted run
  stops; it never continues while claiming a ceiling it is not enforcing.
- **The ceiling is a model-spend ceiling.** It counts model turns — root, subagent, repair,
  compaction — and nothing else. A tool costs wall time, not dollars (the container is already
  running); egress and compute bill elsewhere and are not this flag's business.

## 2. Where the price comes from

styx already prices model turns. `internal/model/price.go` defines a `Pricing` of three **peak**
per-million-token rates — cache-miss input, completion, cache-hit input — and
`Pricing.Cost(u Usage, at time.Time)` prices one turn's usage at the moment it arrived, splitting
prompt tokens on the provider's own cache-hit/miss fields (a provider that reports no split bills
every prompt token as a miss) and halving the total off-peak. `internal/config` already carries the
same three rates per pinned model (`input_per_million`, `output_per_million`,
`cache_hit_per_million`), `config.Defaults()` ships the two DeepSeek models' published peak rates,
and the project overlay wins on conflict (spec §10.3). `internal/app` already folds every usage
event into one running `cost`.

**The configured per-model table is the only price source.** Not a second, hardcoded table; not the
engagement file; not the provider.

- **Not provider-reported.** Neither pinned model returns a cost. Where an OpenAI-compatible endpoint
  does, consuming it would make one flag mean different things per endpoint and let a remote party
  set the assurance — a live problem once ADR-0002's provider breadth lands. The rates stay local
  and reviewable, which is the same posture as the permission overlay.
- **Not the engagement file.** That file authorizes *scope*, never money (spec §6.2, glossary
  "Engagement file"). Putting a rate in it would make a target declaration also a billing decision.
- **Never derived from token counts alone.** Tokens are the quantity; the rate is the price. A
  default rate for an unknown model would be an invented price wearing a plausible number.

### 2.1 Priced and unpriced models

A configured model is **priced** when its entry sets at least one of the three rates. A model with
none is **unpriced**, and a budgeted run **refuses to start (`1`), before the container**, naming the
model and the three keys. A `--max-budget` run against a model styx cannot bill is not a capped run.
Once provider breadth and routing land, the refusal is **reachability-based** — the root model plus
every model `routing:` names — see [`docs/providers-and-routing.md`](providers-and-routing.md) §3.4.

**Consequence, stated plainly:** a genuinely free model — a local endpoint the operator declared
with only a context window — is unpriced too, and so cannot run under `--max-budget`. That is the
right refusal rather than a loss: a model that costs nothing is not what a dollar ceiling is for, and
the alternative is a run that reports `$0.0000` against every cap and never stops. An operator who
wants both can set any positive rate; styx will not decide on their behalf that a missing price means
free.

### 2.2 The price is the invoice's, not an estimate

`Cost` prices at the moment the turn arrived, so the same tokens are worth different dollars at
different hours. The cap therefore tracks what the operator is billed rather than a fixed projection.
The cost of that choice is stated in §4: a cap's stopping point is not reproducible across the clock,
because the price it measures was never fixed either.

## 3. What the ceiling covers

**One accumulator, and every model call in the run lands in it.** `internal/app`'s `recordUsage`
folds each `sessions.KindUsage` event into the session's totals and prices it with the model that
produced it. What reaches that bus:

| Source | Counted | Why |
|---|---|---|
| Root model turn | yes | `Loop.streamTurn` emits one usage event per completed turn |
| Subagent turn | yes | a run inherits the session's loop options, emitter included, so its usage events land on the same bus |
| Repair re-call | yes | a repair is another model turn through the same `streamTurn` |
| Compaction summary turn | yes | `internal/agent/summarize.go` emits its usage on the same bus |
| State-digest append | nothing to count | the digest is harness text, not a model call |
| Tool execution | nothing to count | the ceiling measures model spend (§1) |
| Search-provider query | nothing to count | not a model turn, so not measurable from usage accounting; bounded by `max_results` and the operator's plan instead ([`docs/web-search-and-osint.md`](web-search-and-osint.md) §9) |

**"Across root and child agents" is not an aggregation problem; it is the shape the code already
has.** A subagent is a tool call whose loop shares the session's emitter, so there is no second
wallet to merge — which is exactly why the design does not add one. The one thing that would break
this is a client bypassing the bus; none exists, and none may be added.

## 4. When the check happens

**At the loop's between-turns seam, from accounting alone.** The loop already has exactly one place
where it reasons about the run as a whole before a model call — the turn cap check, compaction, and
the digest append all sit there. The budget check sits beside them: once a completed turn's usage
has been folded, compare the run's accumulated cost against the cap, and refuse the **next** model
call if it is spent.

**Why not a pre-call estimate:** a pre-call check needs a price for a request that has not been
sent. The only number available before the call is the previous turn's reported prompt size, and the
next request is that prompt plus whatever the tools just returned. Any figure derived from it is an
estimate of a request that does not exist yet — and refusing a call that would have fit stops a run
for a number nobody measured. That is the same dishonesty as an invented price, arriving from the
other side.

**Consequence, stated plainly: a turn can cross the cap.** Accounting is post-hoc, so the turn that
carries the run over the line completes, and the run stops before the next one. Overshoot is bounded
by a single turn's cost — which is not small in general, because a 1M-context turn is not cheap. The
design buys a measured ceiling at the price of a soft edge, and §5's warnings exist to keep the edge
rare. Anyone wanting a hard edge should know they are asking for an estimate.

**The crossing turn's tool calls still run.** The loop's invariant is that every call the model made
gets a result (its repair and abandon paths exist to keep it); leaving calls unanswered would
truncate the transcript and hand the model a turn it cannot finish reasoning about. Tool calls cost
no model money, so honouring them does not move the number the cap measures.

**Every loop checks, subagents included.** The check is a loop option, so a subagent's own between-
turns seam refuses its next model call at the same ceiling. A subagent stopped that way returns a
tool error to the root — a delegated run that ran out of money is a failed delegation, not a failed
run — and the root's own next seam then ends the run.

**The check runs before every model call, including a run's first.** Because the seam sits at the
top of each turn rather than at the end of the previous one, a run that begins already at the
ceiling makes no model call at all. Nothing about the rule is new: it is the post-hoc rule read at
the boundary. A subagent dispatched after the root has spent the cap is precisely such a run, and
letting it take one turn would be the unpriced call §6 refuses — a call nobody measured that the
ceiling was meant to forbid.

## 5. Warnings

Two graduated thresholds, announced **once each per run**, in order:

| Level | At | What the model is told |
|---|---|---|
| half | 50% of the cap | half the budget is spent; prefer to narrow the remaining work |
| wrap-up | 80% of the cap | finish the current line of work, record what you have, and return a final answer; further model turns stop at the ceiling |

100% is not a warning — it is the stop (§7).

**The warning reaches the model as a note, not as a prompt change.** The system prompt is the
byte-stable cache prefix (§3.3, ADR-0004); the note is harness-authored text tail-appended at the
between-turns seam, exactly as the state digest is — ordinary persisted, evictable transcript
content. Announced once per level, and re-appended at the next seam when a compaction has evicted it
while the run is still past that threshold: a model that just lost the note also lost the
instruction to wrap up.

**Where warnings surface:**

- **stderr**, in the `styx: ` voice of the harness itself
  ([`docs/headless-ci.md`](headless-ci.md) §6.2):
  `styx: budget 82% used ($0.82 of $1.00)`. A headless run's reader sees the wall approaching.
- **The session JSONL**, as one new event kind (`KindBudget`) carrying spent, cap, and level, because
  nothing renders that is not also persisted (§4.3). The spend curve is then reconstructable after
  the fact.
- **The audit trail is unchanged.** Its rows are tool-call verdicts and provenance; a budget level is
  neither a call nor a verdict. Nothing about the audit's fail-closed contract moves.
- **The state digest is unchanged.** Engagement state is observations about the target (glossary);
  spend is bookkeeping about the run (§9).

## 6. Missing usage fails closed

`model.EventDone.Usage` is **nil** when the provider omits usage, and `streamTurn` then emits no
usage event at all. A turn with no usage is a turn styx cannot price.

**Decision: in a budgeted run, the first completed model turn with no usage ends the run** — exit
`1`, with `! budget cannot be enforced: the provider reported no usage` on stderr.

- The cap would otherwise have a hole exactly where someone else's invoice grows, and a green CI
  result would be read off a run nobody capped.
- **A reported zero is not a missing report.** Usage present with zero completion tokens is priced at
  whatever it says; only an absent payload is unpriced.
- **The run ends after the turn, not inside it.** The unpriced turn's own tool calls still run, for
  §4's reason: every call the model made gets a result, and a tool costs no model money. What the
  turn cannot do is lead to another model call — there is nothing left to measure one against.
- **Considered and rejected:** continuing with "dollars unknown" printed (the cap becomes advisory);
  counting tokens instead (the ceiling is dollars, and the provider supplied neither quantity honestly);
  treating the turn as free (an invented price, §1).
- **Consequence, stated plainly:** `--max-budget` cannot run against a provider that omits usage. That
  is the provider's limitation surfacing at its point of use, like an unserved model under fail-on-
  demand (spec §1). A provider that omits usage would make the status bar and the end summary lie
  about spend as well.

## 7. The outcome and what the run still does

**A budget stop is a broken run: exit `1`.**

- **Not `3`.** The gate reports a scan verdict; running out of money is not one.
- **Not `4`.** Nothing was denied `no-operator`.
- **Not `0`.** The run did not do its work, and a pipeline must be able to see that.
- **No sixth code.** The loop returns a typed `ErrBudgetExhausted` carrying spent and cap, which
  `internal/app` surfaces as the run's error and `cmd/styx` maps through its existing generic error
  path. ADR-0009's five codes stand untouched, and the precedence
  `broken > gate failed > not clean > clean` already puts a budget stop where it belongs.
- **The gate is not consulted.** It renders a verdict for a turn that returned
  ([`docs/headless-ci.md`](headless-ci.md) §8.5); here the turn did not finish, so no
  `! gate failed` line accompanies the `1`. Broken's precedence is enforced by not asking, not by
  computing a verdict and outranking it.
- **The findings export is still written** when `--out` was given. §5 of
  [`docs/findings-export.md`](findings-export.md) writes on every exit path that has a loaded store,
  and a scan that ran out of money still observed what it observed. The export states no verdict, so
  there is no contradiction with the exit code.
- **Teardown is normal.** The state lock is released, the engagement-notes block is appended, the
  session is closed — a budget stop ends the run, it does not kill the process (the same distinction
  the signal path makes).

stderr, at the stop:

```
styx: budget cap $0.0500
> bash nmap -sV 10.0.0.33
  ...
styx: budget 82% used ($0.0410 of $0.0500)
! budget exhausted: $0.0518 of $0.0500 after 9 model turns
styx: done — 9 turns
styx: usage 41,203 tokens · $0.0518 of $0.0500
styx: denied 0 prompts
styx: session 7f2a19c4 (audit styx-audit-20261030T101500Z.jsonl)
```

- **The cap is announced before the run** — one `styx: ` line after the identity line. A run that will
  stop early says so before it starts, the same reason diff scoping makes its narrowing legible.
- **The summary's usage line names the cap when one was asked for** (`$0.0518 of $0.0500`) and stays
  one line: the four-line summary does not become five.
- **The stop line is `! ` class** — the run is over and something failed — and carries the observed
  overshoot, so the soft edge is visible rather than inferred.

## 8. The flag

**`--max-budget <usd>`**, a CI-shaped flag in [`docs/headless-ci.md`](headless-ci.md) §2.2's sense:
given **without `-n`, it is a usage error (`2`)**, never silently ignored.

- **Value: a positive plain-decimal USD amount, at most four fractional digits** (`2.50`, `0.0025`).
  Empty, `0`, negative, non-numeric, scientific notation, and more than four decimals are usage
  errors (`2`). `0` is refused rather than treated as "no budget": a zero ceiling is a run that may
  not make a single model call, which is not a run.
- **Four decimals** because a cent is too coarse for a small run — one turn can cost `$0.004` — and
  beyond four decimals you are expressing fractions no usage report can measure.
- **The cap is per run, not per turn**, and is fixed for the run: there is no `/budget` command to
  move it mid-run, headless having no command surface at all.
- **Why headless-only, not interactive too.** An interactive operator has the status bar's live
  `cost $` readout and can stop at any moment; the cap exists because CI has nobody watching. An
  interactive cap would also need a stop-or-continue answer for a human who is already at the
  keyboard, which duplicates `-n`'s no-operator rule for someone who can simply interrupt. If an
  interactive `/budget` ever earns its keep, it is a statement of intent before a turn, not this
  admission-control flag.
- **`--max-budget` composes with the rest of the CI surface and changes none of it**: `-n`, `--out`,
  and `--fail-on` keep their meanings; the budget is the wallet, the gate is the build verdict, the
  export is the record.

## 9. Persistence: per run, never in engagement state

**Spend is recorded per run and nowhere else.**

- **Not engagement state.** The store is observations about the target — hosts, services, findings,
  credentials, access, segments (glossary "Engagement state"), written only through seven audited
  typed ops with harness-stamped provenance. None of them is "record money", and adding one would
  need a schema version, a new op, and an audit surface for a fact no other consumer derives from.
  A store that also held a ledger would be two records in one file.
- **Not any export.** The findings export deliberately carries no run metadata —
  [`docs/findings-export.md`](findings-export.md) §3.3 and §4 exclude clock, duration, exit code,
  turn count and token spend, so the artifact stays deterministic. Spend would break that for a
  number CI does not act on.
- **Where it lives:** the session JSONL's usage events and budget events, the stderr summary, and the
  TUI status bar (`/status`). The forensic record and the operator's readouts, exactly as tokens
  already do.

**Consequence, stated plainly: `--max-budget` caps one run, never an engagement.** Two CI runs against
the same engagement each get the full ceiling. A weekly or per-engagement spend budget is *not* this
flag; if it is ever wanted it is a **Report**-level computation over session and audit JSONL (v1.3),
never a field in the store — because the store is not a ledger.

## 10. What it does not do

- **No token cap.** `--max-tokens` is a different quantity, and a per-request `max_tokens` is the
  provider's dial, not a run ceiling.
- **No pre-call refusal on an estimate** (§4), and therefore no promise that the cap is never crossed.
- **No provider-reported cost ingestion** (§2).
- **No per-agent, per-turn, per-target, or per-tool split.** One number for the run.
- **No time cap and no tool-call cap.** Wall-clock and tool spend bill elsewhere.
- **No pause, no resume-at-the-ceiling.** A stopped run is over; an engagement continues in a new run
  with a fresh cap (the session id is printed, so `/resume` can pick the work up interactively).
- **No gating, mutation, or reporting.** It never writes a finding, never fails a build for a
  finding, never renders a report.
- **No budget-aware model routing.** Dropping to a cheaper model as the cap nears is ADR-0002
  territory and would make the run's own spend a routing input; not here.

## 11. Touchpoints (applied by the implementation ticket)

- **`cmd/styx/main.go`** — parse `--max-budget` (positive plain decimal, ≤4 dp, `2` otherwise and
  without `-n`); document it in `usage` beside the other CI-shaped flags.
- **`internal/budget`** (new, pure) — the cap arithmetic: a spend/cap pair, the graduated level
  (none / half / wrap-up / exhausted), and the 4-dp formatting the stderr lines use. No clock, no
  store, no I/O, so the thresholds are testable in isolation.
- **`internal/model`** — unchanged. `Pricing.Cost` already prices a turn; the cap never re-prices or
  estimates.
- **`internal/config`** — a priced predicate on `Model` (at least one of the three rates set), so
  §2.1's refusal reads the same definition the pricer uses.
- **`internal/agent`** — a loop option installing the spend reader; the between-turns seam checks it
  before the next model call, emits the budget event and the note (§5), and returns
  `ErrBudgetExhausted`. `streamTurn` records an unpriced turn when a budget is installed and
  `ev.Usage` is nil, so §6 can fail closed.
- **`internal/sessions`** — one new event kind (`KindBudget`) carrying spent, cap, and level.
- **`internal/app`** — supply the reader from the existing accumulator, refuse at startup when the
  selected model is unpriced (before the container), announce the cap after the identity line, map
  the loop's typed failure to the run's error, and extend the summary's usage line. The export and
  the gate paths are untouched.
- **`docs/headless-ci.md`** §6.3 — the summary's usage line names the cap when one was set; one
  pointer, not a second definition.

## 12. Explicitly not in v1.2

An interactive `--max-budget` (or a `/budget` intent statement) · per-engagement or cross-run
cumulative spend · provider-reported cost · pre-call estimates and a hard-edged ceiling · token caps ·
per-agent, per-turn, or per-target budget splits · a spend field in engagement state or any export ·
budget-aware model routing or provider fallback · org/team quotas, alerting, webhooks, and billing
dashboards.
