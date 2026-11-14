# A budget cap is measured, never estimated

The `--max-budget` ceiling (`docs/budget-cap.md`) is priced from the configured per-model rate table
at the moment each model turn's usage arrives, checked at the loop's between-turns seam, and enforced
by refusing the next model call. A turn the provider reported no usage for ends a budgeted run rather
than letting it continue unpriced. Three consequences follow from one premise — **a price is never
invented**: there is no local tokenizer, so a pre-call figure would price a request that does not
exist yet; a provider that reports no usage leaves nothing to measure; and a model with no configured
rate has no price to bill. Each of those either invents a number or drops the assurance, so each
fails closed instead of guessing.

## Considered Options

- **A pre-call estimate bounded by `max_tokens`, plus post-call accounting.** The only option that
  promises never to cross the ceiling, and the reason this ADR exists. It needs a token count for an
  unsent request: the previous turn's prompt size plus a guess at new tool results and the response.
  Refusing a call that would have fit stops a run for a number nobody measured, and the estimate is
  precisely the invented price the premise forbids — for a run whose whole purpose is to bound the
  damage of an autonomous agent. Rejected, with the crossing accepted and disclosed instead.
- **Provider-reported cost, where an endpoint offers it.** Authoritative for that endpoint and
  untrustworthy as a general rule: one flag would then mean different things per endpoint, a remote
  party would set the assurance, and ADR-0002's provider breadth would inherit the split. Rejected;
  the configured table stays the only source.
- **Continue on missing usage and print "dollars unknown".** Keeps the run alive and turns the
  ceiling into an advisory: a pipeline would read a green result off a run nobody capped. Rejected.
- **Refuse to enforce for an unpriced model and run unbudgeted, with a warning.** The same advisory
  in a different costume. Rejected: a budgeted run refuses to start (`1`) before the container,
  naming the model and the three rate keys.
- **Store cumulative spend in engagement state.** Would make the ceiling span runs. Rejected on the
  store's own definition: state is observations about the target, written through seven audited ops
  with harness-stamped provenance, and money is bookkeeping about a session. A store that also held a
  ledger would be two records in one file. Per-run only, recorded in the session JSONL.

## Consequences

- **The ceiling can be crossed once per run.** Accounting is post-hoc, so the turn that crosses the
  line completes and the next model call is refused. Overshoot is bounded by a single turn's cost,
  not in general, because a 1M-context turn is not cheap. The graduated warnings exist to make that
  crossing rare, and the spec says so rather than implying a hard edge.
- **The seam also runs before a run's first turn.** The check sits at the top of each turn rather
  than at the end of the previous one, so a run that begins already at the ceiling — a nested run
  dispatched after the root spent it — makes no model call at all. Without that, its first call
  would be exactly the unpriced turn below, a call nobody measured that the ceiling meant to forbid.
- **`--max-budget` cannot run against a provider that omits usage.** The refusal lands at its honest
  point of use: an unpriced turn would make the status bar, the summary, and the ceiling lie at once.
  That turn still answers its tool calls before the run ends — tools cost no model money,
  and every call the model made keeps its result — but no further model call follows
  it. The run ends after the turn, never inside it.
- **The exit-code space is untouched.** A budget stop is a broken run (`1`), so ADR-0009's five codes
  stand, no pipeline learns a sixth number, and precedence already puts broken ahead of a gate
  verdict — the gate is not consulted at all, rather than computed and outranked.
- **Spend never enters an artifact or the store.** The findings export already excludes run metadata;
  the session JSONL carries the spend curve. A cross-run or per-engagement budget, if it ever
  matters, is a Report-level computation over that JSONL, not a new state field.
- **The stopping point is not reproducible across the clock.** `Pricing.Cost` halves off-peak, so the
  same token spend stops the same run at a different dollar figure at a different hour. The ceiling
  tracks the invoice, which is what an operator is capped against; a fixed projection would be a
  second, wrong price to argue with.
