# styx — relationship graph & attack-path computation

Decided by [#76 Design the relationship-graph and attack-path computation](https://github.com/mobley-trent/styx-agent/issues/76)
(child of the map [Wayfinder: styx prototype → adoptable red-team agent](https://github.com/mobley-trent/styx-agent/issues/53)),
on top of the roadmap's v1.1 substrate ([`docs/red-team-roadmap.md`](red-team-roadmap.md) §1, item 3),
the engagement-state model decided in [#74](https://github.com/mobley-trent/styx-agent/issues/74)
([`docs/engagement-state.md`](engagement-state.md)), and the parser contracts decided in
[#75](https://github.com/mobley-trent/styx-agent/issues/75)
([`docs/parser-tool-contracts.md`](parser-tool-contracts.md)).
Keystone rationale: [`docs/adr/0006-attack-paths-are-advisory.md`](adr/0006-attack-paths-are-advisory.md).

## 1. Scope

One question: given the engagement state, what is the cheapest route from the access already
held to a target the model names — and how is it surfaced **without ever scheduling it**?

Three things this design does not change: the stored graph (`engagement-state.md` §3–§4) is
untouched; the store stays the single record (ADR-0004); no new persisted structure is added.

## 2. The capability projection

Stored edges are **observations** — who holds a secret, where it came from, which finding
produced which foothold. Their directions are provenance directions, not action directions:
`CREDENTIAL_FROM` runs credential → host ("the secret came from here"), so *obtaining* that
secret means traversing it backwards, and there is no forward `access → credential` edge at
all. A search that follows stored edges as written answers the wrong question.

Paths are therefore searched over a **capability projection**: a pure, derived, directed step
set, recomputed on read from the same record. It is a projection of the record, never a second
record — nothing is written, nothing is cached, nothing can drift.

| Capability step | Derives from | Direction | Meaning |
|---|---|---|---|
| `harvest_credential` | `CREDENTIAL_FROM`, reversed | host \| service \| finding → credential | reach that node → the secret is obtainable |
| `use_credential` | `VALID_FOR` | credential → host \| service | the secret authenticates as a user-level principal |
| `admin_via` | `ADMIN_OF` | credential \| access → host \| service | privileged over the target |
| `pivot` | `PIVOT_TO` | access → host | this foothold reaches that host |
| `exploit` | `EXPLOITED_VIA` | the finding's affected host \| service → access | run the vuln, gain the foothold |

Rules:

- **Attributes, never steps.** `RESOLVES_TO`, `RUNS_ON`, and `IN_SEGMENT` are identification
  and grouping facts. They are used to resolve the target (§4) and label nodes; they are never
  traversed.
- **Excluded.** `refuted` findings never produce an `exploit` step; `active: false` entities
  produce no steps at all — a step is dropped if either endpoint is inactive.
- **The exploit step originates at the finding's `affected` host/service**, not at the finding:
  the vuln can only be run from the vulnerable node.
- **Subsumption.** A credential with `ADMIN_OF` a target yields one `admin_via` step, never
  `use_credential` + `admin_via`; privileged routes must not pay twice and lose to the
  unprivileged ones. Reaching a target at admin level satisfies the goal.

## 3. The cost model

Costs are **integers derived from the enums** — inherited discipline from #74 ("a model cannot
calibrate 0.73"). Never probabilities, never floats.

```
step_cost = base(step) × confidence(this step) × verification(exploit only) × noise(step)
path_cost = Σ step_cost
```

**Base** — `admin_via` 2 · `harvest_credential` 2 · `use_credential` 3 · `pivot` 5 · `exploit` 8.
Ranking intent: a route already holding the credential is cheaper than lateral movement, which
is cheaper than exploitation.

**Confidence** — high ×1 · medium ×3 · low ×9, taken from the **stored edge the step derives
from** — the mapping `engagement-state.md` §4 reserves for this design. The one exception is
`exploit`, which takes the **finding's** confidence: calibrating the vulnerability is what
matters there, not the assertion that it worked.

**Verification** — `exploit` only: `verified` ×1, `unverified` ×3. Unverified findings stay
traversable (suggesting the unverified route is useful, and it is already priced 3× as dear);
`refuted` is not in the graph at all.

**OPSEC noise** — a *static per-mechanism* multiplier: `admin_via` ×1 (a login) ·
`harvest_credential` ×2 (reading files) · `use_credential` ×2 (an authenticated access) ·
`pivot` ×4 · `exploit` ×4 (noisy, detectable). The #74 schema carries no per-instance
detectability field, so OPSEC here is a property of the *mechanism*; per-instance noise needs a
schema change and is not v1.

The gaps between multipliers are deliberately wide: confidence and verification dominate a
route's ranking, so a low-confidence route does not win on rounding.

### Worked example

State: `access-1a2b` holds `host-1111`; `PIVOT_TO` (high) reaches `host-2222` and `host-3333`;
`CREDENTIAL_FROM` (high) `cred-aaaa` ← `host-2222`, a token; `ADMIN_OF` (high) `cred-aaaa` →
`host-4444`; `VALID_FOR` (medium) `cred-bbbb` → `host-4444`; `finding-cccc` (medium, unverified,
affected `host-3333`) —`EXPLOITED_VIA`→ `access-9f9f` on `host-4444`. Target: `host-4444`.

| Path | Steps | Cost |
|---|---|---|
| 1 | pivot 5×1×4 = 20 · harvest 2×1×2 = 4 · admin_via 2×1×1 = 2 | **26** |
| 2 | pivot 20 · harvest 4 · use_credential 3×3×2 = 18 | **42** |
| 3 | pivot 20 · exploit 8×3×3×4 = 288 · admin_via 2 | **310** |

The token route wins; verifying `finding-cccc` drops path 3 to 118 and it still loses. K=3
returns all three, cheapest first.

## 4. Sources, targets, resolution

- **Sources** — every active `access` entity, at cost 0. That *is* "current access": a foothold
  is the only place a route can start. `access.via` is not a source; the foothold is.
- **No footholds** — an engagement with no active `access` returns a structured *no-footholds*
  result, never an invented start and never an empty list.
- **Target** — exactly one required `target` string, naming a **host or service**. Resolution
  order: entity id → address → hostname. **An ambiguous or unmatched target is a hard error**,
  never a guess (the parser tools' "inferred-nothing is an error" discipline).
- **Reaching the target** — a path succeeds when its final node is the resolved target entity.
  Its arrival *level* (from the last step) is reported, never persisted: writing an implied
  `access` entity would make this a state mutation, and it is not one.
- Outcome-shaped goals ("domain admin") need the AD domain/user/group entities #74 deferred;
  they are not in v1.

## 5. The search

Dijkstra for the cheapest route, Yen's algorithm for the **K = 3** cheapest loopless routes
(the roadmap's K). The implementation is held to:

- **Deterministic.** Rank by `(path_cost, step signature)`, where the signature is the ordered
  tuple of `(from id, step kind, to id)`. Identical state produces byte-identical output, which
  is what makes golden tests possible at all.
- **Loopless.** Yen's runs with the loopless guarantee; a route never revisits a node.
- **Bounded, loudly.** Caps: 5,000 nodes · 20,000 steps · 12 steps per path. Exceeding any cap
  truncates or refuses with a message naming the cap — never a hang. v1 engagements are small;
  the caps exist so a pathological graph cannot wedge the harness.
- **Fewer than K paths** — return what exists (1 or 2) with a note. Never pad, never return
  near-duplicate variants of the same route.
- **Unreachable** — a structured negative result, not an empty one: "unreachable from current
  access", plus one bounded diagnostic line built from a **reverse** Dijkstra from the target
  intersected with the forward-reachable set — up to three "closest we got" nodes with the
  missing step named ("`host-2222` is one credential away from `host-4444`"). That is the
  difference between a suggestion and a dead end.
- **Read-only.** The computation writes nothing to the store, ever.

### The result shape

Per path: `total_cost`, the arrival level, a one-line rationale, and the ordered `steps[]`,
each carrying `from`/`to` (id plus human label), `step` (mechanism), `confidence`, `cost`, and
`basis` — the stored edge it derives from, or for `exploit`, the finding id, title, and
verification. Truncation follows ordinary tool-output rules (capture truncation with a
`state_query` pointer).

## 6. The tool: `attack_path_suggest`

One tool, registered always, named as the roadmap and #75 already reserve it.

```json
{
  "type": "object",
  "properties": {
    "target": {
      "type": "string",
      "description": "Entity id, address, or hostname of the host or service to reach."
    }
  },
  "required": ["target"],
  "additionalProperties": false
}
```

- **One required property, no optionals** (strict mode). K is fixed at 3, not a parameter:
  there is nothing for the model to tune, and no optional property may exist at all.
- **Gating identical to `state_*`** — the rule table denies it in safe mode (reason: no
  engagement, so there is no store to read) and *allows + audits* it in engagement mode. It
  carries no scope targets, so §6.1 handles it as a rule-table matter alone.
- **All four subagent presets** receive it, exactly as they receive `state_*`.
- `Destructive: false`, `ExploitClass: false`, `Targets: nil` — pure local computation, no
  network, no scope question.
- **Suggestion, never a step.** The tool returns text. The harness never schedules,
  pre-authorizes, or executes a suggested step; when the model acts on one it does so through
  the ordinary tools, each re-passing the policy gate and the scope checks independently. This
  is the invariant ADR-0006 pins.
- **No digest change.** The state digest stays as #74 defined it (it already carries the access
  count); path content is not pushed into the prompt. The model asks.

## 7. Purity & the package boundary

`internal/attackpath`, a pure package behind one entry point:

```
Compute(snapshot Snapshot, target string, k int) (Result, error)
```

No store handle, no IO, no clock, no randomness, no globals — the tool layer loads the state
snapshot and hands it in, and the store never depends on this package. That is what keeps the
computation testable in isolation and re-derivable after any state change. `Snapshot` is the
same read shape `state_query` serves, so the two consumers land once, coherently (#78).

Held to: golden tests over fixture states; determinism (same snapshot → identical result);
monotonicity (adding a step never increases a path's cost); `cost = Σ step costs`; looplessness;
and the exclusions (`refuted` findings, inactive entities).

## 8. Failure & edge cases

- Unresolvable or ambiguous target → structured error naming the candidates found.
- No active `access` → the no-footholds result.
- Target already held (an `access` entity on it) → a zero-step path, reported as "already have
  access".
- Empty graph, target == source, cap exceeded, unreachable → each a named structured outcome;
  never a panic, never an empty response.
- Every error is an ordinary tool result: audit-logged, non-fatal, never a loop crash.

## 9. Spec touchpoints (applied by the implementation ticket)

- **§5.1** — add `attack_path_suggest` to the built-in tool table.
- **§5.4** — add it to all four preset allowlists.
- **§6.1** — mode defaults: safe = deny, engagement = allow (audit-logged).

The state digest is unchanged, so §4.5 and §10 are untouched.

## 10. Explicitly not in v1

Outcome-shaped goals (AD domain/user/group entities, deferred by #74) · per-instance
detectability/OPSEC fields · level-qualified targets and a `level` parameter · optional
parameters of any kind · a `state_query` op in place of a tool · auto-execution or
pre-authorization of suggested steps · phase auto-advance (v1.2, ADR-0003) · cross-engagement
path reuse (deferred with cross-engagement learning) · path persistence or history · a TUI path
renderer (it prints as an ordinary tool result) · automatic verification of the findings a path
relies on.
