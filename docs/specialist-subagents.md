# styx — specialist subagents and parallel orchestration

Decided by [#148 Design specialist subagents and parallel orchestration](https://github.com/mobley-trent/styx-agent/issues/148)
(child of the map [Wayfinder: v1.3 reach & provider designs](https://github.com/mobley-trent/styx-agent/issues/144)),
on roadmap item 11 ([`docs/red-team-roadmap.md`](red-team-roadmap.md) §1).

## 1. Scope

Roadmap item 11 asks for two things: **webapp, identity (AD), post-exploit, and critic presets
with context carry**, and **parallel orchestration at one nesting level**. This document decides
both.

It extends the registry that already exists — a preset is (system prompt, tool allowlist, turn
bound, network class, optional engagement gate), enforced structurally in
`internal/agent/subagent` — rather than adding a surface beside it. The only new harness
behaviour is a concurrency bound, an engagement frame stamped into each run, and cancellation
when the engagement gate transitions. There is no scheduler, no phase object, and no second
nesting level.

Two decisions earn ADRs, because each rewrites a safety posture a future reader would otherwise
question:

- [ADR-0016](adr/0016-delegation-authorizes-nothing.md) — delegation authorizes nothing, so
  engagement mode allows `dispatch_subagent` and safe mode keeps prompting.
- [ADR-0017](adr/0017-a-critic-advises-and-never-records.md) — a critic advises and never
  records.

## 2. The eight presets

Existing four (spec §5.4) are unchanged. Four are new. Two bundle names cover the repeated
columns:

- **`state`** — today's bundle, unchanged: `state_query`, `state_update`, `attack_path_suggest`,
  `exploit_plan_suggest`, the six parser tools, and `api_spec_load` (spec §5.4,
  [`docs/parser-tool-contracts.md`](parser-tool-contracts.md) §9,
  [`docs/api-spec-targets.md`](api-spec-targets.md) §8).
- **`state-read`** — the same bundle without the write path: `state_query`,
  `attack_path_suggest`, `exploit_plan_suggest`. No `state_update`, no parser, no
  `api_spec_load`.

| Preset | Distinctive tools | Network | Gate |
|---|---|---|---|
| `coder` | fs, `bash`, `code_exec` + `state` | none | none |
| `recon` | `web_fetch`, `web_search`, `bash`, fs-read, `browser_*` + `state` | scope | none |
| `exploit-dev` | exec, fs, `web_fetch`, `browser_*`, `proxy_*` + `state` | scope | engagement + `exploit_allowed` |
| `log-triage` | fs-read, `code_exec` + `state` | none | none |
| **`webapp`** | `browser_*`, `proxy_*`, `web_fetch`, `web_search`, `bash`, fs-read + `state` | scope | **engagement** |
| **`identity`** | `bash`, `code_exec`, `read_file`, `write_file`, `glob`, `grep` + `state` | scope | **engagement** |
| **`post-exploit`** | `bash`, `code_exec`, fs incl. `edit_file`, `web_fetch` + `state` | scope | **engagement + `exploit_allowed`** |
| **`critic`** | `state-read`, fs-read | **none** | **engagement** |

Every preset stays at the 40-turn bound (§4.1) and none receives `dispatch_subagent`:
`Preset.Allowlist()` strips it, so one nesting level remains structural rather than a rule the
model could ignore.

**The role gate follows what the role presumes**, which is the rule the existing four already
follow. A role that presumes a foothold (`exploit-dev`, `post-exploit`) needs
`exploit_allowed`; a role that presumes only an engagement (`webapp`, `identity`, `critic`) needs
the engagement and nothing more. This keeps spec §6.3 honest — `exploit_allowed: false` leaves
recon and scanning unaffected — so an engagement that forbids exploitation still gets web testing,
AD enumeration, and a critic. The flag still binds every *call* such a run makes: an exploit-class
call inside `identity` is hard-denied or held exactly as it would be from the main loop.

`browser_*` and `proxy_*` ownership is **not** reopened: design #145 assigned `browser_*` to
`recon` and `exploit-dev` and `proxy_*` to `exploit-dev`
([`docs/browser-and-proxy.md`](browser-and-proxy.md) §6), and that stands. Overlapping
allowlists are already the norm (`state`, parsers, `api_spec_load` are on all four presets), so a
preset's identity is its prompt plus its gate, not a unique tool.

The network class must stay derived from the allowlist, not trusted: the registry's `networkTools`
check gains the `browser_*` and `proxy_*` families and `web_search`, so a preset declared `none`
that carries a reach tool is a registry test failure rather than a quiet hole. `web_search` reaches
a host the engagement does not authorize and is gated per call by `roe.osint_allowed`, not by the
preset ([`docs/web-search-and-osint.md`](web-search-and-osint.md) §10).

### 2.1 `webapp` — the mode-gated HTTP specialist

`webapp` is not a second `exploit-dev`. Two properties make it a role:

1. **It starts under `exploit_allowed: false`.** That is the engagement where authenticated
   crawls, spec-driven endpoint testing, and access-control probing are permitted and exploitation
   is forbidden — precisely the engagement `exploit-dev` refuses to enter.
2. **Its workflow stays inside the application.** Every network action is HTTP(S): browse, capture
   in the proxy, read the app's own declaration, replay with a changed parameter. It runs no
   scanner shell and develops no binary exploit.

Its prompt section: crawl within scope, capture the authenticated session in the proxy, load the
API document where the app publishes one, test the endpoints the load names, and attach the
request/response as evidence. Authentication arrives through **capture then replay** — the proxy
re-sends from its own store and no tool result renders the value — never by reading a credential
out of state, where `state_query` renders every secret as `<redacted>`
(`internal/engagementstate/render.go`).

It carries no `write_file`: the artifacts of this role are `browser_screenshot`,
`browser_download`, and the capture store, and `bash` heredocs remain available under the same
policy anyway. That is a prompt-level posture, stated as one, not a boundary.

### 2.2 `identity` — AD enumeration and the path into the domain

`cme_parse` and `bloodhound_parse` arrive with `state`, so the role's job is to run the
collectors and land their output through the parsers, then read the graph it just built. It keeps
`write_file` because collector output is evidence and lands under `.styx/out/`. It has no
`web_fetch` and no `web_search`: AD work is internal network, and `recon` remains the role with
general web reach.

Under `exploit_allowed: false` it still enumerates — Kerberoasting-class steps are exploit-class
calls, hard-denied per call — which is the behaviour §6.3 already promises.

### 2.3 `post-exploit` — privesc, movement, and documentation

Gated like `exploit-dev` because it presumes a foothold and moves from it. Its prompt covers
privilege escalation, lateral movement to hosts the current access reaches, and **documenting**
persistence rather than establishing it (spec §8.3's red-team pack). It reports `access` entities
and `PIVOT_TO`/`ADMIN_OF` edges as it goes, so the path computation and the report see the same
truth as the run.

### 2.4 `critic`

See §3.

## 3. The critic: read-only and advisory

The critic judges the record. It cannot write it.

**Tools.** `state_query`, `attack_path_suggest`, `exploit_plan_suggest`, `read_file`, `glob`,
`grep`. No `state_update`, no parser, no `api_spec_load`, no exec, no network. In particular it
cannot `set_status`, `set_verification`, or `attach_evidence`.

**What it judges:** whether a finding is real and its severity honest (CVSS qualitative, never a
number — `docs/engagement-state.md` §5); whether its status and verification are supported by the
evidence attached; whether the ranked exploitation plan and the suggested paths reflect what the
record actually makes eligible; and what the record does not answer at all.

**Why read-only** (ADR-0017): judging and recording stay separate acts. A critic that wrote its
own verdict would make its opinion *evidence*, stamped with the critic's provenance, inside the
forensic record an operator later reads as observation — and it would bypass the loop's own
decision about whether it agrees. The critic's value is a second reading, not a second pen. If
the loop agrees, **the loop writes**, and provenance correctly says the main agent did.

**Report shape — the verdict block.** Fixed in the preset's prompt text and never parsed by
anything; the loop reads it and decides:

```
## Verdicts
finding finding-1a2b | recommend severity high → critical | pre-auth on /admin, not post-login | evidence: /admin 200 unauthenticated | confidence: high
finding finding-3c4d | recommend no change | evidence supports the current verdict | confidence: medium

## Clean
- finding-5e6f — no change: verified, evidence attached, severity matches the vector.

## Gaps
- the record cannot say whether finding-7a8b is reachable from the foothold on 10.0.0.9
```

A clean record still produces the block, with `## Verdicts` empty and every judged finding under
`## Clean`, so silence is never mistaken for approval. Confidence uses the record's own enum
(`low`/`medium`/`high`), because that is the vocabulary the path cost model already uses.

The critic is domain-general: the blue team pack names it too (§8.5), since a blue-team analyst
writes the same engagement findings and benefits from the same second opinion. It remains gated on
an active engagement, because `state_query` is denied in safe mode and a critic with no record has
nothing to judge — it refuses with the same message as any engagement-gated role.

## 4. Context carry: the engagement frame

A run receives today's **brief** — the dispatch call's `task` text — and one addition: a
**frozen engagement frame** stamped into the run's system prompt at dispatch, beside the preset's
section. Because a run's system prompt is built once, for that run, the frame is fixed for the
run's life by construction.

```
## Engagement
mode: engagement
engagement: acme-q4-redteam
exploit-class tooling: allowed (prompts in scope)      # or: (auto-approved in scope) | forbidden
time window: open (until 18:00 America/New_York)       # or: closed (until 08:00 …) | unbounded
expiry: 2026-10-15T23:59:59Z                           # or: none
```

**Why posture and not targets.** A specialist needs to know what its actions will cost it —
whether an exploit-class call will be held, whether the window is open, whether the engagement
expires mid-task — because the alternative teacher is the refusal text, which is the worst
possible one. It does not need the authorization list: the orchestrator's brief carries the
target it actually cares about as intent, the pool is the harness's, and the harness — not the
frame — enforces scope on every call. Copying `targets:` would put a second parsed copy of the
authorization in a second context, where nothing reads it but the model.

The frame is rendered by the **same renderer that produces the main prompt's ROE summary**
(spec §7.4), so the two can never disagree about what the operator authorized, and it is advisory
in exactly the same way: it changes what the model attempts, never what is allowed.

**What must never be copied into a run's context** (spec §10.5):

- **Credential secrets.** `state_query` renders `<redacted>`; the proxy replays from its own
  store; the frame carries neither. A specialist authenticates by capture-then-replay.
- **The state digest.** Subagents get none (`docs/engagement-state.md` §8): they read the record
  through `state_query` and report to the parent, which carries the view.
- **The audit trail**, whose params are unredacted by contract.
- **The parent's transcript**, including its tool results. A run starts isolated; that is what
  makes its context affordable and its findings independent.

## 5. Parallel orchestration

### 5.1 The bound: four concurrent runs

`subagent.DefaultMaxConcurrentRuns = 4`, beside the turn bound the package already owns
(`subagent.DefaultMaxTurns`) and the dispatcher's `agent.DefaultMaxParallel`, with a `Runner`
config field to override it. **No new YAML key**: the spec calls the turn bounds
config-overridable and the code's bounds are constants plus options, so this joins them rather
than inventing the missing config surface here.

- A dispatch past the cap **waits** (blocked, first-in first-out), it does not fail: a fan-out
  wider than the cap completes, it just completes in waves.
- A waiter honours context cancellation, so a turn abort while queued returns that abort rather
  than starting a run nobody is waiting for.
- The cap is independent of the 8-call turn cap (§3.3) and of the 40-turn run bound. It bounds
  *runs*, not calls.
- **Four, not eight,** because the fan-out shapes this design names are two to four wide
  (segments, webapp + identity, critic over an exploitation round), and because eight 40-turn
  runs with no dollar ceiling in the tree (`#153` is open) is spend nobody reviewed.

### 5.2 Delegation is the model's act

Fanning out is the model emitting several `dispatch_subagent` calls in one assistant turn. There
is no batch tool and no scheduler; ADR-0006 stays intact — nothing is scheduled, pre-authorized,
or executed by the harness.

The pattern is taught in prompt text, in two places:

- **The red team pack's phase workflow** names the shapes, in the pack data the way every other
  phase instruction lives (`internal/skillpacks/data.go`): enumeration fans one `recon` run per
  segment; `webapp` + `identity` go together when both are in play; `critic` follows an
  exploitation round over the findings it produced.
- **The `dispatch_subagent` description** gains one sentence: independent tasks may be dispatched
  together in one turn.

### 5.3 What the operator sees

- **Live blocks.** Every running run keeps its block (spinner, live preview, 12 transcript lines).
  The live region gains a height clamp: blocks render in start order until the terminal's height
  is spent, then one line — `… 2 more runs (identity, critic)` — and a block takes the next free
  slot as a finished run prints to scrollback. Today the region renders every block with no clamp,
  so four runs already overflow it.
- **The status bar** gains a run counter while any run is live: `runs 3/4`, and `runs 3/4 (1
  queued)` while a dispatch waits on the cap.
- **Prompt cards** keep queuing behind the existing review mutex with role and run attribution,
  and the status counter is what makes the queue legible instead of silent.

### 5.4 Cost

Concurrency is bounded by the cap and by turns, not by dollars: four runs × 40 turns is the
worst case a fan-out can reach. The budget cap ([#153](https://github.com/mobley-trent/styx-agent/issues/153))
will bound cost when it lands, across root and child agents alike (ADR-0010), and this design
depends on none of it — the cap must hold with or without it.

## 6. Gating

### 6.1 Role gates

| Preset | Needs an engagement | Needs `exploit_allowed` |
|---|---|---|
| `coder`, `recon`, `log-triage` | no | no |
| `webapp`, `identity`, `critic` | **yes** | no |
| `exploit-dev`, `post-exploit` | yes | **yes** |

Both refusals are tool-level errors naming the role and the flag, as `Runner.gate` does today,
and `ExploitAllowed` continues to fail closed when no caller reports it.

### 6.2 Delegation's own verdict

`dispatch_subagent` is `prompt` in safe mode and **`allow`, audited, in engagement mode**
(ADR-0016). Delegation authorizes nothing: the run inherits the same policy engine, audit writer,
operator, and container, and every call it makes is judged on its own. It carries no scope
targets, so it is a rule-table matter exactly as `state_*` is.

One consequence is worth stating plainly: **a non-interactive run can now fan out at all.** Before
this change every dispatch met a prompt, and no-operator means denial (ADR-0007), so `-n` could not
delegate even inside an engagement. It still cannot in safe mode, where the prompt remains.

### 6.3 Gate transitions cancel live runs

A run never survives a change to the authorization it was dispatched under. `/mode` back to safe
mode, or `/engagement` onto a different file, tears the gate down and **cancels every live run**:

- The cancellation is a session event, not an audit record — the audit holds the run's calls up to
  that point, each with its own verdict.
- The block prints as **cancelled**, closed with the reason (`engagement deactivated`), and the
  run's pending dispatch returns an error naming the transition.
- The alternative — letting the run finish against the now-safe-mode engine — would spend its
  remaining turns discovering denial after denial while its frame still described an engagement
  that no longer exists.

## 7. Depth: what deepening would require

One nesting level is retained, and nothing here changes that. `Preset.Allowlist()` strips
`dispatch_subagent`, so a subagent cannot delegate even if a preset were mis-declared.

Making depth two real would require, in this order:

1. **A per-depth budget** — the run bound and the concurrency cap are per-run today, so depth two
   needs a bound that accounts for a chain (turns and cost both), or a grandchild can outspend the
   run that spawned it.
2. **Prompt composition instead of replacement** — a role prompt currently *is* the system prompt
   after the shared preamble; a chain needs role sections that compose, inside the prefix the
   provider caches.
3. **Audit attribution naming the chain** — `subagent` is a single role field today; a chain needs
   `parent/child` provenance or the forensic record cannot say which run's grandchild wrote.
4. **A parent link on the session JSONL** so the child-session UX ([#151](https://github.com/mobley-trent/styx-agent/issues/151))
   renders a tree rather than a list, and so the run viewer can nest.
5. **A per-depth concurrency budget** — four per level, or four per chain? Without an answer the
   cap multiplies by depth.
6. **Surfacing that stays legible at depth three** — the live region is a fixed shallow slot;
   nesting blocks inside blocks needs its own rendering decision.

**The trigger for opening it:** a preset whose workflow genuinely needs a specialist it cannot
express in one brief — the concrete case already visible is `post-exploit` needing an `identity`
run of its own to turn a foothold into domain admin. When that is a real workflow rather than a
nicer decomposition, open the effort; until then, one brief and one run.

## 8. Failure and edge cases

- **Unknown role** — unchanged: a tool error listing the eight names, sorted.
- **Gate refusal** — names the role and the flag it needs (`exploit_allowed`, or engaging first).
- **Cap wait + abort** — a queued dispatch returns the context error, so a cancelled turn never
  starts a run.
- **Cancel while a tool call is in flight** — the run's next boundary sees the cancellation; an
  already-dispatched call completes or fails on its own terms and is audited either way.
- **Concurrent writes** — four runs writing state at once contend nothing new: `state_update`
  already serializes through the store's in-process mutex, and the cross-session lockfile is
  unchanged (`docs/engagement-state.md` §1, `internal/engagementstate/store.go`).
- **Critic on a clean record** — an explicit empty `## Verdicts` plus `## Clean` entries; never a
  bare "looks fine".
- **Critic on an entity deactivated mid-run** — it reports the gap; it cannot resurrect the entity
  and does not try.
- **A specialist that cannot finish** — reports blocked, which is a successful run with a blocked
  report, not an error (the shared preamble already asks for exactly that).
- **`webapp` under `exploitation_autonomy: prompt`** — an exploit-class call it makes is held like
  any other; the frame told it so, and the engine decides per call.

## 9. Visibility

- The status bar's run counter (§5.3).
- Subagent blocks, live and committed, with role and run attribution (spec §9.5).
- Audit entries naming the role and run id, as today.
- A cancelled block that says why it is cancelled.

## 10. Explicitly not in v1.3

- A batch tool, a scheduler, a phase object, or a pre-authorizer (ADR-0006).
- Depth two (§7).
- Per-preset turn bounds.
- Operator-defined or model-authored presets — presets stay built-in and pack-agnostic; the plugin
  API is declined and extensibility stays MCP-only.
- Harness-selected presets, or the harness rewriting a brief (auto-selection is the roadmap's
  separate partial-adoption item).
- A critic that writes (ADR-0017).
- A `write_file`-less `webapp` treated as a boundary rather than a posture (§2.1).

## 11. Spec touchpoints (applied by the implementation tickets)

- **§4.1** — the bounds list gains the concurrent-run cap.
- **§4.2** — the engagement frame in a run's prompt; the cap; cancellation on a gate transition.
- **§5.4** — the preset table becomes the eight-preset table of §2, with `state-read` for `critic`.
- **§6.1** — `dispatch_subagent`: safe = prompt, engagement = allow (audited) (ADR-0016).
- **§8.5** — the red team pack names `webapp`, `identity`, `post-exploit`, `critic`; the blue team
  pack names `critic`.
- **§9.1** — the status bar's fields gain the run counter.
- **§9.5** — the live region's height clamp and `… N more runs` line; the cancelled block.
- **§10.1** — the session JSONL gains the cancellation detail beside start/report/error.

## 12. Verification (what the implementation must prove)

- **Registry** — table-driven over all eight: no allowlist contains `dispatch_subagent`; a preset
  declared `none` carries no reach tool (`browser_*` and `proxy_*` included); `critic` carries no
  `state_update`, no parser, no `api_spec_load`, and no network tool; every preset is 40 turns.
- **Gate ladder** — table-driven over eight presets × mode × `exploit_allowed`: `post-exploit` and
  `exploit-dev` refuse without the flag; `webapp`, `identity`, and `critic` run without it; every
  engagement-gated role refuses in safe mode; a nil `ExploitAllowed` fails closed.
- **Frame** — a golden frame per ROE shape; no frame renders a target, a secret, a digest entry, or
  anything from the audit; the frame's posture sentence is byte-identical to the main prompt's.
- **Cap** — eight dispatches in one turn: never more than four running, all eight report, none
  fails, and the queue drains in order; a queued dispatch aborts with the turn.
- **Cancellation** — deactivating mid-run closes the block as cancelled with a reason, errors the
  dispatch, and produces no state write after the transition; the same for `/engagement` onto a
  different file.
- **Delegation verdict** — engagement mode allows and audits a dispatch; safe mode prompts it; a
  non-interactive engagement run dispatches, and a non-interactive safe-mode run does not.
- **Critic** — a clean record yields the empty-`## Verdicts` block; a verdict block round-trips as
  plain text through the dispatch result; the critic cannot write (the tool is absent, not
  refused).
