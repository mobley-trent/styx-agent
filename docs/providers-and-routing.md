# styx — providers and model routing

Decided by [#152 Design provider breadth and per-agent model routing](https://github.com/mobley-trent/styx-agent/issues/152)
(child of the map [Wayfinder: v1.3 reach & provider designs](https://github.com/mobley-trent/styx-agent/issues/144)),
delivering [`docs/red-team-roadmap.md`](red-team-roadmap.md) §1 item 15 and superseding spec §3.1's
DeepSeek-only posture per [ADR-0002](adr/0002-provider-breadth-and-per-agent-routing.md).
Keystone rationale:
[`docs/adr/0022-a-provider-declares-its-endpoint-and-capabilities.md`](adr/0022-a-provider-declares-its-endpoint-and-capabilities.md)
— why a provider is a declaration with declared capabilities, and why a route is never a fallback.

This document decides **three nouns and their consequences: what a provider is, what a model is, and
what a route is**. It does not decide the budget arithmetic
([`docs/budget-cap.md`](budget-cap.md)), the agent loop (spec §4), preset composition and
orchestration ([`docs/specialist-subagents.md`](specialist-subagents.md)), or the wire behaviour of a
single turn (spec §3.3, unchanged).

## 1. Scope

Item 15 asks for "general OpenAI-compatible endpoints, a per-agent model override, and a small model
for title/summary work; DeepSeek stays the default". §2–§4 answer the three nouns in that order; §5–§8
are their consequences; §9 what the implementation must prove; §10 where it touches the tree; §11 what
it deliberately leaves out.

Four boundaries are fixed before the details:

- **Breadth is configuration, not a second protocol.** One OpenAI-compatible client, N declarations
  (ADR-0002). No vendor SDKs, no second wire format, no per-provider code path beyond what §2.3 and §6
  name.
- **A declaration is trusted for how to talk, never for what may run.** Capabilities change
  serialization and nothing else: the policy engine, the engagement scope, ROE, the severity gate and
  the audit trail bind identically on every route. A second provider is not a second authority.
- **A capability is declared, never discovered.** A session's wire behaviour never depends on a probe,
  a base-URL table, or a vendor's advertisement.
- **The model never enters the prompt.** §3.3's byte-stable prefix stays byte-stable; routing a role,
  or `/model` swapping the root, never rewrites a byte the provider caches on.

## 2. The provider

### 2.1 The declaration

A provider is an endpoint object. `models:` entries reference it, `routing:` names models, and the
status bar names providers when they degrade.

```yaml
providers:
  - name: deepseek
    base_url: https://api.deepseek.com
    api_key_env: DEEPSEEK_API_KEY
    capabilities: {strict_tools: true, reasoning: true}
    billing: peak_halved
    strict_path: beta
  - name: local
    base_url: http://127.0.0.1:11434/v1
    api_key_env: ""

models:
  - id: deepseek-flash
    provider: deepseek
    context_window: 1000000
    input_per_million: 0.30
    output_per_million: 1.20
    cache_hit_per_million: 0.006
  - id: qwen-local
    provider: local
    wire_model: qwen3-coder:30b
    context_window: 262144
```

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Unique within the config. Names the provider in errors, `/status`, and the status bar. |
| `base_url` | yes | The OpenAI-compatible base. Trailing slash trimmed; a path (`…/v1`) is preserved as written. |
| `api_key_env` | no | The **name** of an environment variable holding the credential (§2.2). Empty means no credential. |
| `capabilities` | no | The closed capability set (§2.3). Absent keys mean the less capable behaviour. |
| `billing` | no | `peak_halved` or `flat` (§3.3). Default `flat`. |
| `strict_path` | no | Path segment appended to `base_url` for strict-tool requests (§6). Default empty. |

**`providers:` replaces wholesale on overlay**, exactly like `permissions` and `mcp`: the block is a
complete declaration, not an append. The cost, stated plainly: an operator who adds a second provider
restates DeepSeek's entry if DeepSeek stays. The alternative — merge by name — would make "which layer
declared this endpoint and this rate" ambiguous, which is the ambiguity `models:` already refuses.

A model that names no `provider:` names `deepseek`, which is how every existing config keeps parsing
unchanged. A config that replaces `providers:` without a `deepseek` entry and leaves a model
unannotated is refused at startup, naming the model and the missing provider — never a silent
assignment to whichever provider happens to be first.

Duplicate names, a missing `base_url`, and an unknown capability key are all config errors. Unknown
*top-level* config keys stay tolerated (spec §10.3's same-major contract), but `capabilities` is a
closed enum by decision: a typo like `strict_tool` would silently downgrade every turn's
serialization, which is the same failure the MCP validation refuses when a server quietly fails to
launch.

### 2.2 The credential

- **`api_key_env` names a variable; styx never reads a key from config** (spec §10.5). The value is not
  logged, not persisted, and never enters model context.
- **Empty means no credential**, and that is a declaration, not a fallback: styx does not go looking in
  a vendor-default variable for a provider that did not name one. A misconfigured provider fails on
  demand with its own name rather than borrowing another provider's key.
- **`STYX_BASE_URL` survives as a testing shim**, overriding the built-in DeepSeek provider's base URL
  only. It is subject to §2.4's scheme rule at resolution, so it cannot be used to smuggle a remote
  cleartext endpoint past config validation.

### 2.3 Capabilities, declared and closed

Two, both absent-by-default:

| Capability | Declared | Without it |
|---|---|---|
| `strict_tools` | schema-enforced tool arguments on the wire | `strict` is stripped from every descriptor; the repair layer is the only argument validation (§6) |
| `reasoning` | the provider streams a separate reasoning channel (`reasoning_content`) | no reasoning deltas are produced or parsed |

**Tool calling is not a capability.** A provider that cannot call tools cannot run the harness at all;
declaring it would be a config that starts and then fails every turn. There is no `tools:` key.

**Considered and rejected:**

- **Discovering capabilities at first use.** Most OpenAI-compatible endpoints advertise nothing, so
  "discovery" means "try and infer", and inference makes a session's wire behaviour depend on a network
  round trip that can change underneath a run.
- **A compiled-in base-URL vendor table.** It is an invented fact about endpoints styx has never seen,
  and it silently mislabels every self-hosted deployment of a listed vendor's software.
- **A per-model capability override.** A capability is a property of the endpoint's implementation, not
  of a model ID. A provider that genuinely serves two styles is declared twice, under two names, and
  the model entries say which endpoint each belongs to.

Declaring the asymmetry is the point: ADR-0002 already accepted that a non-DeepSeek provider loses
schema-enforced tool calls. §6 makes that admission visible rather than implied.

### 2.4 The endpoint's scheme

**`https` is required; `http` is allowed only when the host is a loopback or private literal** —
`127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`. Anything else is a
config error at startup, naming the URL.

- **The check is textual.** A hostname must be `https`, because styx does not resolve names during
  config validation and will not acquire a DNS dependency to decide whether a name points somewhere
  private. An operator running their own resolver for a LAN endpoint uses `https` or an address literal.
- **Why refuse at all:** a mistyped remote endpoint would otherwise put the provider's credential on
  the wire in cleartext with nothing said, and the single most common breadth case — a local model
  server — is exactly what the private-literal allowance covers.
- **Fatal at startup**, consistent with spec §1: invalid config is not a fail-on-demand case.

## 3. The model

### 3.1 Identity and the wire string

- **`id` is styx's identity key.** Unique across the whole model set; what `/model` types, what
  `routing:` names, what `ev.Model` stamps, and what prices a turn (`recordUsage` looks it up). Global
  uniqueness is what makes a route unambiguous once models come from several endpoints.
- **`wire_model` is optional and defaults to `id`**: the string sent to the provider. Identity and wire
  reality diverge in both directions — two endpoints may both serve `llama-3.3-70b`, and one config
  cannot hold two entries with one key; a local endpoint may want `qwen3-coder:30b` on the wire and a
  readable `qwen-local` in the picker. Identity stays styx's; the wire gets what the provider expects.
- **`/status` shows `id` and the provider, never the wire string**: what an operator types is what they
  should see.

### 3.2 The window

`context_window` stays required and positive. It bounds two things and no others: the compaction
trigger (§4.5) and — for a routed model — that run's own compactor.

### 3.3 The price, and the billing clock

**The rates remain the configured per-model table's**, exactly as
[`docs/budget-cap.md`](budget-cap.md) §2 fixed: not provider-reported, not from the engagement file,
never derived from tokens alone. Breadth does not reopen where a price comes from. It does reopen
*when* the price applies.

`Pricing.Cost` applies DeepSeek's billing calendar to every model today: `IsPeak` hardcodes weekday UTC
windows and everything off-peak bills at half. A flat-rate provider priced `$3 / $15` would therefore
bill at `$1.50 / $7.50` at noon UTC — a 2× error in the one number a ceiling is measured against.

**The billing clock is declared per provider:** `billing: peak_halved | flat`, default `flat`.
`peak_halved` applies the published weekday windows and halves off-peak; `flat` charges the stated
rates at any hour.

- **The default fails safe.** A provider whose true off-peak price is half is over-counted under
  `flat`, so a `--max-budget` run stops early; under-counting is the failure that makes a ceiling a lie.
- **The built-in DeepSeek provider declares `peak_halved` explicitly**, so a fresh install bills
  exactly as it does today — and an operator restating DeepSeek copies the key, which is §2.1's
  wholesale rule applied once more.
- **Considered and rejected:** deriving the clock from the base URL (an invented fact again); per-model
  peak windows (a billing calendar belongs to the account, not to a model ID); arbitrary window lists
  (a small calendar parser for a benefit no provider has asked for).

### 3.4 Priced, unpriced, and what a budgeted run refuses

A model is **priced** when its entry sets at least one of the three rates, unchanged from
[`docs/budget-cap.md`](budget-cap.md) §2.1.

**The startup refusal is reachability-based.** A `--max-budget` run refuses to start (exit `1`, before
the container) when **any model it can reach** is unpriced, naming every one of them and their three
keys in a single message: the root model, and every model `routing:` names.

- **Why only those:** `/model` is unreachable in a headless run — a non-interactive run has no command
  surface at all — so the rest of the model set cannot bill this run. Refusing a model the run cannot
  use would be a startup refusal over a number nobody measured, which is the shape
  [`docs/budget-cap.md`](budget-cap.md) §1 rejects.
- **A routed turn that is priced lands in the same accumulator**, because `recordUsage` prices by the
  event's own `Model`. Routing creates no second wallet; it is the same shape budget-cap §3 already
  describes for subagents.
- **An interactive run may route to an unpriced model**, and then the cost readout says `cost —` rather
  than `$0.0000`: no rate was supplied, so a zero would be a claim that the turns were free. The
  distinction is the same one §6 of budget-cap makes between a reported zero and a missing report.

## 4. The route

### 4.1 The map

```yaml
model: deepseek-flash        # the root's model
routing:
  summarizer: qwen-local     # compaction's summarizer
  recon: deepseek-flash      # the recon preset
  critic: deepseek-v4-pro    # a preset that ships later
```

- **Keys:** `summarizer`, plus the name of each built-in preset. **Values:** a model ID from the
  configured set.
- **Absent means the root's model.** A fresh install routes nothing and behaves exactly as it does
  today; a role becomes different only when an operator says so.
- **The root has no `routing:` key.** `model:` is its declaration and `/model` its session override;
  a `root:` entry would be a second way to say the same thing with a different precedence.
- **No `/route` command.** A per-session route change would let two runs of one role use different
  models in one transcript while the config and `/status` said otherwise, and `/model` already covers
  the case an operator has in front of them.
- **Routing is config, not session state.** A resumed session re-reads it; `ev.Model` keeps the
  attribution each past turn actually had, and nothing is repriced retroactively.

### 4.2 A route is never a fallback

- **A routed provider that is unreachable or uncredentialed fails that agent's first turn**, with the
  provider and model named, and the run continues (§5, spec §1 fail on demand).
- **No substitution — not to the root's model, not to another provider, not to a cheaper one.** A
  silent substitute makes the transcript's account of which model produced which evidence a lie, and
  attribution is the record's job (§7).
- **A failed delegation is not a failed run**: a run that routes `critic` to a provider that is down
  returns a tool error to the root, the same shape [`docs/budget-cap.md`](budget-cap.md) §4 gives a
  subagent that runs out of money.
- **Budget-aware routing and provider fallback stay out** (§11): dropping to a cheaper model as the cap
  nears makes the run's own spend a routing input, which budget-cap §10 already refused.

### 4.3 Unknown roles are refused

`routing:` naming a role the harness does not ship is **a config error at startup**, listing the roles
that exist.

- A typo'd key would otherwise route nothing, silently — a cost surprise with no signal. That is the
  precedent §2.1 borrows from MCP validation, and the reason `docs/mcp-remote-and-oauth.md` refuses
  `sse` by name rather than ignoring it.
- When `webapp`, `identity`, `critic` and `post-exploit` ship
  ([`docs/specialist-subagents.md`](specialist-subagents.md)), their names become valid keys. Until
  then a config that names one is refused by name rather than accepted into a no-op — honest at the
  cost of one config edit when the presets land.

### 4.4 Titles are not in this design

Item 15 says "a small model for title/summary work". **There is no title generation in the tree**: no
session title is generated, stored, or displayed. Summary work exists — compaction — and is routed
here, including the small-window consequence in §4.5.

When titles exist, they take a `titles` key in the same map, or reuse `summarizer` if the design that
adds them decides they are one job. Deciding that now would decide a feature nobody has specified.

### 4.5 Windows, when agents resolve different models

The compactor is stateless and, today, **shared** — built from the root's `context_window` and handed
to the main and subagent loops alike, with a summarizer request that carries the whole segment and no
size of its own. That is correct only while every agent resolves one model. Under routing it is wrong
in both directions: a 128k preset inside a 1M-root session would never trigger compaction before
overflowing, and a cheap 32k summarizer would be handed an ~850k-token segment.

**Decision: the compactor becomes per run.**

- A run builds its compactor from **its own model's** `context_window`. The root's compactor is the
  root's; each routed run gets its own. Instances are cheap and stateless by construction, which is
  what makes this a wiring change rather than a redesign.
- **The summarizer's input is clipped at the smaller of two windows:** the run's window and the
  summarizer's own. Two sizes, two owners — the trigger belongs to the conversation's model, the
  summary request belongs to the summarizer.
- **`/model` still rescales the root's compactor** (`SetContextWindow`), and any route that was
  following the root moves with it; an explicit route does not move.
- **A summary that still fails is already best-effort**: `maybeCompact` emits `compaction failed: …`
  and the run continues with its conversation intact. Routing makes that path more reachable, not less
  visible.

## 5. Fail on demand, per provider

Spec §1 already requires that the harness start without a reachable provider, and
`internal/app/provider.go`'s `lazyModelClient` already delivers it for one. Breadth multiplies it:

- **One lazy client per provider**, keyed by name: built on the first turn that names one of its
  models, cached on success, **not** cached on failure, with its own status marker. A transient outage
  or a corrected credential recovers on the next turn without a restart.
- **`GET /models` validation is per provider, and checks only the models declared on it**, at that
  provider's own resolution. Provider B being down never fails a turn routed to A.
- **The status bar's provider slot carries one marker per degraded provider**, root's first and
  comma-joined when several are down: `⚠ provider openai unavailable`. One slot, because the bar is one
  line and the operator's next action is "which endpoint is broken".
- **Startup constructs nothing and reads no network.** The only pre-turn knowledge is the presence
  check that already seeds the marker — now per provider.

## 6. When a provider cannot enforce schemas

`Tool.Strict` is `!Lenient` at descriptor build and today every built-in is strict except the one
lenient exception; `wireParams` switches the whole request to `<base>/beta` when any tool is strict.

**For a provider declaring `strict_tools: false`, the client strips `strict` from every tool
descriptor, never selects the strict path, and sends an ordinary `<base_url>` request.** The repair
layer is then the only argument validation — the asymmetry ADR-0002 accepted, made concrete.

What does not change: the tool set, each descriptor's schema, the repair layer's bounds and its
per-turn retry ceiling, the lenient built-in exception (`exploit_plan_suggest`, spec §5.1), the
parallel-call cap, and the prompt.

**The asymmetry is visible once per session.** One `styx: ` line per degraded provider, after the
identity line and before the first turn:

```
styx: provider local: no strict tool schemas — arguments validated by the repair layer only
```

plus a block in `/status`. It is stated, not carried in the status bar: this never changes
mid-session, so a permanent warning token would become furniture, while a line at start is read once
and unread thereafter — which is exactly the budget cap's argument for announcing itself up front.

## 7. What the operator and the record see

- **Status bar:** the **root's** model, unchanged. A `routes:2` marker would be a token nobody can act
  on, and showing the *running* agent's model would make the bar flip as concurrent subagents
  interleave.
- **`/status`:** a routing block — one line per role whose model differs from the root's,
  `role → model (provider)` — and a provider block with each endpoint's host, credential presence
  (`set` / `absent`, never a value), capabilities and billing clock.
- **A child run's view** names the model the run used, folded from that run's own `ev.Model` events
  ([`docs/child-runs.md`](child-runs.md)): a fact about a run belongs in the run's own view, because
  that is where ADR-0021 made it addressable.
- **The audit trail gains `model`** — additive, `omitempty`, harness-stamped from the resolved request,
  never model output. The record already carries `subagent`, `isolation` and `autonomy` as attribution;
  with two models in one session, "which model proposed this call" is the same kind of fact, and the
  audit is what an auditor reads *without* the session log. Existing rows are untouched.
- **The session JSONL is unchanged.** `KindUsage` already carries `Model` and `recordUsage` prices by
  it, so spend needs no new field and no re-derivation.
- **Nothing renders that is not persisted** (spec §4.3): every readout above is a fold over config plus
  events already written.

## 8. Failure and edge cases

- **Root provider unreachable** — the run's first turn fails exactly as it does today; the marker names
  that provider; the next turn retries and recovers.
- **Routed provider unreachable** — that agent's first turn fails with the provider named; the root
  receives a tool error; the run continues; only that provider's marker is set.
- **A route naming a model that does not exist** — config error at startup, naming the role and the
  value. Never "no route": a route that resolves to nothing is the silent no-op §4.3 refuses.
- **A model naming a missing provider** — config error, naming the model and the provider.
- **Duplicate model ID, duplicate provider name, empty `base_url`** — config errors (the ID check
  exists today).
- **An unknown capability key** — config error (§2.1).
- **`api_key_env` set but absent from the environment** — that provider's marker reads `no api key`
  before the first turn; its turns fail on demand (§5).
- **`api_key_env: ""`** — no `Authorization` header is sent, and that is not a degraded state.
- **`http` with a non-private host** — config error (§2.4).
- **A provider reporting no usage** — a budgeted run fails closed on that provider's first completed
  turn (budget-cap §6), with the model and provider named; an unbudgeted run shows `cost —` (§3.4).
- **`/model` to a model on a provider that is down** — allowed and config-valid; the next turn fails on
  demand naming that provider, and the bar marks it. A `/model` that refused would be a pre-flight
  network call, which is the one thing §1 fail-on-demand forbids.
- **`/model` swapping the root mid-session** — unset routes follow the new root; explicit routes do not
  move; the root's compactor rescales and the summarizer clip is recomputed.
- **An engagement-gated preset that is routed** — unchanged: `exploit-dev` still refuses outside an
  engagement and without `exploit_allowed` (ADR-0012, `docs/specialist-subagents.md` §4). Routing is not
  an authority and never satisfies a gate.
- **A headless (`-n`) run** — same config, no command surface, routing works (delegation is audited and
  allowed in engagement mode, ADR-0016), and the budget refusal is reachability-based (§3.4).
- **A resumed session after a config change** — re-reads config; a route to a removed model is a
  startup config error; past turns keep the attribution and the price they were recorded with.

## 9. Verification (what the implementation must prove)

- **Compatibility** — a v1.3-shaped config (a `models:` list, `model:`, no `providers:`, no
  `provider:` keys) loads and runs identically; the built-in DeepSeek provider is what those models
  resolve to; `billing: peak_halved` keeps today's off-peak prices and `STYX_BASE_URL` still overrides.
- **Wholesale replacement** — a project overlay declaring one provider and one model leaves exactly
  those; an unannotated model with no `deepseek` provider is refused by name.
- **Scheme validation** — `https` anywhere passes; `http` on a loopback and on each private literal
  passes; `http` on a public address and on a hostname fails at startup naming the URL; the
  `STYX_BASE_URL` shim cannot bypass it.
- **Declared capabilities** — a `strict_tools: false` provider receives descriptors with no `strict`
  and a request to `<base_url>` (not `<base_url>/<strict_path>`); a `strict_tools: true` provider gets
  strict descriptors and the strict path; `reasoning: false` yields no reasoning deltas from a
  reasoning-shaped fixture.
- **Per-provider laziness** — provider B down: a turn routed to A succeeds; a turn routed to B fails
  with B named; A's marker is clear and B's is set; after B recovers, its next turn succeeds without a
  restart. Config validation never contacts the network.
- **Routing** — a preset with a route uses its own model and its own window; the root is unaffected; an
  unset role follows the root including after `/model`; an explicitly routed role does not follow
  `/model`; an unknown role is refused at startup naming the shipped roles.
- **Budget** — a routed unpriced model refuses a `--max-budget` start, naming every unpriced reachable
  model at once; a priced routed model's turns land in the same accumulator (`recordUsage` by
  `ev.Model`); `cost —` appears for an unpriced interactive run and `$0.0000` never does.
- **Compaction under routing** — a run on a 128k model triggers at 85% of 128k inside a 1M-root
  session; the summarizer request is clipped at `min(run, summarizer)`; a summarizer that still fails
  emits `compaction failed:` and the run continues.
- **Attribution** — an audit row from a routed run carries `model` equal to the model the request
  named, and rows from before the field exists parse unchanged (`omitempty`); a child-run view prints
  the run's model from its own events.
- **Prompt stability** — the assembled system prompt is byte-identical across two sessions that route
  differently and across a `/model` swap.
- **No policy change** — the same tool call on two routes produces the same verdict, reason, and
  isolation in the audit trail; a routed engagement-gated preset refuses exactly as a root-dispatched
  one does.

## 10. Touchpoints (applied by the implementation tickets)

- **`internal/config`** — `providers:`, the model's `provider` and `wire_model`, `routing:`, and the
  validation set: duplicate/missing provider, dangling model reference, unknown role, unknown
  capability key, scheme rule, and the `billing` / `strict_path` defaults.
- **`internal/model`** — `Info` carries its provider's endpoint facts; the client's DeepSeek-specific
  constants (beta path, off-peak clock, `reasoning_content`) become declared inputs; `Pricing` gains the
  billing clock instead of hardcoding `IsPeak` for every model. The `ModelClient` seam is unchanged.
- **`internal/app/provider.go`** — a lazily resolved client per provider, each with its own marker, and
  a status assembly that joins them.
- **`internal/app`** — routing resolution for the root and per run; the degraded-capability lines; the
  reachability check for a budgeted start; `/status`'s provider and routing blocks; the `cost —`
  readout; `/model`'s rescale and route-follow.
- **`internal/agent`** — a per-run compactor built from that run's model; the summarizer clip.
- **`internal/agent/subagent`** — the runner resolves its preset's model for its own loop (its own
  resolver, window, and compactor) instead of inheriting the root's.
- **`internal/audit`** — the additive `model` field on `Record`.
- **`internal/app/commands.go`** — `/status` and `/model`'s listings name providers.
- **`docs/spec.md`** §3.1 and §13 — superseded pointers to this document (ADR-0002 already declared the
  supersession; §3.1 now says where the posture moved).
- **[`docs/budget-cap.md`](budget-cap.md)** §2.1 — one pointer: the refusal is reachability-based once
  routing lands.

## 11. Explicitly not in this design

A second wire protocol or a vendor SDK · capability discovery, probes, or a base-URL vendor table ·
per-model capability overrides · falling back to another model or provider when a route fails ·
budget-aware routing or a cheaper model as the cap nears · a `/route` command or any per-session route
mutation · a `root:` routing key · title generation (or a `titles` route) · routing an MCP server's own
model · provider-reported cost · a merge rule for `providers:` or `models:` · pricing calendars beyond
`peak_halved` and `flat` · per-engagement or cross-run spend · a model ID in the system prompt, the
status bar's non-root models, or any output that would make the byte-stable prefix vary · changing what
the policy engine, scope check, ROE, gate, or audit contract decide.
