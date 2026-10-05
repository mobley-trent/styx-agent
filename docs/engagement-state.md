# styx — engagement-state & findings data model

Decided by [#74 Design the engagement-state and findings data model](https://github.com/mobley-trent/styx-agent/issues/74)
(child of the map [#53](https://github.com/mobley-trent/styx-agent/issues/53)), on top of
the roadmap's v1.1 substrate ([`docs/red-team-roadmap.md`](red-team-roadmap.md) §1, item 1).
This model is the fact base [#75 parser-backed tool contracts](https://github.com/mobley-trent/styx-agent/issues/75)
and [#76 relationship-graph and attack-path computation](https://github.com/mobley-trent/styx-agent/issues/76)
build on. Keystone rationale: [`docs/adr/0004-engagement-state-lives-outside-the-conversation.md`](adr/0004-engagement-state-lives-outside-the-conversation.md).

## 1. Storage & lifecycle

- **One JSON document per engagement:**
  `~/.local/share/styx/engagements/<project>/<engagement-name>/state.json`, where
  `<engagement-name>` is the `name:` field of `engagement.yaml`. Sits alongside the
  session store (`~/.local/share/styx/sessions/`), never inside the repo — the store
  holds credentials and loot, so it must never enter git.
- **Writes are atomic:** write to a temp file in the same directory, then rename over
  the target. A crash leaves either the old or the new document, never a torn one.
- **One writer:** an advisory lockfile (pid-checked, stale locks reclaimed) guards
  `state_update`. A second concurrent session on the same engagement may read; writes
  fail with a clear "engagement state is locked by session X" error. No silent
  last-writer-wins clobbering of a forensic record.
- **Versioning:** a top-level `schema_version` (starts at 1). Same-major readers
  tolerate unknown additive keys — the same contract as session JSONL and config
  (§10.1, §10.3). An incompatible major refuses loudly with a message naming the file;
  no automatic migration in v1.
- **Retention:** the store persists until the operator deletes it. Deactivation
  (`/mode`) and session end keep it; nothing auto-prunes on engagement expiry.

## 2. The observation-only principle

**State records observations; authorization never enters the store.** Scope and ROE live
solely in `engagement.yaml` and the policy engine. The store may hold a fact like "host
10.0.0.7 answered on 445" even for something later found out of scope — but no field of
any entity or edge carries, mirrors, or implies authorization. There is exactly one
source of truth for what is allowed, and it is not this file.

## 3. Entities (v1: six kinds)

Every entity carries a common envelope: `id` (harness-assigned stable identifier,
`<kind>-<4 hex>`), `active` (bool, default true — v1 has no deletes, so entities are
deactivated instead), `created_at`, `updated_at`, and the provenance of the last write
(§6).

| Kind | Fields | Natural key (upsert match) |
|---|---|---|
| `host` | `addresses[]`, `hostname`, `os`, `tags[]` | primary address |
| `service` | `host` ref, `port`, `proto` (tcp/udp), `product`, `version`, `state` (open/closed/filtered) | host + port + proto |
| `credential` | `type` (password/hash/key/token), `principal`, `secret`, `tags[]` | principal + type + secret |
| `access` | `principal` (credential ref or account name), `target` (host/service ref), `level` (user/admin/system), `via` (finding/credential ref) | principal + target |
| `segment` | `label`, `cidrs[]` | label |
| `finding` | see §5 | title + affected refs |

Identity is the harness-assigned `id`; addresses, hostnames, and principals are
*attributes*. A merge or re-address changes attributes, so no edge ever dangles.
`upsert_entity` with a matching natural key reuses the existing id rather than creating
a duplicate.

AD-specific entities (domain, user, group, computer) are **deferred**: v1 carries
identity relationships through `access`, `credential`, and the edges below; richer
directory modeling returns only if a parser contract (#75) demands it.

## 4. Relationship-graph edges

A **closed enum**: directed, endpoints validated against the table, per-edge
`confidence` (low/medium/high — the cost model in #76 maps these to modifiers), and the
same provenance stamp as entities. Any new edge type is a design-doc change, not a
free-form string.

| Edge | From | To | Meaning |
|---|---|---|---|
| `RESOLVES_TO` | host | host | hostname resolves to this address |
| `RUNS_ON` | service | host | service is offered by this host |
| `IN_SEGMENT` | host | segment | host belongs to this network segment |
| `CREDENTIAL_FROM` | credential | host \| service \| finding | where the secret came from |
| `VALID_FOR` | credential | host \| service | the secret works on this target |
| `ADMIN_OF` | credential \| access | host \| service | privileged over this target |
| `PIVOT_TO` | access | host | this foothold reaches that host |
| `EXPLOITED_VIA` | finding | access | this finding produced this foothold |

The `access.via` field (§3) is a single-hop convenience mirror of its `EXPLOITED_VIA`
or `CREDENTIAL_FROM` edge; the edge is canonical and `state_update` maintains both in
one operation, so they cannot drift.

## 5. The finding record

| Field | Values |
|---|---|
| `title` | short human label |
| `severity` | `info` \| `low` \| `medium` \| `high` \| `critical` (CVSS qualitative) + optional `cvss_vector` |
| `status` | lifecycle, below |
| `confidence` | `low` \| `medium` \| `high` — enums, never numbers: a model cannot calibrate 0.73, and #76 maps the enum to path-cost modifiers |
| `verification` | `unverified` (default) \| `verified` \| `refuted` |
| `evidence[]` | evidence items, below |
| `affected[]` | host/service refs |
| `first_seen` / `last_seen` | timestamps |

**Status lifecycle** — transitions are validated by the store; anything else is refused:

```
detected ↔ confirmed → false_positive
                    → fixed        (fixed → confirmed reopens)
                    → risk_accepted
```

**Verification invariant:** `verified` and `refuted` are refused until the finding has
at least one evidence item. A finding without evidence is unvalidated — always.

**Evidence item:** `kind` (cli-output | http-response | artifact | screenshot | note),
origin tool, session id, timestamp, and a ref (artifact path or inline excerpt), all
provenance-stamped. Provenance is never model-supplied: the harness stamps `source`
(model or tool name), subagent attribution, session, and time on every mutation.

## 6. The tools

Two tools, registered always, both behind the single policy gate (§5.3 normative order —
schema validation → verdict → audit-before-execution → dispatch):

- **`state_query`** — reads: structured filters over kinds and attributes, listing, and
  1–2-hop neighborhood reads over the graph. No query language in v1. Output truncates
  at capture like any other tool output.
- **`state_update`** — typed, schema-validated operations:

| Op | Validation enforced by the store |
|---|---|
| `upsert_entity` | kind ∈ six kinds; natural-key match reuses id; envelope stamped |
| `upsert_finding` | severity/status/confidence/verification enums |
| `set_status` | lifecycle transitions only (§5) |
| `attach_evidence` | provenance stamped by the harness, not passed in |
| `set_verification` | ≥1 evidence item required |
| `add_edge` / `remove_edge` | type ∈ closed enum; typed endpoints; confidence enum |

There are **no delete ops** in v1: entities go `active: false`; edges may be removed
without dangling anything. The model never writes the document wholesale — every
mutation is a typed op through this API, which is what makes "never model-invented"
enforceable rather than aspirational. Parser tools (#75) write through these same ops.

## 7. Gating & presets

- **The surface is engagement-mode-only.** The default rule table denies `state_*` in
  safe mode (reason: no engagement — there is no store to touch) and allows them in
  engagement mode, with every verdict audit-logged. Calls carry no scope targets, so
  they are not scope questions (§6.1 handles them as rule-table matters alone).
- Writes are local and non-scope: **allow, not prompt** — a prompt per state write would
  be unworkable volume once parsers and subagents are writing findings; the audit trail
  is the control.
- **All four subagent presets** (`coder`, `recon`, `exploit-dev`, `log-triage`) receive
  both tools: parsers run inside subagents, so the write path must reach them, and
  provenance already carries subagent attribution.

## 8. Feeding the prompt: the state digest

The record lives on disk, outside the conversation. That makes the two spec promises
true **by construction**:

- **Never compacted (§4.5):** compaction operates on transcript content; it can evict
  *views* of the state, never the state itself.
- **Never model-invented (§10.2):** no model output reaches the store except through
  the audited, schema-validated ops of §6.

The model still needs to *see* state without paying a query every turn, so the harness
appends a **state digest** message:

- **Content:** entity counts by kind, top open findings as one-liners (severity +
  title), access count, unverified-findings count, and deltas since the previous
  digest. Overflow truncates with a pointer to `state_query`.
- **Trigger:** appended only when state changed since the last digest — plus once after
  compaction evicts digests, and once at engagement activation.
- **Placement & cost:** tail-appended (never mutating the transcript head), so the
  exact-prefix cache keeps warming; digests are ordinary persisted, evictable content —
  §4.3's "nothing renders that isn't also persisted" holds, and §7.4's frozen
  engagement context is untouched. The system prompt stays a byte-stable prefix
  frozen at session start.
- **Subagents get no digest:** they consume state through `state_query` and report to
  the parent, which carries the view.

## 9. Downstream consumers

- The **§10.2 engagement-end notes block** in STYX.md is generated *from* the store
  (targets, findings, artifacts) — the store replaces model recollection as its source.
- A human-readable `findings.md` render is **deferred** to the v1.3 report-generation
  work (map fog); v1.1 ships no render.

## 10. Spec touchpoints (applied by the implementation tickets)

- **§4.5** — record that engagement state survives compaction by construction (record
  outside the conversation; digests evictable).
- **§5.1** — add `state_query` / `state_update` to the built-in tool table.
- **§5.4** — add both tools to the preset allowlists.
- **§6.1** — mode defaults: `state_*` safe = deny, engagement = allow (audit-logged).
- **§10** — storage entry for the engagement-state store (path, versioning, lockfile).

## 11. Explicitly not in v1

AD domain/user/group entities · a query language · delete ops · `findings.md` render ·
mirroring scope/ROE into state · cross-engagement learning · numeric CVSS/confidence.
