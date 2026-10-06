# styx — parser-backed tool contracts

Decided by [#75 Design the parser-backed tool contracts](https://github.com/mobley-trent/styx-agent/issues/75)
(child of the map [Wayfinder: styx prototype → adoptable red-team agent](https://github.com/mobley-trent/styx-agent/issues/53)),
on top of the roadmap's v1.1 substrate ([`docs/red-team-roadmap.md`](red-team-roadmap.md) §1, item 2)
and the engagement-state model decided in
[#74](https://github.com/mobley-trent/styx-agent/issues/74) ([`docs/engagement-state.md`](engagement-state.md)).
Keystone rationale: [`docs/adr/0005-parsers-are-harness-side-and-parser-mandatory-is-tracked.md`](adr/0005-parsers-are-harness-side-and-parser-mandatory-is-tracked.md).

## 1. Scope & the v1.1 parser set

Six harness-owned parser tools, one per scanner:

| Tool | CLI counterpart | v1 artifact format |
|---|---|---|
| `nmap_parse` | nmap (`-oX`) | XML |
| `nuclei_parse` | nuclei (`-jsonl` / `-je`) | JSON Lines |
| `sqlmap_parse` | sqlmap | per-target text log |
| `gobuster_parse` | gobuster | text output (dns/vhost/dir) |
| `cme_parse` | CrackMapExec / NetExec | per-target text log |
| `bloodhound_parse` | BloodHound collectors | legacy JSON (users/computers/groups/domains) |

Per `docs/engagement-state.md` §3, AD domain/user/group entities are **deferred**, so
`bloodhound_parse` writes through the identity subset it can express: `access`, `credential`,
and the `ADMIN_OF` / `PIVOT_TO` / `EXPLOITED_VIA` edges. Everything else in Pentestcode's
18-tool set (`xss_detect`, `jwt_analyze`, `cred_spray`, `ensure_tools`, …) is **out of this
ticket**; `state_query` / `state_update` are owned by [#74](https://github.com/mobley-trent/styx-agent/issues/74) ([`docs/engagement-state.md`](engagement-state.md)), and `attack_path_suggest` by [#76](https://github.com/mobley-trent/styx-agent/issues/76) ([`docs/attack-paths.md`](attack-paths.md)).

They share an internal `internal/parsers` framework: a per-format **extractor** (bytes →
typed candidate records) and a common **write pipeline** (records → §6 ops → atomic commit →
receipt). N is six, not N hand-rolled tools.

## 2. Tool contract shape

- **One named tool per format**, each strict. Per the harness's strict-mode rule
  (every declared property is `required`; `internal/agent/schema_test.go`), each schema is
  exactly:

  ```json
  {
    "type": "object",
    "properties": {
      "path": {
        "type": "string",
        "description": "Workspace-relative path to the raw tool output to parse."
      }
    },
    "required": ["path"],
    "additionalProperties": false
  }
  ```

  There are **no optional parameters and no disambiguators**: everything (target host,
  scanner, port) is inferred from the artifact. An inferred-nothing call is a §7 error,
  not a guess.
- **Path only, no inline text.** Scanner output is large (an nmap XML over a /24 is
  megabytes) and would blow the turn's token budget and the 100 KB capture truncation; the
  artifact must survive as the evidence ref anyway. Inline text would invite the model to
  paste a truncated or `grep`-ed view — the hand-grepping anti-pattern the invariant exists
  to kill.
- The path is resolved with the existing `resolveWithin(WorkDir, path)` confinement
  (`internal/agent/tools_read.go`): no `..` escape, no symlink escape; the parser reads the
  same workspace `read_file` does.
- `Destructive: false`, `ExploitClass: false` (parsing is neither), `Targets: nil` (no
  network). Every call still rides the normative order: schema validation → policy verdict
  → audit → dispatch (§5.3). No special case.

## 3. The artifact convention

- Raw scanner output is written by the CLI in the session container to a **designated
  artifact directory** under the project root — `.styx/out/` — which is bind-mounted as
  `/workspace` and therefore visible harness-side. The prompt (and, in v1.2, the sandbox
  image's help text) routes scanner output there; the harness additively gitignores
  `.styx/`.
- The designated directory is what makes §4's obligation-watching reliable: the harness
  can see an artifact appear even when argv sniffing misses a wrapped or scripted run.
- Artifacts are **retained**, not auto-pruned: they are the evidence refs state points at.
  Removal is the operator's act.
- A parser accepts **any** workspace-relative path (not only `.styx/out/`), so the model can
  re-parse an artifact it already holds; the designated dir is a convention for detection,
  not a constraint on the parser.

## 4. The parser-mandatory invariant

The rule: **a raw CLI run's findings reach engagement state only through its parser.** Hand-
grepping XML/JSON into a `state_update` call does not reproduce the mapping, the evidence
attachment, or the harness-stamped provenance — so it is not a path into state at all.

Enforcement is **structural + tracked, never a hard block**:

1. **Structural.** State is writable only through the audited, schema-validated typed ops
   of `docs/engagement-state.md` §6. The parser is the only harness component that maps
   scanner output onto those ops, so the parser is the only productive path; there is
   nothing to bypass *to*.
2. **Tracked.** The harness maintains a **pending-parse obligation**:
   - **Detected** when a `bash` command's argv matches a known scanner pattern (best-effort,
     to attribute *which* parser is expected), **or** when a new artifact appears in
     `.styx/out/` (the reliable backstop; unknown-origin artifacts get a generic nudge).
   - **Surfaced** in the **state digest** (a `pending parse: <artifact> → <parser>` line,
     see `docs/engagement-state.md` §8) and in the status bar; and as a directive text in
     the turn following detection.
   - **Cleared** when the matching parser successfully parses that artifact, the artifact is
     removed, or the obligation is explicitly waived.
3. **Never a hard block.** The loop does not refuse further scanner runs or network calls
   while an obligation is open: argv sniffing cannot see every scanner and a block risks
   deadlock on an artifact the model should not parse yet. An ignored obligation simply
   leaves state without those findings — and the digest makes that visible, which is the
   control.

## 5. The parse → state write contract

A parser call runs one deterministic pipeline:

```
artifact bytes → per-format extractor → typed candidate ops
  → one atomic §6 batch (upsert_entity | upsert_finding | attach_evidence | add_edge)
  → parse receipt
```

- **Atomic.** The whole batch commits in one store operation: either every op lands or none
  does. A crash or validation failure mid-batch writes nothing (§7).
- **Harness-written, never model-written.** The parser is a harness component; the model
  supplies only `path`. Every entity/finding/edge the parse creates is provenance-stamped
  by the harness (source = the parser tool name, session, time), never model-supplied —
  preserving `docs/engagement-state.md` §6's "never model-invented."
- **No status/verification escalation.** Parsers write `status: detected`,
  `verification: unverified` and never advance either; `set_status` / `set_verification`
  remain model/operator acts (a parser may set `confidence`, never `verified`).
- **Receipt.** The tool result is a compact JSON **parse receipt** (truncated at capture
  like any tool output, with an artifact pointer on overflow):

  ```json
  {
    "tool": "nmap_parse",
    "artifact": ".styx/out/nmap-10.0.0.0_24.xml",
    "ok": true,
    "entities": {"host": {"new": 3, "updated": 1}, "service": {"new": 11, "updated": 0}},
    "findings": {"new": 2, "updated": 0},
    "edges": {"RUNS_ON": 11, "RESOLVES_TO": 2},
    "created_ids": ["host-1a2b", "service-3c4d"],
    "skipped": [{"record": "…", "reason": "unparsable port spec"}],
    "warnings": []
  }
  ```

  The receipt is the model's feedback loop: it tells the model what entered state without
  re-reading the raw output.

## 6. Per-parser mapping

Every parser upserts the host (and service, when a port is named) it observed, so edges
never dangle. Natural keys are `docs/engagement-state.md` §3's.

| Parser | Entities | Edges | Findings? | Severity / confidence source | Evidence |
|---|---|---|---|---|---|
| `nmap_parse` | `host` (addresses, hostname, os), `service` (port/proto/product/version, state=open), `segment` from a scanned CIDR | `RUNS_ON`, `RESOLVES_TO`, `IN_SEGMENT` | **No** — ports are facts, not vulnerabilities | n/a (facts) | none (findings only carry evidence; hosts don't) |
| `nuclei_parse` | `host`, `service` (matched port) | `RUNS_ON` | Yes, one per template match | severity from nuclei `info.severity`; confidence `medium` | `http-response` (request/response excerpt) + `artifact` |
| `sqlmap_parse` | `host`/`service`, `credential` (dumped users/hashes), `access` (DB admin) | `CREDENTIAL_FROM`, `VALID_FOR`, `EXPLOITED_VIA` | Yes, one per injectable parameter | severity `high` (confirmed injection); confidence `high` | `cli-output` (payload/log excerpt) + `artifact` |
| `gobuster_parse` | `host`, `service` | `RESOLVES_TO` (dns/vhost modes) | **dir mode:** one `info`-severity finding **per host**, carrying the discovered-path list as evidence | none in output → `info` / `low` | `cli-output` + `artifact` |
| `cme_parse` | `host`/`service`, `credential`, `access` | `VALID_FOR`, `ADMIN_OF`, `PIVOT_TO` | Yes, per positive module result (e.g. SMB signing off) | severity from module; confidence `high` for a valid-login result | `cli-output` + `artifact` |
| `bloodhound_parse` | `access` (user→host at a level), `credential` | `ADMIN_OF`, `PIVOT_TO`, `EXPLOITED_VIA` | No (it is an identity graph, not a vuln list) | n/a | `artifact` |

Notes on the text-shaped parsers: `sqlmap_parse` and `cme_parse` parse their per-target
`log` files with strict line patterns and accept reduced field fidelity (no JSON path in
v1). `gobuster_parse` collapses all discovered paths for a host into one info finding
rather than one finding per path — a dir listing is context, not N findings.

## 7. Failure & malformed output

Strict, atomic, non-fatal, never-silent:

- **Unparseable / unrecognized / format-mismatched** artifact → **nothing is written**, and
  the tool returns a structured error naming the expected format, the artifact ref, and an
  offending sample. A normal tool error — never a loop crash — always audit-logged.
- **Partial parse** (some records invalid) → the valid batch **commits**, and the receipt
  reports `skipped` entries with per-record reasons. No silent drops.
- **Empty-but-valid** output → success with zero counts.
- **Unknown format version** → refuse with a message; never guess, never regex-scrape a
  human-readable blob as a fallback when a structured format was expected.
- A failed parse leaves no partial state and the obligation open (§4).

## 8. Deduplication & repeated scans

- Entities upsert on their **natural key** (`docs/engagement-state.md` §3); a re-scan reuses
  the existing id and refreshes attributes, never duplicates.
- Findings match on **title + affected refs**: a re-detected finding updates `last_seen`,
  **appends** the new evidence item, and **does not change `status`** (a `fixed` finding is
  not silently reopened by a re-scan; reopening is `set_status`'s job, §5 of the model doc).
- `first_seen` is set once; `last_seen` on every sighting.

## 9. Gating, placement, presets

- **Harness-side execution.** Parsing is pure computation over a workspace file: no network,
  no container dependency, cheaper, and it keeps the *trust boundary* out of the container
  that holds untrusted output. The raw CLI runs in the container; the artifact round-trips
  through the shared `/workspace`; the parser is the harness-side boundary that turns
  untrusted bytes into typed state. (The "inside the container" requirement is satisfied
  where it matters — CLI execution — without handing the authoritative parser to the
  untrusted side.)
- **Engagement-mode-gated, like `state_*`.** Registered always; the rule table denies all
  six in safe mode (no engagement, so no store to touch) and **allows + audits** them in
  engagement mode. They carry no scope targets, so §6.1 handles them as a rule-table matter
  alone — no scope question.
- **All four subagent presets** (`coder`, `recon`, `exploit-dev`, `log-triage`) receive the
  six, exactly as they receive `state_*`; `recon` is the primary consumer. Provenance carries
  subagent attribution.

## 10. Limits & robustness

- **Size:** parse streams the artifact; a large artifact must not balloon the harness heap
  (the same concern `read_file`'s 4 MiB cap addresses). A hard ceiling refuses with a clear
  error rather than OOM.
- **Time:** a wall-clock parse timeout turns a hang into a tool error.
- **Confinement:** every path goes through `resolveWithin(WorkDir, …)`; no reading outside
  the workspace.
- **Idempotence:** re-parsing the same artifact is safe (natural-key upserts; §8).

## 11. Spec touchpoints (applied by the implementation tickets)

- **§5.1** — add the six parser tools to the built-in tool table, with their `path`-only
  schemas.
- **§5.4** — add the six to all four preset allowlists.
- **§6.1** — mode defaults: parser tools safe = deny, engagement = allow (audit-logged).
- **§10** — record the `.styx/out/` artifact convention and its gitignore entry.
- **§4.5 / §7.4** — the pending-parse obligation rides the state digest (tail-appended,
  never mutating the prompt head).

## 12. Explicitly not in v1

Inline raw-text input · optional/disambiguator parameters · a generic `parse_output`
dispatcher · parser-side `set_status` / `verify` · auto-execution of discovered paths ·
AD domain/user/group entities · `findings.md` render (v1.3) · the combined run+parse tool
shape.
