# styx — reports and the local run viewer

Decided by [#147 Design report generation and the local run viewer](https://github.com/mobley-trent/styx-agent/issues/147)
(child of the map [Wayfinder: v1.3 reach & provider designs](https://github.com/mobley-trent/styx-agent/issues/144)),
delivering [`docs/red-team-roadmap.md`](red-team-roadmap.md) §1 item 10 — report generation and a
local run viewer. Companion to [`docs/findings-export.md`](findings-export.md), which owns the
machine record this document deliberately does not re-render. Keystone rationale:
[`docs/adr/0015-a-report-renders-state-and-the-roe-never-the-audit.md`](adr/0015-a-report-renders-state-and-the-roe-never-the-audit.md).

This document decides **what a Report is, what produces it, and what the local viewer reads and
shows**. It does not decide the findings export (shipped, [`docs/findings-export.md`](findings-export.md)),
HTML or SARIF reports, report diffing across runs, child-session navigation (item 14, ticket
[#151](https://github.com/mobley-trent/styx-agent/issues/151)), or any change to the policy gate —
a Report and a viewer both read; neither grants anything.

## 1. Scope: three words, still three things

[`docs/findings-export.md`](findings-export.md) §8 fixed the vocabulary, and this design keeps it:

- **Findings export** — the machine record (`vulnerabilities.json`, `.csv`, `findings.sarif`),
  deterministic, written by a non-interactive run into `--out`. Shipped.
- **Report** — the human document: one Markdown file describing an engagement — what is authorized,
  what was found, what was obtained, and by which route.
- **Artifact** — raw scanner output in `.styx/out/`, evidence a finding cites and a parser reads.

The export and the Report are **two renderings of one truth, neither a copy of the other**. They
share the reportable-finding predicate (§2.1) and nothing else: the export is for a pipeline, the
Report is for a client, an auditor, or the operator's own memory a month later.

## 2. What a Report is built from

### 2.1 State plus the ROE, never the audit

**A Report renders two sources and no others:**

| Source | Contributes |
|---|---|
| **Engagement state** (`engagementstate.Snapshot`) | hosts, services, findings, credentials, access, segments, the relationship graph, and every timestamp on them |
| **The engagement file** (`engagement.Load`) | the authorization half: targets, operator, expiry, and the ROE limits as declared |

The **audit trail is not a source**, and neither is the session JSONL. Three reasons, in order of
weight:

- **The audit record is unredacted by contract.** `audit.Record.Params` is "verbatim — never
  truncated and never redacted" (`internal/audit/audit.go`). A shareable document built from it
  inherits the leak, and parameter blobs are exactly where tokens, passwords, and request bodies
  land.
- **The audit answers a different question.** It records what the harness *decided* — verdicts,
  refusals, prompt resolutions — and its reader is a forensic one, asking "did anything run outside
  the authorization". The Report's reader asks "what is the posture of this engagement".
- **The state is already sufficient for the ticket's asks.** Routes actually taken are recorded as
  edges (`EXPLOITED_VIA`, `PIVOT_TO`, `ADMIN_OF`, `VALID_FOR`) with `Provenance` stamps; a timeline
  is `FirstSeen` / `LastSeen` / `Provenance.At`; footholds are `access` entities. Nothing the Report
  narrates needs the audit, so reaching for it would only import its liabilities.

### 2.2 Authorization is not in state, so the file supplies it

`GLOSSARY.md` is explicit that engagement state is **observations only** — "authorization is never
part of it" — and `docs/engagement-state.md` §2 keeps it that way. A Report that carried a
scope-and-ROE section sourced from state would therefore be describing something the store does not
hold.

So the engagement file is read **through the same validation the gate uses** (`engagement.Load`). A
file that fails validation is not quoted with a caveat: the command fails (§5.3). A report citing an
invalid authorization would be worse than no report.

### 2.3 What a Report cannot say

Isolation level, container loss, interruptions, refusals, prompt resolutions, and pending parses are
**runtime facts**, and none of them is in state. Rather than reach into the audit for them, the
Report states its own boundary in §3.2 — a reader is told what they hold and where the other half
lives. The alternative (silence) invites a client to read a clean report as "nothing was refused",
which is precisely the inference ADR-0008 refused to let a machine artifact make.

## 3. The document

### 3.1 Shape

One Markdown file, LF line endings, trailing newline, one `##` section per part, sections in this
fixed order:

```markdown
# Engagement report — acme-q4

State revision 41 · state schema 1 · rendered from engagement state and engagement.yaml

## Engagement and authority
targets, operator, expiry, ROE (exploit_allowed, destructive_forbidden, time window,
exploitation autonomy level) — each line as declared, none interpreted

## What this document is
the boundary paragraph (§3.2)

## Findings
severity table, then each finding (§3.3)

## Access obtained
one row per access: target, level, via, first seen

## Credentials held
one row per credential: type, principal, source, valid-for targets — never the secret

## Routes taken
the exploitation chain per foothold, derived from edges

## Omissions and limits
counts of what was not carried, unresolved refs, and the no-suggestions statement
```

### 3.2 The boundary paragraph

> This report renders the engagement's state at revision N together with the rules of engagement as
> declared in `engagement.yaml`. What the harness *did* — refusals, prompt resolutions, isolation
> level, interruptions — is the audit trail's subject, recorded per session as
> `styx-audit-<timestamp>.jsonl` in the project directory.

The paragraph names a convention rather than a file, because a Report has no session and must not
pretend to one.

### 3.3 Findings

The Report carries the **reportable** set — `active`, status in `{detected, confirmed,
risk_accepted}`, verification ≠ `refuted` — which is `findingsexport.Reportable`, read from the one
place it is defined, so the Report and the export can never disagree about which findings exist.

Each finding renders as a small block, sorted severity (critical → info), then title, then joined
affected endpoints, then id — the export's §4 order, shared rather than re-invented:

- **title**, severity, and `cvss_vector` when the store holds one;
- **status**, confidence, verification — all three, never one standing in for another (`detected`
  and `unverified` are what a reader needs to know before trusting a critical);
- **affected**, resolved to coordinates as the export resolves them (`address:port/proto`, hostname);
  an unresolvable ref prints as the raw ref, marked unresolved, never dropped;
- **evidence** as a count and its refs, verbatim — raw output stays in the artifact it names;
- **first seen / last seen** as the store's own timestamps, RFC 3339 UTC.

No remediation prose, no scores, no narrative inference. Remediation is a human's writing, and a
harness that inferred it would be inventing a fact of its own.

### 3.4 Credentials and secrets

**`Entity.Secret` is never rendered, in any format, at any verbosity, by any flag.** Credentials
appear as their non-secret envelope: type, principal, the `CREDENTIAL_FROM` source, and the
`VALID_FOR` targets. A credential line therefore says "a password for `svc-backup`, found on
`10.0.0.33`, valid on `fileserver`" — enough to brief a client on exposure, nothing that logs in.

This is a property of the rendering function (§6), so it is testable: a fixture store holding a
known secret must not produce output containing it.

### 3.5 Routes taken, and the routes not taken

**Routes taken** are derived from the graph: for each `access` entity, the finding that produced it
(`EXPLOITED_VIA`, mirrored in `access.via`), the host it reaches (`PIVOT_TO`), and the level held
(`ADMIN_OF` / `level`). They are printed as a chain, not as prose.

**Suggested routes are excluded.** Attack paths are computed on read, priced, and advisory
(ADR-0006); printing one in a client document reads as a recommendation the harness never made, and
would go stale the moment state changes. The Report says so in one line — suggestions are advisory
and live in `exploit_plan`, not in a report — so their absence reads as a decision.

### 3.6 Determinism

A Report inherits ADR-0008 exactly:

- **No wall clock anywhere.** No `generated_at`, no duration, no session id, no exit code, no version
  banner prose that changes per build. "When was this made" is the file's mtime; styx does not claim
  a date it would have to stamp.
- **The header states the state's identity** — engagement name, `schema_version`, `revision` — which
  is what makes a report reproducible and a diff between two reports meaningful: the posture
  changed, and nothing else.
- **Order is total and declared** (§3.3), and nothing iterates a map.
- **Two renders of one snapshot are byte-identical**, pinned by a golden-file test — the same test
  shape `internal/findingsexport` already uses.

A timestamped report remains available to anyone who wants one by checking it into a repository,
where the commit carries the date.

## 4. Omissions and limits

The section exists so an omission is never silent, mirroring the export's `counts.omitted`:

- **counts of findings not carried** — `false_positive`, `fixed`, `refuted`, inactive — by status;
- **unresolved refs, named** — an affected endpoint that no longer resolves prints as a ref and a
  reason, because a finding that quietly lost a host reads narrower than the record says;
- **the no-suggestions line** (§3.5);
- **the boundary pointer** (§3.2) is the header's job, not repeated here.

What the section never does is claim a run condition. "Ran in degraded isolation" is not state, and
a Report that guessed at it would be the silent downgrade the safety model exists to refuse.

## 5. The command: `styx report`

### 5.1 Surface

```
styx report [--engagement <path>] [--out <path>]
```

- **No `-n` requirement, and no dependence on a run.** A Report is over an *engagement*, which
  outlives any session; the findings learned in a later session belong in the same document.
- **It does not reuse `--out`'s export path.** That flag is the run-end export's, writes three files,
  and belongs to a non-interactive run. `styx report` writes one file, at any time.
- **The file goes to `.styx/report/<engagement>.md`** by default, and `--out <path>` overrides it
  (a file path; a missing parent directory is created).
- **`.styx/report/` is not gitignored.** `.styx/out/` stays artifacts-only and ignored; a Report is a
  deliverable, and whether it is committed is the operator's call (the same posture the export takes
  toward the operator's `--out` directory).

### 5.2 Which engagement

The project may hold several engagement files — the gate's own discovery looks for
`*.engagement.yaml`, `*.engagement.yml`, `engagement.yaml`, `engagement.yml`, and `.styx/*.yaml`
(`internal/app/run_tui.go`). `styx report` resolves:

- `--engagement <path>` always wins;
- exactly one candidate ⇒ it is used;
- zero ⇒ exit `1`, naming the patterns looked for;
- several ⇒ exit `1`, **listing them** and naming `--engagement` as the fix.

There is no picker and no "most recent wins": guessing which authorization a document should quote is
the one guess this command must not make.

### 5.3 Reading, and failure

- **Read-only, without the lock.** A Report is a view of a snapshot; taking the store's write lock for
  a read would let a running session block a reader for no reason. The store's own load path is used,
  so a snapshot taken mid-session is the last committed save, never a torn file.
- **No store for that engagement ⇒ exit `1`**, naming the engagement and the path looked for. Unlike
  the export's deliberate valid-empty document for a safe-mode run, an empty Report would be a
  document making a claim — "nothing found" — about an engagement styx has never seen.
- **An engagement file that fails validation ⇒ exit `1`** with the validation error, before anything
  is written.
- **Writing is atomic.** The file is written to a temporary file in the destination directory and
  renamed into place; a failure removes the temporary and leaves any previous report untouched, then
  exits `1`. A half-written report is worse than a stale one, because it looks current.
- **Re-running replaces the file.** The report is derived, so refreshing it is the normal operation;
  refusing on an existing file would turn "this report is stale" into the operator's manual problem.
- **Exit codes:** `0` written, `1` any failure above, `2` usage. There is no gate and no `3`/`4` — a
  Report states a posture, it never fails a pipeline. Gating is `--fail-on`'s job
  ([`docs/headless-ci.md`](headless-ci.md) §8).
- **One receipt line on stderr, nothing on stdout:**

  ```
  styx: report .styx/report/acme-q4.md (state revision 41, 7 findings, 3 omitted)
  ```

  The counts come from the same predicate that filtered the document, so the receipt cannot
  disagree with the file.

## 6. The viewer: `styx view`

### 6.1 Surface

```
styx view <session-id | path.jsonl>
```

- **Offline, no server, no pager process.** It prints and exits; `styx view <id> | less` is the pager,
  `grep` is the filter, and `--skip`-style flags do not exist in v1. ADR-0001 already decided that
  the terminal is the pager; a viewer that re-implemented one would be the AltScreen mistake returning
  one layer out.
- **No interactivity.** No keybindings, no scrolling viewport, no `/view` TUI command. Item 14 adds a
  *new entry point* beside this one, not a rewrite of it (§6.5).
- **Resolution:** an argument ending in `.jsonl` (or containing a path separator) is opened as a file;
  anything else is a session id resolved through `sessions.Store` for the current project. An unknown
  id exits `1`, listing the ids that do exist.
- **Output is plain text on stdout**, no ANSI — a viewer whose output depends on a TTY is a viewer
  that cannot be grepped, diffed, or pasted into a ticket.

### 6.2 What it shows

In file order, through the one renderer (§7):

1. **A header** — session id, project, first event's time, event count. Facts from the file, not a
   generated-at stamp.
2. **The transcript** — every persisted event: user turns, assistant text, reasoning, tool calls with
   their `verdict` and `reason`, tool results **in full** (the safety elision marker and its
   pointer to the JSONL remain for pathological output), plans, diffs, subagent blocks, engagement
   activation, MCP lifecycle, isolation, errors, compaction, usage.
3. **Reasoning prints.** This is the operator's own session on their own machine; unlike a `-n` run
   ([`docs/headless-ci.md`](headless-ci.md) §6.1), there is no pipeline that the inner monologue could
   corrupt.
4. **A findings block, labelled.** The store's snapshot rendered with the export's reportable
   predicate, headed honestly:

   ```
   ## Findings — engagement state at view time, revision 41
   ```

   A session file does not contain findings; the block is the engagement's *current* state, and the
   label is what keeps a reader from attributing today's findings to that run. The session's own
   `state_digest` events remain in the transcript where they occurred.
5. **A footer** — the session's token and cost totals from its own `KindUsage` events, and its denial
   count. Both are already reconstructable from the file ([`docs/headless-ci.md`](headless-ci.md)
   §6.3); the viewer just says them.

### 6.3 Failure while reading

- **An unreadable line** prints `! unreadable record at line N: <reason>` and reading continues. A
  reader is not an enforcement point, and stopping at the first bad line would make a damaged log
  unreadable exactly when someone needs it.
- **An unknown event kind is skipped silently**, and an unknown key on a known kind is ignored: the
  same-major compatibility contract (`docs/spec.md` §10.1) is what makes an old viewer usable on a
  newer log.
- **A missing or empty file** is exit `1` with the path named — there is nothing to be honest about.

### 6.4 What it does not show

No findings *history*, no per-turn state diffing, no audit verdicts beyond the `verdict`/`reason`
already on each tool call, no credentials (never rendered — same rule as §3.4), and no cross-session
view. Each of those is a different artifact's job or a later ticket.

### 6.5 The seam to child-session UX (item 14)

Subagent runs are already bracketed in the JSONL (`KindSubagent` plus `subagent`/`run_id` on inner
events), so the viewer prints them as folded blocks with **role and run attribution**, exactly as the
transcript recorded them. A session may have children later; that becomes a second input surface
(choose a run, then view it) beside `styx view`, which keeps its contract: one session id, one
transcript. No tree, no picker, no nesting depth in this design.

## 7. One renderer, two front ends

The TUI renders with `Model.apply` — model-bound, folding subagent blocks, writing into the live
region ADR-0001 defines. The viewer needs the *committed* half of that path and none of the live
region. Duplicating it would let the live transcript and a replayed one drift, which is the "nothing
renders that isn't also persisted" invariant failing in reverse: a record that reads differently
depending on who is reading it.

So:

- **`internal/transcript`** owns "one persisted event → the lines a terminal prints": assistant text
  and reasoning, tool calls with verdict and reason, full tool output with the safety cap, plan and
  diff blocks, subagent block folding by `run_id`, the operation/refusal line vocabulary.
- **The TUI keeps the live region** — editor, status bar, prompt card, streaming partial — and calls
  the transcript writer for everything it commits to scrollback.
- **The viewer is that same writer plus a header, a findings block, a footer, and no live region.**
- **Styling is injected, not assumed**: the TUI passes its theme; the viewer passes a plain style
  (§6.1).
- **Acceptance test:** replaying a transcript fixture through the plain writer prints what the TUI
  printed live for the same fixture — one golden file, two front ends.

This is a real refactor of shipped TUI code, which is why it is the viewer's first task and gates it
(§9).

## 8. Naming, and where this stops

- **The Report is not an export and never writes one.** A Report that emitted `vulnerabilities.json`
  would duplicate the export's rendering; an export that grew this narrative would be a Report
  (findings-export §9: one rendering, one owner).
- **The Report cites artifacts, it does not bundle them.** Evidence refs point at `.styx/out/` paths
  the reader may or may not have; packaging evidence into a single archive is a distribution question,
  not a rendering one.
- **A Report is about one engagement.** Multi-engagement reporting is a portfolio question with no
  requester.

## 9. Spec touchpoints (applied by the implementation tickets)

- **`cmd/styx`** — `report` and `view` subcommands; usage text; exit codes `0/1/2` (§5.3, §6.1).
- **`internal/report`** (new, pure) — `Render(snap engagementstate.Snapshot, eng *engagement.Engagement) ([]byte, error)`:
  §3.1's shape, §3.3's ordering and resolution, §3.4's secret exclusion, §3.5's route derivation,
  §3.6's determinism, §4's counts. No I/O, no clock, no store access — which is what makes
  byte-identical output testable.
- **`internal/transcript`** (new) — the extracted committer of §7, consumed by `internal/tui` and by
  the viewer.
- **`internal/app`** — engagement resolution, read-only store load, atomic write, the stderr receipt
  (§5.2, §5.3).
- **`internal/findingsexport`** — `Reportable` is imported, never re-implemented; the Report and the
  export share one predicate.
- **Tests** — a golden Report from a fixture store and engagement file; two renders byte-identical; a
  store holding a known credential secret renders no secret; dangling refs named; omitted counts;
  `--engagement` resolution for zero/one/several candidates; write failure leaves the previous report
  intact; a viewer fixture renders the recorded transcript; a malformed line continues; an unknown
  kind is skipped; an unknown session id exits `1`.

## 10. Explicitly not in this design

HTML reports · a JSON or SARIF *Report* (the export is the machine record; SARIF stays its job) ·
report diffing across revisions · bundling evidence artifacts into the report · remediation prose
generated by the harness · report templates or per-engagement styling · `--report` on a headless run
· automatic report generation at session end · an interactive viewer, its own pager, or filters ·
viewing the audit JSONL · a `/view` TUI command · child-session navigation (item 14,
[#151](https://github.com/mobley-trent/styx-agent/issues/151)) · exporting engagement state
wholesale · any credential value in any artifact.
