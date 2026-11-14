# styx — child runs

Decided by [#151 Design the child-session UX](https://github.com/mobley-trent/styx-agent/issues/151)
(child of the map [Wayfinder: v1.3 reach & provider designs](https://github.com/mobley-trent/styx-agent/issues/144)),
delivering [`docs/red-team-roadmap.md`](red-team-roadmap.md) §1 item 14. Keystone rationale:
[`docs/adr/0021-a-child-run-is-an-address-in-its-parents-log.md`](adr/0021-a-child-run-is-an-address-in-its-parents-log.md)
— why a run is a slice of its parent's log and never a session of its own.

This document decides **what makes a subagent run an inspectable session: how it is identified, how
it is found, what a run shows, and how it relates to the run viewer**. It does not decide the live
rendering of a running block (spec §9.5, [`docs/specialist-subagents.md`](specialist-subagents.md)
§5.3), the session JSONL's schema beyond the additive notes in §12, `/resume`'s conversation rebuild
(spec §10.1), or depth two (`docs/specialist-subagents.md` §7).

## 1. Scope

Item 14 asks for subagent runs "exposed as inspectable sessions". The ticket asks four things, and
§2–§5 answer them in that order: identity, discovery, live-versus-final, and the relationship to the
viewer. §6–§8 are their consequences, §9 the output contract, §10 the naming, §11 what the
implementation must prove, §12 where it touches the spec.

Two boundaries are fixed before the details:

- **A run view is a view, never an authority.** Inspecting a run grants nothing, re-executes nothing,
  and never reaches the policy engine. Reading a session has never been a permission; this design
  adds no permission to read, and no exit code that gates anything (§9).
- **Nothing renders that isn't persisted** (spec §4.3). Every line a run view prints comes from that
  run's own persisted events — the same events the live block rendered — so a record cannot read
  differently depending on who is reading it.

## 2. Identity: an address, not a session

### 2.1 A run is already a slice of its parent's JSONL

Spec §10.1 defines one append-only session JSONL per session. A subagent run is already fully
recorded in it: `KindSubagent` brackets it (start carries the role, run id and brief; report or error
closes it; a gate transition closes it as cancelled), and every event the nested loop emits carries
that run's `subagent` and `run_id` (`internal/agent/loop.go` `emitEvent`). Nothing is missing from
the record — only an address and a way to print one slice.

**So a run gets no file, no session id, and no store of its own.** It is addressed as *(session, run
id)*, and every view in §5 is a filter over the parent's events. Four reasons, in order of weight:

- **One session = one JSONL is the storage contract**, and everything downstream assumes it: the
  `/resume` picker, the store's per-project naming, the audit pairing, the "crash-safe, inspectable"
  property. A second file per run would be a second writer appending to a log the parent is still
  writing, with its own open/close ordering to get wrong, for content the parent already holds.
- **A child file would need a parent pointer to be findable**, and a pointer whose only consumer is
  a tree is the first half of depth two — which [`docs/specialist-subagents.md`](specialist-subagents.md)
  §7 deliberately does not open. Charting a data relationship for a capability that is out of scope
  is how out-of-scope capabilities arrive by accident.
- **`/resume` never depended on it.** `agent.Conversation` already skips every event carrying a
  `subagent` attribution, so a worker's transcript is never replayed as the main agent's own. Resume
  coherence is a property of attribution, not of file layout.
- **One file is what "inspectable" means here.** The operator holds the session; the runs are inside
  it. Two files would let a run outlive or drift from the session that dispatched it, and neither is
  possible for a run that never had an existence of its own.

The cost, stated plainly: a parent log carries its children's transcripts, so a session that fanned
out four times is a bigger file. It is bounded by the 40-turn run bound and the four-run concurrency
cap, and it is the price of "one session, one record" — which is the property that makes the log
worth opening a month later.

### 2.2 The address

A run is named `<session> / <run-id>`, and `run_id` keeps the shape the dispatcher already mints:
`<role>-<n>` (`coder-1`, `critic-2`). Readable on a block header, sortable within a role, and already
in every persisted event.

### 2.3 Run ids are unique within a session, and that is a new requirement

Today `run_id` is unique within a **process**: `subagent.Runner.seq` starts at zero in every one. A
resumed session appends to the *same* file, so a session resumed once can hold two `coder-1` runs —
harmless while the id was only a fold key, and fatal now that it is an address.

**The runner is seeded from the log.** At `/resume` the harness already replays the session to build
the conversation; the same pass yields, per role, the highest `<n>` any persisted `KindSubagent` start
carries for that role, and that is the runner's starting sequence for the session. A fresh session
seeds at zero. Ids therefore read in order *across* resumes (`coder-1`, then `coder-2`) and a session
never reuses one, at no extra I/O: the replay is happening anyway.

- **No format change and no opaque ids.** The alternative fixes for uniqueness — a random suffix, a
  per-process epoch prefix — avoid the seeding and cost the legibility the live block header depends
  on (`▾ recon-2`), and would show two ids for one notion of "the second recon run".
- **A duplicate can still exist** in a hand-edited log or one written before this fix. Then `--run`
  refuses it rather than guessing: exit `1`, listing every match with its turn position and pointing
  at the parent view, where both print in order (§8). That is the same posture `styx report` takes
  toward several engagement files — an address that cannot be resolved to one thing is an error, not
  a choice.

### 2.4 What is deliberately not persisted

- **No parent-link field.** The session *is* the parent; a stored back-pointer to it is tautological
  until depth two exists, and §7 of the subagent design names the field that work would need.
- **No per-run state snapshot.** Engagement state is observations, lives outside the conversation,
  and has no per-run attribution (ADR-0004, `docs/engagement-state.md` §2). A run view will not
  invent one.
- **No per-run cost record.** `usage` events carry the run's `run_id` like any other event, so a
  run's tokens and cost fold from the log (§5).
- **No per-run report artifact.** The report is the closing bracket event's text, quoted.

## 3. What a run is made of

Four parts, each from events already persisted:

| Part | Source |
|---|---|
| **Brief** | the start event's `Text` — the `task` the dispatch call carried |
| **Transcript** | the run's inner events, in file order, through the shared writer (§7) |
| **Outcome** | the closing event: `Text` (report), `Failure` (error), or the cancellation detail |
| **Totals** | folded from the run's own `tool_call`, `usage` and bracket events (§5.4) |

The brief and the report are the two halves of the dispatch contract: the brief is what the
dispatcher asked for, and the report is the exact string the parent's `dispatch_subagent` tool result
carried. The parent's own `tool_call`/`tool_result` pair for that dispatch is therefore not reprinted
in a child view — the tool result duplicates the report by construction, and the brief duplicates the
call's task.

## 4. Discovery

An operator reaches a session's runs from the two places sessions are already reached:

- **`/resume`'s picker** gains a run count in each entry's detail line (`· 3 runs`). `sessions.List`
  already replays every session to build its summary, so the count costs a fold over events already
  in memory — a second replay pass would be the only thing that made this expensive, and it is not
  needed.
- **`styx view <session> --runs`** prints the run index: one row per run in start order (the order
  the live region opened its blocks), with run id, role, status, turns, refused count, and the
  brief's first line.

```
run          role       status      turns  refused  brief
coder-1      coder      reported     12       0     fix the failing parser test
recon-1      recon      reported      9       0     enumerate 10.0.0.0/24
critic-1     critic     cancelled     4       0     judge findings 1-3
```

**No `/runs` command and no picker nested under `/resume`.** Inside a live session the surface for a
running run is its block, and for a finished run the block already printed in full into scrollback
(§6); a TUI command would duplicate the viewer over content the terminal already shows. A nested
picker would also give `/resume` a second axis for a record that belongs to exactly one session —
the nesting depth this design's identity decision removed.

## 5. The child view: `styx view <session> --run <run-id>`

### 5.1 Shape

One fixed order, one `##` section per part, plain text (§9):

```
# Child run coder-2 — session 20261114T090102Z-1a2b

session 20261114T090102Z-1a2b · project styx-agent-4f2a · role coder · status reported
started 2026-11-14T09:04:11Z · closed 2026-11-14T09:06:02Z · 9 turns · 31 tool calls

## Brief
fix the failing parser test and report the root cause

## Transcript
… the run's events through the shared writer: assistant text, reasoning, tool calls with
their verdict and reason, tool results in full under the safety cap, diffs, plan blocks,
errors …

## Report
… the closing event's text, verbatim …

## Refusals
turn 3 · bash · hard-deny · roe
turn 7 · web_fetch · deny · no-operator

## Totals
tokens 41233 (cache 28904 hit / 12329 miss) · cost $0.09 · ran unasked 24 · operator-approved 5 · refused 2
```

### 5.2 Status, and the outcome section

`status` is one of `reported`, `failed`, `cancelled`, `incomplete`, and it decides the outcome
section's heading and content:

- **`reported`** — `## Report`, the text verbatim. Nothing is added to it: the report is the run's
  own words, and a view that annotated them would be a second author.
- **`failed`** — `## Failure`, the error text, plus the run's turn bound when the bound is what
  stopped it (the preset's 40 turns is worth knowing before reading a truncated transcript).
- **`cancelled`** — `## Cancelled` with the reason the gate transition recorded (`engagement
  deactivated`), so a run that stopped because the authorization changed is never mistaken for one
  that stopped because it finished ([`docs/specialist-subagents.md`](specialist-subagents.md) §6.3).
- **`incomplete`** — `## Incomplete`, naming what is missing: *no report, error, or cancellation
  after the start at 2026-11-14T09:04:11Z; the record ends here*. A crashed process, a killed
  terminal, or a session still running in another window all land here, and the view says which
  facts it does not have rather than implying the run is still going.

A `cancelled` and a `failed` run are different statuses, not one "did not finish": the first means
the authorization changed under it, the second means the run itself broke.

### 5.3 Refusals

`## Refusals` prints only when the run refused something, one line per refused call: turn, tool,
verdict, reason. It is a **recap of the transcript**, folded from the same `tool_call` events the
transcript already printed — never a second source, and never a summary that could disagree with the
lines above it.

It earns its own section because refusing is the specific thing an operator opens a *child* to check:
the parent's folded block is a report, and a report does not say "I was not allowed to". The reasons
are the engine's own closed set (`rule-match`, `out-of-scope`, `destructive`, `exploit-approval`) plus
the verdict's, and a non-interactive run's `no-operator` refusal reads exactly as it did live
([`docs/headless-ci.md`](headless-ci.md) §3).

The vocabulary is the audit's, because that is where a verdict is defined: `allow`, `allow-plan`,
`allow-once`, `allow-session`, `deny`, `hard-deny`. There is no persisted `prompt`: a prompt always
resolves to one of the two allow-once/session outcomes, to a deny, or to a turn abort — so a tally of
three categories (ran unasked, operator-approved, refused) accounts for every call that has one.

### 5.4 Totals

- **Turns** are the run's own loop counter. Every event carries `Turn`, but a child's counter is its
  own loop's, not the parent's — which is why every fold in this design keys on `run_id` and never on
  turn numbers alone.
- **Tokens and cost** fold from `usage` events carrying this `run_id`, with the cache hit/miss split
  the cost model uses (spec §3.1). The same rule as the session footer: the numbers come from the
  run's own events, not from a difference between parent totals.
- **No usage recorded** is printed when a run produced none (a cancelled run often will): a `$0.00`
  would be a claim about a run that never spent, not a fact about a run that never reported.

### 5.5 The findings block

A child view carries the same labelled findings block the session view carries — the engagement's
state at view time, with the reportable predicate shared with the export:

```
## Findings — engagement state at view time, revision 41
```

A run does not have findings of its own. State is the engagement's, it is not in the log, and a
per-run attribution would be invented by the viewer; the label is what keeps a reader from
attributing today's findings to that run. This is the one part of a child view that is not the run's
own record, and it is the same part, labelled the same way, in both scopes.

## 6. Live versus final

- **A running run is inspected in the live region, and nowhere else.** Spinner, preview line, Tab to
  expand, retired to scrollback (printed in full) the moment it closes — spec §9.5 and
  [`docs/specialist-subagents.md`](specialist-subagents.md) §5.3. This design changes none of it.
- **The viewer never tails.** No `--follow`, no streaming, no waiting on a live run. ADR-0001 made
  committed lines immutable and the live region the only mutable surface; a viewer that followed a
  file would be a second live region, which is the mistake ADR-0001 refused one layer out — the same
  reason the viewer has no pager and no interactivity ([`docs/reports-and-viewer.md`](reports-and-viewer.md)
  §6.1).
- **An unclosed bracket prints, and exits `0`.** The view succeeded; the run did not. Refusing to
  print would make a crashed session's last run unreadable exactly when someone opens the file, and
  the honest answer — a transcript that stops, labelled `incomplete` — is already available.
- **"Opening" a finished run inside the TUI is scrolling back.** The block printed in full at close,
  so its detail is reached by printing more, not by a keybinding. The child view exists for what the
  TUI cannot serve: last week's session, a headless run's log, a JSONL copied off a machine, or one
  run pulled out of a session too long to scroll.

## 7. One renderer, two scopes

[`docs/reports-and-viewer.md`](reports-and-viewer.md) §7 extracted `internal/transcript` so the live
transcript and a replayed one cannot drift. Child runs do not get a second renderer:

- **The run view is that writer with a run header and a run footer** — the brief, the transcript, the
  outcome, the refusals, the totals — and the same labelled findings block (§5.5). Its body is a
  filter over the parent's events by `run_id`, not a new rendering.
- **The parent's plain view prints each run's slice at its closing event**, in full, rather than
  interleaving each inner event as it falls in the file. With four concurrent runs the file interleaves
  two or three transcripts line by line; printing them as they fall would produce a stream no reader —
  and no diff — can follow, and it would break the acceptance test the viewer design already states:
  replaying a fixture through the plain writer prints what the TUI printed live. The TUI printed the
  block at close, so the plain view prints it at close, whole.
- **A run still open when the file ends** prints at the end of the parent's view, marked `incomplete`,
  for the same reason the child view does (§5.2): the bytes that exist are shown, and the missing
  close is named.
- **Nothing is collapsed and no line is dropped.** Every child line the file holds appears exactly
  once, in the order a reader saw it live.

## 8. Failure and edge cases

- **Unknown session** — unchanged: exit `1`, listing the ids that do exist.
- **Unknown run id** — exit `1`, listing the session's run ids.
- **Ambiguous run id** — exit `1`, listing every match with its turn position and naming the parent
  view as where both print (§2.3).
- **`--runs` on a session with none** — prints `no child runs`, exit `0`. A session that dispatched no
  run is a fact, not a failure.
- **`--runs` and `--run` together** — usage error, exit `2`.
- **`--run` against a file path** — works: `.jsonl`/separator resolution happens first, exactly as the
  viewer contract already defines it, and the run selection applies after resolution.
- **A damaged line inside the slice** — the existing viewer behaviour: `! unreadable record at line N:
  <reason>`, and reading continues.
- **A start with no inner events** — brief plus `## Incomplete`. A run that died before its first turn
  is still a run that existed.
- **A closing event with no start** (a damaged or hand-edited log) — not addressable, so it never
  appears in the index; in the parent view it prints at its file position as an attributed line with a
  one-line note that its start is missing. Nothing is silently swallowed.
- **A headless (`-n`) session** — no special case: engagement mode may fan out (ADR-0016), the events
  are the same events, and the view reads the same file.
- **A cancelled run** — `status cancelled` with its reason; its transcript stops where the
  cancellation did, and it produces no state write after the transition by construction
  (`docs/specialist-subagents.md` §6.3).

## 9. Output contract

- **Plain text on stdout, no ANSI**, LF line endings, trailing newline; nothing on stderr for a
  successful view. A view whose output depended on a TTY could not be grepped, diffed, or pasted into
  a ticket.
- **No wall clock.** Every timestamp printed is an event's own time. Two views of one file are
  byte-identical, so a diff between two views means the record changed and nothing else.
- **Exit codes:** `0` the view printed — including for a `failed`, `cancelled`, or `incomplete` run,
  because the run's outcome is content, not the command's status; `1` resolution or render failure;
  `2` usage.
- **No gate and no `3`/`4`.** Inspecting a run is not an assertion about the engagement, and a viewer
  that failed a pipeline would be gating on the presence of a refusal. Gating is `--fail-on`'s job
  ([`docs/headless-ci.md`](headless-ci.md) §8).

## 10. Naming

Roadmap item 14 calls this "child-session UX". This design calls the thing a **child run** and the
glossary gains the term, because the decision in §2 makes the roadmap's name a misnomer: a run has no
session id, no file, and no resume. Calling it a child session would give "session" a second meaning
in the one document an implementer reads to learn what a session is — and the definition would have to
spend a paragraph explaining why the child session is not a session. The roadmap item keeps its
original name where it is cited, so the trail from the capability gap to this design stays continuous.

## 11. Verification (what the implementation must prove)

- **Address uniqueness** — a resumed session that dispatches a run mints an id above every persisted
  run of that role; a fresh session starts at `1`; two identical `coder-1` in one fixture are refused
  by name, with both turn positions listed.
- **Index** — a fixture with three runs prints three rows in start order with status, turns, refused
  count and brief; a session with no runs prints `no child runs` and exits `0`.
- **One run, four outcomes** — `reported`, `failed`, `cancelled`, `incomplete` each produce their own
  heading and content; the report prints verbatim; a refused run's recap count equals the deny lines
  in its own transcript.
- **Totals isolation** — a run's tokens and cost fold only from `usage` events carrying its `run_id`;
  a second run's usage never leaks in; a run with no usage says so instead of printing zero.
- **Interleaving** — a fixture with two concurrent runs whose events interleave prints each block
  whole at its close, in close order, and prints every child line exactly once.
- **No tail** — a file whose final bracket is open prints `incomplete` and terminates; no waiting, no
  partial line buffering.
- **Renderer parity** — the parent view of a fixture equals what the TUI printed live for it (the
  existing acceptance test, extended to child blocks), and a child view of the same fixture equals the
  matching block.
- **Secrets** — a fixture whose run touched a credential renders no secret value: the child view is
  the same writer, and inherits the exclusion
  ([`docs/reports-and-viewer.md`](reports-and-viewer.md) §3.4).
- **Determinism** — two views of one file are byte-identical.

## 12. Spec touchpoints (applied by the implementation tickets)

- **§10.1** — additive notes only: `run_id` is an address within a session; a cancellation detail
  joins start/report/error on the subagent bracket; no new event kind, no new file, no parent-link
  field.
- **§4.2** — a run id is unique within its session, and the dispatcher's sequence is seeded from the
  session's replayed log at resume.
- **§9.5** — unchanged: the live region keeps rendering a running block, Tab included.
- **`cmd/styx`** — `view --runs`, `view --run <id>`; usage text; exit codes `0/1/2` (§9).
- **`internal/sessions`** — `Summary.RunCount` for the picker, and a pure run-index derivation over
  persisted events (index, one run's slice, status, refusals, totals).
- **`internal/agent/subagent`** — the `Runner`'s per-role starting sequence, supplied by the caller
  from its resume replay.
- **`internal/transcript`** — the session writer and the run writer over one implementation; a run's
  slice grouped at its closing event in the session scope.
- **`internal/app`** — resume seeds the runner; the `/resume` picker detail line.

## 13. Explicitly not in this design

A file per run · a parent-link field or a run tree · depth two (`docs/specialist-subagents.md` §7) ·
`--follow` or any live tail · a `/runs` TUI command or a picker nested under `/resume` · resuming
*into* a child run · replaying a child's transcript into the main conversation · cross-session or
project-wide run search · exporting a run to its own artifact · per-run state snapshots or diffs · a
per-run report · HTML or JSON output · any change to the policy gate or the audit trail · any new
permission to read a session.
