# styx — the non-interactive run

Decided by [#113 Decide the non-interactive run](https://github.com/mobley-trent/styx-agent/issues/113)
(child of the map [Wayfinder: styx prototype → adoptable red-team agent](https://github.com/mobley-trent/styx-agent/issues/53)),
delivering the `-n/--non-interactive` half of the roadmap's headless/CI capability
([`docs/red-team-roadmap.md`](red-team-roadmap.md) §1, item 5).
Keystone rationale: [`docs/adr/0007-non-interactive-runs-never-widen.md`](adr/0007-non-interactive-runs-never-widen.md).

The rest of that CI surface is decided beside this document and is deliberately **not** repeated
here: the machine-readable findings artifact ([#114](https://github.com/mobley-trent/styx-agent/issues/114)),
the severity gate and its exit codes ([#115](https://github.com/mobley-trent/styx-agent/issues/115)),
diff scoping ([#116](https://github.com/mobley-trent/styx-agent/issues/116)), the USD budget cap
([#117](https://github.com/mobley-trent/styx-agent/issues/117)), and the offensive sandbox image
([#118](https://github.com/mobley-trent/styx-agent/issues/118)).

## 1. Scope

Every styx run so far has one safety story: a human at the prompt. `-n` removes that human, so one
question needs answering — **what is a run with no terminal and no operator?**

Four things must be decided for it, and only these: where the task comes from (§2), what a
promptable verdict resolves to (§3–§4), what reaches the operator's pipes (§6), and how the run
ends (§7). Nothing here changes a rule, a scope check, an ROE limit, or an audit stamp: a headless
run's verdicts are the same verdicts, computed by the same engine.

Two boundaries are fixed before the details:

- **`-n` is a transport, not a mode.** Safe mode stays safe mode; engagement mode stays engagement
  mode. No preset widens because a flag was passed.
- **Headless never widens.** It only honours authorizations a human already wrote down
  (ADR-0007).

## 2. The run's shape

`styx -n "<task>"` — one task, one turn, no terminal.

| Property | Interactive | `-n` |
|---|---|---|
| Task source | the input line, repeatedly | one positional argument, once |
| Turns | as many as the operator submits | exactly one (§2.1) |
| Command surface | `/help`, `/mode`, `/resume`, `/compact`, `/skills`, … | none |
| Prompt cards | inline, answered by the operator | answered by §3 |
| Renderer | the TUI's live region + scrollback | a line printer over the same event bus (§6) |
| End of run | ctrl-c / ctrl-d / `/quit` | the turn returns, or a signal (§7) |

The CLI surface today is `--engagement`, `--project`, `--version`, `--help`, and the `update`
command (`cmd/styx/main.go`). `-n` adds exactly one flag and one positional:

- **`-n` / `--non-interactive`** is a boolean, and the short form follows the `-h` precedent.
- **The task** is the single non-flag argument. Missing, or a second one, is a usage error (`2`) —
  never a terminal opened to ask.
- **With `-n`, a bare argument is always the task, never a command.** `styx -n "update"` runs the
  task `update`; `styx update -n` combines a command with a flag that cannot honour it and is a
  usage error, like `styx --version -n`.

### 2.1 One task, one turn

A headless run submits its task once and lets the loop run to completion — up to the existing turn
cap (200 internal model steps, `agent.DefaultMaxTurns`), which is where multi-step work belongs.
There is no second prompt, no stdin reader, and no queue:

- **stdin is never read.** A CI job that forgot to feed the process must not hang; a task file can
  wait for a real need.
- **A pipeline of tasks is a shell loop.** `for t in …; do styx -n "$t"; done` is honest about the
  fact that each is its own session, its own audit file, and its own exit status.
- **No command surface exists.** `/resume`, `/model`, `/clear`, and `/compact` are TUI affordances;
  anything a CI run needs must be a flag. Skills remain reachable through the model's `skill`
  tool, unchanged by `-n`.

### 2.2 `-n` is orthogonal, and its flags are not optional

Any flag that only makes sense headless — `--fail-on`, `--max-budget`, `--scope-mode diff`,
`--out` — is a **usage error (`2`) without `-n`**, never silently ignored. A CI-shaped flag on an
interactive run means the operator believes they are running CI while a human is still at the
prompt; refusing is the only honest answer. The reverse case needs no rule: the interactive surface
is `/commands`, and §2.1 removes it entirely.

`-n` neither requires nor refuses a terminal. Running it in an interactive shell is the supported
way to see exactly what CI will see.

## 3. With no operator, a prompt is a deny

The rule table's job is unchanged: `allow` and `deny` keep their verdicts, and the ROE hard limits
keep hard-denying. Only the promptable middle needs an answer, and there is exactly one that never
manufactures an authorization:

| Rule-table verdict | Interactive | `-n` |
|---|---|---|
| `allow` | runs | runs |
| `prompt` | operator card | **denied** |
| `deny` | denied | denied |
| `hard-deny` (ROE) | denied | denied |

Rules:

- **A prompt never becomes an allow.** Not by the flag, not by a preset, not by a "no human means
  nobody objects" reading. `ask` is the place a human is asked; with no human, nothing was asked
  and nothing was granted.
- **The denial is a tool result, not a run failure.** The model sees a denial exactly as it sees a
  human's deny, and the turn continues — it may find another route. A model must not be able to
  end a scheduled run by attempting one out-of-scope thing.
- **The audit distinguishes the two deny reasons.** The row stays `deny` (the verdict space is
  closed; `-n` adds no verdict), but a headless resolution carries the reason **`no-operator`**,
  never `out-of-scope` or `default-table`, so the forensic record says which silence refused it.
  The audit write still precedes execution and still fails closed.
- **Every denial is visible twice:** a line on stderr as it happens (§6), and a count in the end
  summary (§6.3). A partly-blocked run can never be mistaken for a clean one.
- **Subagents inherit it.** They share the operator seam, so a subagent's prompt is denied the
  same way and carries its attribution.

### 3.1 The two ways to widen, and no third

Authority comes from something a human reviewed before the run:

1. **The project config overlay** — `permissions.rules` (`.styx/config.yaml`, spec §6.1) may narrow
   defaults or widen prompts to allows for that project. It is committed and reviewable, and even
   it may never weaken an ROE hard limit or an engagement scope check.
2. **The engagement file** — an in-scope action in engagement mode is already auto-allowed and
  audit-logged (spec §6.2). No new rule; `-n` just stops the operator from being asked about
  anything else.

There is no `--yes`, no `--allow-prompted`, and no "CI preset" that flips prompt to allow. A flag
that blanket-grants the middle band is the one thing this decision exists to refuse.

**Consequence, stated plainly:** in safe mode writes, exec, and network are prompt-default, so a
bare `-n` run **reads, reasons, and reports — it cannot mutate the workspace.** Writing headless
requires a committed overlay rule or an engagement scope. That is the intended shape: read-only by
default, authority by prior written authorization.

## 4. The cards that are not the rule table

Two operator interactions sit beside the policy verdict, and both need a headless answer. Today
`Loop.run` sends **every** diff-class tool (anything with a preview) through the diff review
regardless of what the rule table said, so a blanket reject would deny writes the operator already
authorized.

### 4.1 Diff review: accept only what was already allowed

- The change is applied **iff the call's resolved policy verdict was `allow`** — an overlay rule
  or an in-scope engagement action. The human already authorized that class of change in a file
  they reviewed; the card is a content check, and its authorizer is absent, not its authorization.
- A call whose verdict was `prompt` was denied upstream and never stages a diff at all.
- A rejected diff prints `! rejected <path> (no operator)` and is not applied.

**Consequence:** with a bare `-n` in safe mode no file is modified, which is §3.1's consequence
arriving from the other direction.

### 4.2 Plan approval: never pre-authorized

A plan block asks the operator to pre-authorize its steps for one turn. Headless there is no
approver, so the plan is **never approved**: the planning step returns its proposal unapproved and
each step then faces the rule table on its own. That is the conservative direction — pre-authorization
only ever skips prompts, and headless has no prompts to skip.

## 5. Startup, refusals, engagement mode

### 5.1 Fail on demand is unchanged

`-n` adds **no provider preflight.** The single turn carries the provider check, exactly as an
interactive first turn does (spec §1, "fail on demand"): an unreachable provider or a missing key
fails that turn with its actionable error, and the run exits `1`. The identity line never claims
provider health it has not checked.

### 5.2 What stays fatal at startup

Unchanged, because it is the same `Build`: an unparseable config, a refused or stale or
unresolvable engagement file, a present-but-malformed `SKILL.md`, and an audit or session log that
cannot be opened (fail closed — a run does not proceed unlogged). Both logs live in the project
directory, so **a read-only project checkout refuses to start**; CI must give it a writable working
copy.

### 5.3 Engagement mode is usable headless, and is the intended CI shape

An engagement file plus `-n` is the shape the roadmap promises, so the parity has to be complete:

- **One door, the same gate.** `--engagement <file>` is the launch door; `/engagement` and `/mode`
  simply do not exist without a command line. This is not a weaker second door — the gate is a
  shared function, and the launch flag is one of its two existing callers.
- **Identical downstream.** Same strict validation, same hostname pinning, same egress rules, same
  audit stamps, same state digest, same pending-parse obligation, same policy engine. Nothing about
  a verdict or a stamp depends on whether a terminal exists.
- **Run end is engagement end.** Teardown appends the engagement-notes block to `STYX.md`, removes
  the scope summary and the egress allowlist, closes the state store and releases its lock — the
  same work `/mode safe` and session end already do (spec §7.3).

### 5.4 One run per engagement

The engagement state store takes a pid-checked write lock, and a second process on the same
engagement opens **read-only**: it can read, and every state write fails `ErrLocked`. For a CI
scan that is a run which exits successfully having recorded nothing — the worst outcome a pipeline
can be handed.

So under `-n`, an engagement-mode run that finds the lock held by another live session **refuses to
start** (`1`, before the container), naming the holder. Interactive keeps today's behaviour — it
reads, and the state digest says the state is locked, which a human can act on.

Safe-mode runs have no store, so parallel safe-mode runs are unaffected. So are runs in different
project directories, and runs against different engagements.

### 5.5 Nothing ambient phones home

The update notifier's single releases fetch is **off under `-n`** — it is already suppressed in
engagement mode, and a CI log has no use for an upgrade nag. `styx update` stays the explicit way
to ask.

## 6. Two streams, one bus

Headless attaches a line printer to the existing event sink (`Harness.setUI`) — the same seam the
TUI renders from, which is what keeps "nothing renders that is not also persisted" true for a pipe
as well. Nothing new is emitted; the run decides where each kind goes.

### 6.1 The split

| Where | What |
|---|---|
| **stdout** | the turn's assembled answer text, and nothing else |
| **stderr** | the identity line, operations, refusals, errors, the end summary |
| **disk only** | audit JSONL, session JSONL, engagement state, artifacts |

Rules:

- **stdout is the answer.** One stream for the model's final text means `styx -n "…" > report.md`
  is correct by construction, and a pipeline never has to strip decoration. No ANSI, no theme, no
  progress, no cursor control.
- **stderr is the transcript.** Tool calls and results, the isolation banner, denials, rejected
  diffs, subagent brackets, interrupts, errors, and the summary.
- **Nothing is printed that is not an event.** The wordmark banner is a TUI startup affordance and
  never prints headless; the update notice is off (§5.5); slash-command output does not exist.
- **Deltas are not printed.** `text_delta` and `reasoning_delta` are render-only by definition
  (spec §4.3) and a byte stream with no live region gains nothing from them; the assembled assistant
  text carries the same content at the end of the turn. A long turn is therefore **silent on
  stdout until it completes** — a CI log is read after the fact, not watched.
- **Reasoning is not printed either.** It stays in the session JSONL. Headless prints the audit
  trail, not the inner monologue.
- **Tool output prints in full up to the existing capture truncation** (spec §4.5), with its
  truncation marker. There is no live region, so nothing is collapsed or expandable later: the pipe
  is the pager, exactly as ADR-0001 makes the terminal's scrollback the pager interactively.

### 6.2 Line vocabulary

Four prefixes (and the un-prefixed answer), so a human `grep` and a test both have something
stable to key on:

| Prefix | Class | Example |
|---|---|---|
| *(none)* | the answer, on stdout | the model's final text |
| `styx: ` | the harness's own voice: identity, summary, fatal error | `styx: 0.3.1 · engagement acme-q4 · session 7f2a…` (safe mode reads `safe mode`) |
| `! ` | something refused, failed, or interrupted | `! deny bash (no operator: not permitted non-interactively)` |
| `> ` | an operation beginning | `> bash nmap -sV 10.0.0.0/24` |
| `  ` | the body of the previous operation | a tool result's first lines, a subagent's report |

Errors keep `main.go`'s existing `styx: `-prefixed convention, so a run's fatal error reads the way
every other styx failure already does.

### 6.3 The end summary

Four lines on stderr, on every exit path it can reach — the second signal's immediate exit is the
one exception:

```
styx: done — 3 turns
styx: usage 41,203 tokens · $0.0182
styx: denied 1 prompt (run not clean)
styx: session 7f2a19c4 (audit styx-audit-20261030T101500Z.jsonl)
```

- **Turns and usage** come from the session's own accounting (`KindUsage`), so the summary and the
  status bar never disagree.
- **The denial count is authoritative.** Zero means nothing was blocked; anything else means the run
  did not do all of what it was asked. It is repeated as `run not clean` precisely so a reader who
  never looks at the count still sees it.
- **The session id** is what makes the run resumable: `styx` then `/resume <id>` picks the session
  up interactively, and the audit filename is the forensic record.
- The summary is **human-readable only**. There is no `--json` run summary in v1.2 (§9).

## 7. How the run ends

There is no ctrl-c and no `/quit`, so the run needs its own end conditions.

| Event | Behaviour | Exit |
|---|---|---|
| The turn returns | normal end; summary printed | `0` |
| Turn returned an error (provider loss, loop failure) | `! <error>`, summary printed | `1` |
| Turn cap reached | `! turn cap reached (200 turns without a final answer)` | `1` |
| First `SIGINT` / `SIGTERM` | cancel the in-flight turn (the same cancel path Escape uses), `! interrupted`, flush and tear down | `1` |
| Second `SIGINT` / `SIGTERM` | immediate exit, no further cleanup | `1` |
| Container loss mid-run | per-tool failure, `! ` line, the run continues (degraded isolation was announced at start, spec §9.5) | unchanged |
| A denied prompt | not a failure — the turn continues (§3); the run reports it as not clean | not clean (code: #115) |

Rules:

- **A broken run never reports success.** If the turn errored, the exit is `1` even when text
  reached stdout, so a pipeline can never mistake a partial answer for a finished run.
- **Provider loss ends the turn and the run — it does not retry.** Fail-on-demand put the failure
  at its point of use; a headless run does not loop against a provider that is not answering.
- **Signals are a cancel, not a kill,** so the state store closes, its lock releases, and the
  engagement notes are appended — the same teardown a normal end gets.
- **The code space is untouched.** `2` stays a usage error, `1` a failed run, `0` a completed one.
  Whether the severity gate gets its own code, and what a not-clean run exits with, is
  [#115](https://github.com/mobley-trent/styx-agent/issues/115)'s decision — this document only
  requires that a blocked run be distinguishable from a clean one and from a broken one.

## 8. Spec touchpoints (applied by the implementation ticket)

- **`cmd/styx/main.go`** — parse `-n/--non-interactive` and the single positional task; document
  both in `usage`; keep `2` for usage errors and `1` for a failed run.
- **`internal/app`** — `Options` gains `NonInteractive bool` and `Task string`; `Run`'s existing
  `Runner` seam selects a headless printer instead of `runTUI`. No new wiring path: `Build` is
  shared, which is what makes §5.2 and §5.3 true without a second code path.
- **`internal/app`** — the headless runner installs the event sink (printer) and **no** prompt
  sink, so §3's denial is structural rather than a special case in the operator adapter.
- **`internal/policy`** — one new reason value, `no-operator`, for a prompt resolved with no
  operator attached. No new verdict, no new rule, no change to the decision function.
- **`internal/agent`** — an admission must carry its resolved verdict (it knows it at admit time
  and does not retain it today) so §4.1 can honour "accept iff allowed". Nothing else in the loop
  moves.
- **spec §9.1** — the TUI is one of two runners; the event bus is the interface both consume. Worth
  saying once in the spec, since it is what keeps a second renderer from forking behaviour.

## 9. Explicitly not in v1.2

The findings artifact and its path ([#114](https://github.com/mobley-trent/styx-agent/issues/114)) ·
the severity gate and the exit-code space
([#115](https://github.com/mobley-trent/styx-agent/issues/115)) · diff scoping
([#116](https://github.com/mobley-trent/styx-agent/issues/116)) · the USD budget cap
([#117](https://github.com/mobley-trent/styx-agent/issues/117)) · the sandbox image
([#118](https://github.com/mobley-trent/styx-agent/issues/118)) · a `-q`/`--verbose` level or a
`--json` summary (one verbosity, one human-readable summary) · reading tasks from stdin or a file ·
multi-task and multi-turn runs · a `--yes`/`--allow-prompted` flag (ADR-0007) · a CI preset that
widens the rule table · retry/backoff on provider loss · resume-in-place of a headless session (the
session id is printed so an interactive `/resume` can pick it up instead) · parallel runs against one
engagement store (§5.4) · a `styx view`-class log renderer (v1.3's run viewer) · Windows conventions
for signals (out of platform scope, spec §13).
