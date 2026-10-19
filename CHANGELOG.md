# Changelog

All notable changes to styx are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are cut from stable tags only; there are no nightly or beta channels.
How a release is made — and how the GitHub Release notes are taken from this
file — is documented in [RELEASING.md](RELEASING.md).

## [Unreleased]

### Changed

- The TUI builds against Bubble Tea v2.1.0. Earlier v2 releases left the rows a
  shrinking live region gave up as stale text on screen, which the new command
  menu and pickers would show on every keystroke; v2.1.0 clears them.

### Added

- Parser tools: the six artifacts a red team actually produces — nmap XML, nuclei JSONL,
  sqlmap logs, gobuster output, CrackMapExec/NetExec logs, and BloodHound collector JSON —
  are read by harness-side tools (`nmap_parse`, `nuclei_parse`, `sqlmap_parse`,
  `gobuster_parse`, `cme_parse`, `bloodhound_parse`) into engagement state: one extractor
  per format, one atomic op batch, one receipt, with skipped records reported and never
  guessed. A parse cannot take the scanner's word for it — an open port is a fact, not a
  finding, and no parse escalates status or verification. Scanner output lands in
  `.styx/out/`, which activation creates and gitignores, and the harness notices what
  nobody parsed: argv sniffing plus an artifact watch put a
  `pending parse: <artifact> → <parser>` directive in the state digest and a count in the
  status bar, a nudge and never a block. Denied in safe mode, allowed and audited in
  engagement mode, and available to every subagent preset. (#80)
- Engagement state: a per-engagement record of what was observed — hosts,
  services, credentials, access, segments, findings, and the typed relationship
  graph over them — kept as one schema-versioned JSON document outside the
  conversation, written atomically under a pid-checked lock. The model reaches
  it through two audited tools, `state_query` and `state_update`, whose typed
  ops are the only write path, so provenance is harness-stamped and a finding
  cannot be verified before it has evidence. Because the record lives on disk,
  compaction can never touch it; a digest of it is appended to the prompt when
  state changes, and the engagement-end notes in STYX.md are generated from it.
  Both tools are denied in safe mode, where there is no store to touch, and
  allowed and audited in engagement mode. (#78)
- Model reasoning prints dimmed inline as part of the transcript: thinking
  streams above the answer while a turn runs, commits to the scrollback ahead
  of the answer it explains, and stays visually distinct from both answers and
  tool output. A subagent's reasoning prints dimmed inside its block the same
  way. (#72)
- Typing `/` opens an inline command menu over the harness's command registry:
  it filters as you type, up/down move the selection, Tab completes the command
  name, and Enter runs the highlighted command. `/model`, `/resume`, and `/theme`
  now open a modal picker instead of printing a list to type an id from, and
  `/help` is generated from the same registry, so a new command is documented,
  listed, and offered a picker from one declaration. `/theme` chooses the dark
  or light scheme or hands the choice back to the terminal background. (#71)
- The input line is a real editor: the cursor moves and edits mid-line, word
  navigation and selection follow the usual readline keys, and up/down recall
  previous prompts (the draft in progress is restored on the way back down).
  Live prompt cards stay modal, so an open card never moves the cursor. (#67)
- `Escape` aborts the turn in flight and returns the prompt without leaving
  styx; the interrupted turn prints as an abort and stays resumable, and its
  partial answer is kept in the scrollback. While nothing is running, `Escape`
  clears the input line. `ctrl-c`/`ctrl-d` still quit. (#68)
- Assistant answers print as formatted markdown: headings, lists, tables, inline
  code, fenced blocks, and links render in scrollback, tinted from the dark or
  light theme in force. Text still streams raw while a turn is in flight; the
  committed line is the rendered form. Subagent answers render the same way
  inside their block. (#69)
- Tool results, diffs, and subagent transcripts print in full into the
  scrollback instead of stopping at 20 lines with no path to the rest; a
  finished subagent block always prints its whole transcript, while a
  still-running one shows its recent tail in the live region. A pathological
  output (a multi-megabyte read, say) elides behind a marker that points at the
  session log, so one call cannot flood the terminal. (#70)

## [v0.2.1] - 2026-10-07

### Changed

- The STYX AGENT wordmark is a new design, and the startup banner now renders
  on terminals at least 96 columns wide (down from 109); narrower terminals
  still skip it rather than wrap or truncate. The README logo is the same art.
- The TUI prints committed transcript lines once into the terminal's own
  scrollback and keeps only a fixed bottom live region, rather than retaining
  an alternate screen with a height-trimmed transcript: native scrollback and
  search work again, `/clear` drops the model context without rewriting what
  has already printed, and a still-live subagent block stays animated in the
  live region until its run ends and commits. (#84)
- `allow-session` now grants the tool for the rest of the session instead of
  only the parameters that prompted; an out-of-scope target or a destructive
  call still prompts on every attempt. (#85)
- `/skills` is a pure listing: it no longer advertises `/<skill-name>`
  invocation and the matching `/help` line is gone (invocation still works).
  (#85)

### Fixed

- A tall committed block (for example the `/skills` listing) could leave its
  overflow as blank scrollback, because the print-above path cannot insert
  more lines than the screen height; committed lines now print in chunks
  bounded by the terminal. (#85)

## [v0.2.0] - 2026-10-06

### Added

- The STYX AGENT startup wordmark, tinted with the active theme and stamped with
  the running version, rendered once at the top of the initial transcript on
  terminals at least 109 columns wide (narrower terminals skip it rather than
  wrap or truncate). (#64)

### Changed

- The harness now starts without a reachable model provider. A missing
  `DEEPSEEK_API_KEY` or a model the provider does not serve no longer refuses
  startup: the failure surfaces at its point of use as a recoverable turn error,
  the status bar shows a degraded marker, and a later prompt retries — so a
  transient outage or a corrected credential recovers without a restart.
  Safety-critical refusals (invalid config, a refused or stale engagement file)
  stay fatal at startup. (#55)

### Fixed

- `/quit` and `/exit` were a no-op in the TUI: they set the quit flag but never
  emitted the Bubble Tea quit message, so the program ran on. Both now exit
  exactly as ctrl-c does. (#62)

## [v0.1.1] - 2026-10-05

### Fixed

- The `skill` tool declared its free-form arguments as a bare object, which
  DeepSeek strict mode rejects outright (`An object with no properties is not
  allowed`). Because the tool is sent on every request, every turn failed with
  `400 Bad Request` whenever any model-invocable skill was discovered. The
  arguments are now carried as a JSON object string (`args_json`), matching
  `propose_plan`'s `params_json`, and decoded by the handler. (#51)

## [v0.1.0] - 2026-10-05

Initial pre-alpha release: the tracer-bullet harness runs end to end.

### Added

- One hand-rolled agent loop with a byte-stable system prompt, a bounded turn
  cap, and parallel-dispatch caps.
- The policy engine: the single allow/prompt/deny choke point, a project rule
  overlay, and an audit write on every call.
- Built-in tools: `read_file`, `write_file`, `edit_file`, `glob`, `grep`,
  `bash`, `code_exec`, `web_fetch`, `ssh_logs`, `propose_plan`,
  `dispatch_subagent`, and the `skill` tool.
- Dual-mode safety: safe mode by default; engagement mode unlocked through the
  strict engagement gate (scope pins and rules of engagement).
- Container-isolated exec with host-edge egress enforcement and a visible
  degraded-isolation fallback.
- MCP servers over stdio, exposed as ordinary audited tool descriptors.
- Skill packs (coding, red team, reverse engineering, blue team) and SKILL.md
  agent skills.
- Streaming TUI: inline diffs with per-diff accept/reject, permission cards, plan
  approval, a status bar, themes, sessions with `/resume`, context compaction,
  and cost tracking.
- Persistence: session JSONL logs, the audit trail, and STYX.md project memory.
- Distribution: goreleaser Linux/macOS archives with keyless-cosign-signed
  `SHA256SUMS`, a Homebrew tap, and a Linux install script.

[Unreleased]: https://github.com/mobley-trent/styx-agent/compare/v0.2.1...HEAD
[v0.2.1]: https://github.com/mobley-trent/styx-agent/releases/tag/v0.2.1
[v0.2.0]: https://github.com/mobley-trent/styx-agent/releases/tag/v0.2.0
[v0.1.1]: https://github.com/mobley-trent/styx-agent/releases/tag/v0.1.1
[v0.1.0]: https://github.com/mobley-trent/styx-agent/releases/tag/v0.1.0
