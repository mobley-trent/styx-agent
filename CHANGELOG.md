# Changelog

All notable changes to styx are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are cut from stable tags only; there are no nightly or beta channels.
How a release is made — and how the GitHub Release notes are taken from this
file — is documented in [RELEASING.md](RELEASING.md).

## [Unreleased]

## [v0.2.1] - 2026-10-07

### Changed

- The STYX AGENT wordmark is a new design, and the startup banner now renders
  on terminals at least 96 columns wide (down from 109); narrower terminals
  still skip it rather than wrap or truncate. The README logo is the same art.

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
