# styx-agent

`styx` — a terminal agent harness for coding plus red-team, reverse-
engineering, and blue-team work, with harness-enforced dual-mode safety.
The model is untrusted; the Go harness mediates everything: one policy
engine, one agent loop, container-isolated execution.

**Status:** pre-alpha. The tracer bullet runs end to end ([issue #22]); the
coding co-pilot interaction lands on top of it ([issue #23]): `glob` and `grep`
orient in the repo, `write_file` and `edit_file` stage inline diffs with
per-diff accept/reject and accept-all-rest-of-turn, permission prompts render
as inline keyboard-first cards (allow-once / allow-this-session / deny), and an
approved plan pre-authorizes its listed actions for the turn — never overriding
hard denies, ROE limits, or scope checks. Every tool call still runs the full
normative order — schema validation → policy verdict → audit write → dispatch →
truncated result → model. Sessions persist as append-only JSONL with `/resume`;
global and project config merge; turn and parallel-dispatch caps are enforced.
Containers, subagents, skills, MCP, and the full TUI land in subsequent tickets.
See [docs/spec.md](docs/spec.md) for the buildable spec and
[CONTEXT.md](CONTEXT.md) for the domain glossary.

## Build

Requires Go 1.26+ (Charm's Bubble Tea v2 requires it).

```sh
make check              # the full CI gate: build, vet, lint, test
make build              # build the styx binary
./styx --help           # usage
DEEPSEEK_API_KEY=... ./styx   # run in a repo (safe mode by default)
```

Secrets are environment-only: `DEEPSEEK_API_KEY` is read from the environment
and never written to disk or into model context. `styx --engagement <file>`
activates engagement mode through the engagement gate; without it, safe mode
is the default.

## Layout

The package layout and per-package boundary rules are specified in
[docs/spec.md §2](docs/spec.md) and documented in each package's doc
comment. Headlines:

- `cmd/styx` — the CLI entry point (`styx`)
- `internal/app` — startup wiring: config, engagement gate, TUI boot
- `internal/agent` — the single hand-rolled agent loop
- `internal/policy` — the pure policy engine, the safety choke point
- `internal/diff` — the pure line diff behind write/edit review
- `internal/model` — the single wire seam to the model provider
- `internal/containerlayer` — the only package touching the host network stack

Storage: per-session JSONL under `~/.local/share/styx/sessions/<project>/`, the
audit trail (`styx-audit-<timestamp>.jsonl`) in the project directory, and
project memory in `STYX.md`.

## License

Apache-2.0.

[issue #22]: https://github.com/mobley-trent/styx-agent/issues/22
[issue #23]: https://github.com/mobley-trent/styx-agent/issues/23
