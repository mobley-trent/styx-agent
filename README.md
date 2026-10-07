```
 .d8888b. 88888888888 Y88b   d88P Y88b   d88P            d8888  .d8888b.  8888888888 888b    888 88888888888
d88P  Y88b    888      Y88b d88P   Y88b d88P            d88888 d88P  Y88b 888        8888b   888     888
Y88b.         888       Y88o88P     Y88o88P            d88P888 888    888 888        88888b  888     888
 "Y888b.      888        Y888P       Y888P            d88P 888 888        8888888    888Y88b 888     888
    "Y88b.    888         888        d888b           d88P  888 888  88888 888        888 Y88b888     888
      "888    888         888       d88888b  888888 d88P   888 888    888 888        888  Y88888     888
Y88b  d88P    888         888      d88P Y88b       d8888888888 Y88b  d88P 888        888   Y8888     888
 "Y8888P"     888         888     d88P   Y88b     d88P     888  "Y8888P88 8888888888 888    Y888     888
```
# styx-agent

`styx` — a terminal agent harness for coding plus red-team, reverse-
engineering, and blue-team work, with harness-enforced dual-mode safety.
The model is untrusted; the Go harness mediates everything: one policy
engine, one agent loop, container-isolated execution.

**Status:** pre-alpha (v0.1.1). The harness runs end to end: one hand-rolled
agent loop with a byte-stable system prompt and bounded turn and
parallel-dispatch caps, and one policy engine as the allow/prompt/deny choke
point, with an audit write on every call. Built-in tools cover file
manipulation (`read_file`, `write_file`, `edit_file`, `glob`, `grep`),
container-isolated exec (`bash`, `code_exec`), network fetch, plan approval,
subagent dispatch, and agent skills; external capabilities arrive through the
same gate as per-project MCP servers over stdio, becoming ordinary audited
descriptors regardless of server-side strictness. Dual-mode safety is enforced
by the harness: safe mode by default, engagement mode unlocked through the
strict engagement gate (scope pins and rules of engagement). The four built-in
skill packs (coding, red team, reverse engineering, blue team) and `SKILL.md`
agent skills extend the workflow surface. The streaming TUI renders inline
diffs with per-diff accept/reject and accept-all-rest-of-turn, keyboard-first
permission cards, plan approval, a status bar, dark/light themes, slash
commands, and cost tracking; sessions persist as append-only JSONL with
`/resume`, context compaction, and `STYX.md` project memory. See
[docs/spec.md](docs/spec.md) for the buildable spec and [GLOSSARY.md](GLOSSARY.md)
for the domain glossary.

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
- `internal/app` — startup wiring: config load, engagement gate, TUI boot
- `internal/agent` — the single hand-rolled agent loop (`internal/agent/subagent` holds the dispatch engine)
- `internal/model` — the single wire seam to the provider (`internal/model/repair` validates tool-call arguments)
- `internal/policy` — the pure policy engine, the safety choke point
- `internal/diff` — the pure line diff behind write/edit review
- `internal/engagement` — engagement file load/validate, scope pins, DNS pinning
- `internal/containerlayer` — the only package touching the host network stack
- `internal/mcpclient` — MCP servers over stdio: discovery, calls, lifecycle
- `internal/tui` — the Bubble Tea program: stream, status bar, prompt cards, blocks
- `internal/sessions` — append-only session JSONL store and resume
- `internal/memory` — `STYX.md` project memory
- `internal/skills` — `SKILL.md` discovery across global and project roots
- `internal/skillpacks` — the four built-in packs: prompt sections, allowlist deltas
- `internal/config` — global + project YAML merge, env secrets, defaults
- `internal/audit` — the fail-closed session audit JSONL writer
- `internal/update` — release-latest check and per-source upgrade hint

Storage: per-session JSONL under `~/.local/share/styx/sessions/<project>/`, the
audit trail (`styx-audit-<timestamp>.jsonl`) in the project directory, and
project memory in `STYX.md`.

## Install

Blessed surfaces ([docs/spec.md §12](docs/spec.md)):

- **macOS 13+ — Homebrew tap:**
  ```sh
  brew install mobley-trent/styx/styx
  ```
- **Linux — install script** (picks the architecture, verifies the archive
  against the published `SHA256SUMS`, installs to `~/.local/bin`):
  ```sh
  curl -fsSL https://raw.githubusercontent.com/mobley-trent/styx-agent/main/install.sh | sh
  ```

Release archives carry `SHA256SUMS` signed with **keyless cosign** (`cosign
sign-blob`, GitHub Actions OIDC). The install script verifies the checksum
automatically; for a manual download, verify the signature first:

```sh
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/mobley-trent/styx-agent/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS
```

`go install github.com/mobley-trent/styx-agent/cmd/styx@latest`, Linuxbrew, and
unpacking a release archive by hand all work but are unsupported.

## Updates

**There is no self-updater, ever** — a security harness never rewrites its own
binary mid-flight.

```sh
styx update   # prints the latest release and your detected install source
```

The TUI update notifier makes a **single** request to the GitHub
releases-latest endpoint per session and prints a one-line notice when a newer
stable release exists. It never installs anything. Opt out with
`update_notifier: false` in config or `STYX_NO_UPDATE_NOTIFIER=1` in the
environment; it is disabled automatically for source builds and while
engagement mode is active.

## Changelog & releasing

User-visible changes are recorded in [CHANGELOG.md](CHANGELOG.md). The release
process — `make release VERSION=vX.Y.Z`, which tags and publishes through the
release workflow — is documented in [RELEASING.md](RELEASING.md). The GitHub
Release body is taken from the changelog section for the tag.

## Compatibility

- **Sessions and config are same-major compatible.** Session JSONL and YAML
  config are read with unknown kinds/keys tolerated; new fields are additive.
  Upgrading within a major version never strands history or refuses an old
  config.
- **The engagement file is versioned** with `apiVersion: styx.engagement/v1`,
  validated at the engagement gate; an unknown version refuses to start rather
  than run with an ambiguous scope.
- Channels are **stable SemVer tags only** — no nightly or beta builds.

## License

Apache-2.0. See [LICENSE](LICENSE).
