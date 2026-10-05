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
truncated result → model. External capabilities arrive through the same gate:
per-project MCP servers are launched over stdio and their tools become ordinary
descriptors — validated by the harness regardless of server-side strictness,
resolved by the same policy engine, and audited like built-ins, with connection
lifecycle (ready / failed / disconnected) surfaced in the stream and the status
line. Sessions persist as append-only JSONL with `/resume`; global and project
config merge; turn and parallel-dispatch caps are enforced. Skills, skill packs,
and the full TUI land in subsequent tickets. See [docs/spec.md](docs/spec.md)
for the buildable spec and [CONTEXT.md](CONTEXT.md) for the domain glossary.

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
- `internal/mcpclient` — MCP servers over stdio: discovery, calls, lifecycle
- `internal/containerlayer` — the only package touching the host network stack

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

[issue #22]: https://github.com/mobley-trent/styx-agent/issues/22
[issue #23]: https://github.com/mobley-trent/styx-agent/issues/23
