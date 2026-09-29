# styx-agent

`styx` — a terminal agent harness for coding plus red-team, reverse-
engineering, and blue-team work, with harness-enforced dual-mode safety.
The model is untrusted; the Go harness mediates everything: one policy
engine, one agent loop, container-isolated execution.

**Status:** pre-alpha scaffold ([issue #18]). The module skeleton and CI
gate exist; the agent loop, policy engine, TUI, and tooling land in
subsequent tickets. See [docs/spec.md](docs/spec.md) for the buildable
spec and [CONTEXT.md](CONTEXT.md) for the domain glossary.

## Build

Requires Go 1.24+.

```sh
go build ./...          # build the module
go build ./cmd/styx     # build the styx binary
./styx --help           # usage
go test -race ./...     # tests
```

## Layout

The package layout and per-package boundary rules are specified in
[docs/spec.md §2](docs/spec.md) and documented in each package's doc
comment. Headlines:

- `cmd/styx` — the CLI entry point (`styx`)
- `internal/policy` — the pure policy engine, the safety choke point
- `internal/model` — the single wire seam to the model provider
- `internal/containerlayer` — the only package touching the host network stack

## License

Apache-2.0.
