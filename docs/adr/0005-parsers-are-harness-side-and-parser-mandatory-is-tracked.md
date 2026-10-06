# Parser tools run harness-side, and parser-mandatory is tracked rather than hard-blocked

The v1.1 parser tools (`docs/parser-tool-contracts.md`, #75) turn raw scanner output into
engagement-state writes. Two choices here would surprise a future reader, and both were
real trade-offs. **First,** the parsers execute **harness-side**, reading a workspace file,
not inside the session container: the parser is the trust boundary that transforms
untrusted scanner bytes into typed state, so it must not live on the untrusted side, and
parsing needs no container. The raw CLI still runs in the container and the artifact
round-trips through the shared `/workspace`. **Second,** the *parser-mandatory-after-CLI*
invariant is **tracked and surfaced, never a hard block**: the harness detects scanner runs
and unparsed artifacts and surfaces a pending-parse obligation in the state digest, but the
loop never refuses further actions. Hard-blocking would fight the model on evidence the
harness cannot see completely (argv sniffing misses wrapped or scripted runs) and risks
deadlock; the durable guarantee is structural instead — state is writable only through the
audited typed ops, so the parser is the only path into it.

## Considered Options

- **Parse inside the container.** Would match "the tools stay inside the container" most
  literally, but hands the authoritative parser to the untrusted side (the container holds
  attacker-influenced output) and adds a container dependency to what is pure computation.
  Rejected.
- **Hard-gate the invariant** (refuse further scanner runs or network calls while an
  artifact is unparsed). Strongest methodicalness, but detection is best-effort, blocks are
  easy to deadlock, and it puts the harness in the model's way. Rejected.
- **Model-mediated writes** (parser returns JSON; the model calls `state_update`).
  Reintroduces exactly the lossy transcription step the invariant exists to remove, and
  lets model output reach state — contradicting the "never model-invented" promise.
  Rejected.

## Consequences

- The parser's output is trustworthy by construction, and the pending-parse obligation is
  advisory: an ignored obligation leaves state without those findings, visibly, rather than
  wedging the loop.
- `.styx/out/` becomes the harness-visible artifact convention, and artifacts are retained
  as evidence refs rather than pruned.
