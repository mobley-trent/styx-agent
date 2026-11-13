# Authorization is an operator act, never a session side effect

A remote MCP server authenticates with OAuth
([`docs/mcp-remote-and-oauth.md`](../mcp-remote-and-oauth.md), #150). The Go SDK's
`StreamableClientTransport` makes the convenient shape obvious: it calls the handler's `Authorize`
itself when a request comes back 401, and the first such request is tool discovery at session start.
Wire that up and a browser opens because the session started.

It should not. **An authorization is a trust decision taken once, by a human, deliberately** — and a
session that opens a browser on the operator's behalf has taken that decision for them, at a moment
they did not choose, about a grant that lets a third party act with their credentials. So the flow
starts only from an explicit operator action: `/mcp` → *authorize*, or `styx mcp auth <server>` before
the session. Startup connects, discovery hits 401, the server is marked `auth_required`, and the
session proceeds without it.

Two corollaries, both consequences rather than separate decisions:

- **A lazy first-tool-call flow is refused.** It is the same act with a worse trigger: the model's
  choice of tool becomes what opens a browser, which puts the untrusted party in the position of
  proposing a trust decision. The model never proposes a grant; the operator's own command does.
- **A mid-session 401 does not raise a card.** The call returns the tool error naming the fix, and the
  operator authorizes through `/mcp` when they choose. The SDK's one-shot retry after `Authorize`
  remains available for the token a flow the operator just completed supplied — but nothing starts a
  flow to satisfy a call.

## Considered Options

- **Authorize during startup discovery (the SDK's default shape).** Every repo with an un-authorized
  server would block its own startup behind a browser, and "read one file" would wait on an OAuth
  flow. Worse, the operator's click lands before they have read anything the card shows.
- **Authorize lazily on the first tool call that needs the server.** Refused above: the model's tool
  choice would trigger a credential grant, and the card would appear mid-turn with no context about
  why.
- **Require tokens to be supplied out of band only** (env var or a hand-placed file), with no flow at
  all. This is coherent and it is what a pure-CI harness would do, but it makes a local operator
  perform a credential dance in a browser and paste the result — worse security, because a token
  pasted through a shell lands in shell history.
- **Explicit operator action only, in the TUI and the CLI (chosen).**

## Consequences

- **`-n` needs no special case for authorizing.** No flow exists to suppress; a server without a
  usable token comes up `auth_required` and the run continues. A refresh token is still spent, because
  that grant was authorized when a human completed the flow — spending it is not a new grant.
- **The authorization card is not a permission prompt.** It is not a policy verdict, no engine issued
  it, and it authorizes a server rather than a call. It renders and is dismissed separately for that
  reason, and the design says so where the card is specified.
- **A session can be useful before a server is authorized.** Un-authorized servers are unavailable
  tools, not a failed session — the same "fails visibly, never crashes the loop" rule §5.5 already
  gives a stdio server that dies mid-session.
- **Authorizing is a deliberate, auditable act.** `styx mcp auth` exists because the CLI is the one
  surface that works before a session and in a non-interactive context; a grant that could only be
  taken by launching the TUI first would push operators toward pasting tokens into config.
- **The cost is a step for the operator.** An un-authorized server does not work until they act, and
  the error message has to carry the fix — which is why the state is `auth_required` with that
  message, rather than a generic connection failure.
