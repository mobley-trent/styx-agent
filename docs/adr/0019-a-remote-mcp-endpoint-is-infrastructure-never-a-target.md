# A remote MCP endpoint is infrastructure, never a target

v1.3 item 13 extends `internal/mcpclient` beyond stdio
([`docs/mcp-remote-and-oauth.md`](../mcp-remote-and-oauth.md), #150). The new thing is a URL in an
MCP server entry: a fixed endpoint the harness connects to, authenticates against, and calls tools
through. Spec §6.2's scope check exists to answer "may styx act against this host", and an operator
could reasonably expect the answer to apply here.

It should not. **An MCP endpoint is infrastructure, not a target.** It is declared in a reviewed
config file by the human who owns the machine, never passed as a tool argument, and it is not a place
styx intends to act against — it is the place its tooling lives. The engagement's target pool says
what styx may act *against*, not where its capabilities come *from*. So connecting is allowed
because a human wrote the endpoint down, exactly as the model provider's endpoint is allowed for the
same reason, and the pool is never consulted.

Two mechanical facts follow, and both are refinements of existing decisions rather than new ones:

- **The endpoint is not added to the container egress allowlist** (spec §5.2). That allowlist governs
  traffic leaving the session container. Remote MCP traffic leaves the harness process and never enters
  the container's network, so allowlisting it there would widen container egress for traffic that
  cannot use it.
- **No MCP tool declares `Targets`.** `Tool.Targets` is a built-in property because the harness must
  see a destination to check it, and that is precisely what an MCP tool cannot offer
  ([ADR-0013](0013-reach-tools-are-harness-side-and-the-proxy-is-the-scope-edge.md)). Every call is
  still gated — per call, in both modes — but the verdict is a rule-table verdict, not a scope match.

## Considered Options

- **Scope-check the endpoint like a target.** Superficially the conservative choice, and it inverts the
  tooling relationship: a CI image pointed at `mcp.vendor.com` would prompt on every interactive run
  and hard-deny every headless one, for a server the operator had already authorized by declaring it
  in version control. It also teaches operators to add their vendor endpoints to the target pool,
  which is worse — it makes third-party infrastructure look like an authorized objective.
- **A per-server OSINT-style ROE flag**, so an engagement must opt in to disclosure as ADR-0018 makes
  search opt in. Rejected: search needed a flag because its call carries no destination and the model
  authors the text; an MCP call already lands on the rule table as `prompt` in both modes, which puts
  a human in front of the disclosure at the moment it happens. A second gate on the same act would
  disagree with the first one eventually, and an operator who forbids vendor disclosure simply does
  not configure the server.
- **Mirror the endpoint into the container egress allowlist.** Rejected as a category error: the
  harness dials the endpoint, the container does not.
- **Treat the whole server as out of scope for engagements**, leaving remote MCP to safe mode.
  Rejected: engagement mode is where the tools matter, and refusing it there would push operators to
  run the same vendor tool outside the harness, where no call is gated or audited at all.
- **Declared infrastructure, allowed at connect, tools gated per call, limitation documented
  (chosen).**

## Consequences

- **The limitation is now written down, because it is the price.** A remote server's own downstream
  I/O is outside scope enforcement: whatever it fetches, scans, or stores is its conduct, not a call
  the harness dispatched. A stdio server already has that boundary — it runs as a host process with
  unbounded network — so the change is not new exposure but newly *explicit* exposure, with a third
  party holding both the credential and the network.
- **A call's arguments are a disclosure to the vendor**, and in engagement mode they name targets.
  That is authorized by declaring the server, made visible by the per-call prompt, and audited
  verbatim like every other call's params.
- **The gate does not move.** `mcp__*` is unknown to the default rule table, so it prompts in safe and
  engagement mode alike; engagement widens nothing by itself. A headless run denies every MCP call the
  operator did not write an overlay rule for (ADR-0007).
- **Installing a remote server is a trust decision**, on the same footing as installing an MCP binary
  and larger in reach. The documentation says so where the endpoint is configured, not in a footnote.
- **A future bridge that lets an MCP server declare destinations** would not inherit this allowance; it
  would have to earn its own scope story, which is why the map carries it as fog rather than as an
  inevitable extension of this one.
