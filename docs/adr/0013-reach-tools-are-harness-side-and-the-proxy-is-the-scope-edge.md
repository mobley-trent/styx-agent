# The reach tools are harness-side, and the harness proxy is the scope edge for non-tool traffic

The v1.3 reach tools (`docs/browser-and-proxy.md`, #145) put a browser and an interception
proxy in the harness's tool set. Two choices here will surprise a future reader.

**First, both are built-ins, though the roadmap says extension is MCP-only.** That rule
protects the single policy choke point: an extension cannot add a path around the engine. It
assumes a tool's destinations arrive in its arguments, which is true for a scanner and false
for a browser — a click navigates wherever the page says. The harness learns destinations only
through `Tool.Targets`, which a built-in declares and an MCP tool cannot; the MCP adapter's
argument sniffing would see nothing at all for the interesting half of a browsing session. An
MCP browser is therefore a scope hole, and the alternative is a new bridge letting a server
declare destinations it was never passed. Enforcing scope is the harness's own job, so it owns
the tools that need a new kind of check.

**Second, the proxy — not the tool call — is the scope check for browser traffic.** Every page
load, redirect hop, subresource, and container-side scan request re-passes a pinned-IP scope
check at the proxy. That check **denies with a 403 and an audit entry and never prompts**: a
prompt needs a call in flight and a card to render it on, a tunnel has neither, and an
unanswered prompt is a hung browser. The operator's widen is the engagement file. This means a
non-tool request can be denied without any verdict the operator sees live — the audit and the
403 are the record, and the ticket that started the browser was itself policy-gated.

## Considered Options

- **MCP-supplied browser.** Would have kept the roadmap's rule literally intact. Rejected: a
  browser's real destination is not an argument, so no argument-based target extraction can
  see it; the capability would pass the gate with an empty target set and be scope-unchecked.
- **MCP-supplied proxy (Caido/Burp over MCP).** Buys maturity cheaply. Rejected: the third-party
  process's egress is entirely outside the harness's control, so the "egress re-passes scope at
  the harness" requirement would be unmeetable by construction.
- **Container-resident browser.** The strongest isolation, and it keeps hostile rendering off
  the operator's machine. Rejected for v1.3: the pinned image ships no browser by design, so it
  needs a sandbox-image release plus a CDP route into the container — a second design before
  this one can land. Recorded as the hardening path, and the status bar states `browser: host`
  so the posture is never implied to be stronger than it is.
- **Prompt on an out-of-scope proxied request.** Consistent with the engine's out-of-scope rule,
  and unimplementable: there is no in-flight call to attach a card to.
- **Live interception queue (Burp parity).** The recognisable capability, and the one an agent
  has no surface for: no in-flight call to raise a card on, and a stalled navigation with no
  operator in a headless run. Rejected in favour of capture + replay + tamper-on-replay, whose
  tampered destination is an explicit, scope-checked `url` argument.
- **Redact at capture-write time.** Simplest reading of "secrets never reach the model". Rejected
  because it breaks replay: an authenticated exchange re-sent from a redacted capture no longer
  authenticates, so the proxy would only ever work on unauthenticated traffic. The real bytes
  stay on disk at `0600` in a harness-owned directory; only the model-facing views redact.

## Consequences

- `web_fetch` and the browser diverge on redirects: the fetch refuses them, the browser follows
  them and checks each hop. That asymmetry is deliberate and is stated in both docs.
- A new artifact family lives under `.styx/out/` (captures, screenshots, downloads) with **no
  pending-parse obligation** — a continuously written capture is not the finished artifact that
  obligation watches, and no v1.3 parser maps an HTTP exchange onto state.
- The browser is an operator prerequisite like `ssh`, and its failure is a tool error rather
  than a degraded session.
- The proxy becomes the second enforcement point for scope, beside the container firewall. Any
  future tool that reaches the network without passing through a tool call has to route through
  it, not beside it.
- An MCP-supplied browser or proxy remains possible, but only after a bridge lets an MCP server
  declare destinations the harness never sees in the arguments — which supersedes this ADR's
  first half rather than routing around it.
