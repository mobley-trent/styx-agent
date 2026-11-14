# A provider declares its endpoint and capabilities, and a route is never a fallback

v1.3 item 15 adopts provider breadth and per-agent model routing
([`docs/providers-and-routing.md`](../providers-and-routing.md), #152) on top of ADR-0002's decision
that breadth is configuration behind one OpenAI-compatible seam. The obvious shape is the one config
already has: a flat `models:` list where every entry implicitly goes to the one endpoint and the one
credential the harness knows, with a capability guessed from the model ID or probed at first use.

It should not be. **A provider is a declaration — an endpoint, the environment variable its credential
is read from, a closed capability set, and a billing clock — and a model names exactly one.** Three
consequences follow that the flat shape cannot express, and each was the reason to choose this one:

- **A declared capability is how a session's wire behaviour stays fixed.** `strict_tools` and
  `reasoning` change serialization, not authority, and declaring them means a run never discovers
  mid-turn that its endpoint cannot enforce schemas — the asymmetry ADR-0002 accepted becomes a line
  the operator reads at start instead of an error at the fifth turn.
- **A price needs its billing clock declared beside it.** `Pricing.Cost` halves every model's rates
  off-peak on DeepSeek's weekday calendar; with breadth that is a 2× error for any flat-rate endpoint,
  in the one number a budget ceiling is measured against. `billing: peak_halved | flat` is declared per
  provider, defaulting to `flat` because over-counting stops a run early while under-counting makes the
  ceiling a lie.
- **A route is a route.** `routing:` names a model per role; an unreachable provider fails that
  agent's first turn and nothing substitutes another model. A silent fallback would make the
  transcript's account of which model produced which evidence a lie, which is the one thing a
  red-team record cannot afford.

Identity stays separate from the wire: a model's `id` is styx's key (unique, priced, addressable in
`ev.Model`) and an optional `wire_model` is what the provider is sent, because two endpoints may serve
the same model name and a local endpoint may want a vendor-specific string.

## Considered Options

- **A flat `models:` list carrying its own `base_url` and `key_env`.** No provider object: smallest
  diff, and every entry is self-contained. Rejected because there is then nowhere to declare a
  capability or a billing clock without repeating it on every model — and because "which endpoint is
  degraded" would have no name to report.
- **Capabilities discovered at first use.** Rejected: most OpenAI-compatible endpoints advertise
  nothing, so discovery is inference, and it makes wire behaviour depend on a network round trip that
  can change underneath a run.
- **A compiled-in base-URL vendor table.** Rejected: an invented fact about endpoints styx has never
  seen, which mislabels every self-hosted deployment of a listed vendor's software.
- **Routing with fallback** (route to a provider, fall back to the root model when it is down).
  Rejected: it converts an attributed failure into an unattributed success, and it would silently
  change which model the record should credit.
- **Keeping DeepSeek's off-peak halving for every model and documenting "quote rates pre-halving".**
  Rejected: it makes a rate's meaning depend on a hidden clock, which is the invented price
  [`docs/budget-cap.md`](../budget-cap.md) §1 forbids, and it inverts the safe default.
- **A declared provider object with a declared capability set, a declared billing clock, and routes
  that never fall back (chosen).**

## Consequences

- **Every existing config parses unchanged**: a model that names no provider names the built-in
  `deepseek` provider, which ships the two pinned models and `billing: peak_halved`, so a fresh install
  prices and validates exactly as before.
- **`providers:` replaces wholesale on overlay**, like `permissions` and `mcp`. Stated cost: adding a
  second provider means restating DeepSeek's entry if DeepSeek stays. A merge rule would make "which
  layer declared this endpoint and this price" ambiguous.
- **The request path's DeepSeek-isms become declared inputs** — the strict path segment, the
  `reasoning_content` channel, the off-peak calendar — so the client is one OpenAI-compatible
  implementation configured N ways rather than N clients.
- **The compactor becomes per run**, sized to that run's model, and the summarizer's input is clipped
  at the smaller of the run's and the summarizer's windows. A shared compactor was only ever correct
  while every agent resolved one model.
- **The audit trail gains an additive `model`**, because two models in one session makes "which model
  proposed this call" provenance rather than a statistic.
- **A budgeted run's startup refusal is reachability-based** — the root model and every routed model —
  so the cap has no hole where a routed unpriced model would be priced at zero.
- **A configuration error is now also a routing error**: an unknown role, a dangling model, an unknown
  capability key, or a remote `http` endpoint refuses to start, rather than degrading into a session
  that behaves unlike the one the config describes.
