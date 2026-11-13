# A specification declares facts, never authorization

The v1.3 API-specification work (`docs/api-spec-targets.md`, #146) turns an OpenAPI, Swagger, or
Postman document into targets. The roadmap promised something stronger than it got: "an API spec can
be a target; **its declared base URLs are authorized inside the engagement**". This ADR records why
a declared server authorizes nothing, and why a declaration writes so little.

**First, the spec narrows; it never widens.** A declared server is usable only if its resolved
addresses already fall inside the engagement's pool. The reason is structural rather than cautious:
the pool has exactly one door. `docs/spec.md` §7.1 gives `targets:` a single flat set with no
groups and no ambient discovery, §6.1 says the engagement file authorizes scope and nothing else,
and ADR-0007 makes a non-interactive run honour only authorizations written down before it started.
A document that authorized its own declared hosts would be a second door, and the tool's `path`
argument would be the handle on it — whichever path a model named would widen scope, which is the one
move the whole safety model exists to refuse. Keeping the spec a fact source also keeps every design
beside it honest: reports, path reasoning, and the run viewer can cite a declaration without ever
having granted one.

**Second, a load writes hosts and nothing else.** It would have been natural for a declared server
to become a `service` entity — and it is wrong. `service.state` is `open`/`closed`/`filtered`, and
every value is an observation; nothing in the document was observed. Writing `open` would make the
forensic record claim a port nobody touched. Adding a `declared` value is the honest fix and still
the wrong one *now*: it widens a closed enum ADR-0004 closed, and a `schema_version: 1` document
carrying it is one an older build must refuse — a state-schema versioning decision the map has
already recorded as not yet made. So endpoints and declared services wait, and the surface reaches
the model as one derived inventory artifact plus a receipt.

## Considered Options

- **Declared base URLs authorize, whatever names the document.** The roadmap's literal reading, and
  the most ergonomic: point at a spec, test what it lists. Rejected because it hands scope widening
  to the model's path argument, and because a spec in a repository is a file anyone can open a PR
  against — an authorization source that changes with a branch is not an authorization source.
- **`engagement.yaml` gains a `specs:` block that pins declared servers at gate validation.** A
  human-reviewed widening, consistent with "widening stays a human editing the engagement file", and
  the literal roadmap sentence becomes true. Rejected because it creates a second authorization pool
  beside `targets:` — two places to look, two validation paths, two ways for a host to become
  reachable — to save one line in a file the operator already edits.
- **Prompt to widen scope for that run.** Familiar from the out-of-scope rule. Rejected in both
  modes: `-n` has no operator, and interactive it would be a flag-that-bypasses-scope wearing a card.
- **Match pool entries as written, no resolution.** Rejected: a CIDR pool can never equal a
  hostname, so a spec would be usable only when `targets:` already lists the name — most real
  engagements would find their own API unusable.
- **Write `service` entities with `state: open`.** Cheap and queryable. Rejected as a lie (above).
- **Import document credentials as `credential` entities.** Would make an authenticated API testable
  in one call. Rejected: it moves a repo file's secret into the loot store and within one
  `state_query` of model context, against spec §10.5; the document's *requirements* are what the
  model needs.
- **Discover spec-looking files at activation.** Convenient, and it makes a run's target set depend
  on files nobody named for that run — the ambient auto-detection §7.2 refuses.
- **One parser tool per format.** The six-parser precedent. Rejected: the output contract is
  identical and the format is unambiguous from the document, so a second tool only adds a guess.
- **A first-class `http_request`.** Rejected for this design, not forever: it is a new network tool
  owing its own scope edge, and `bash` + `curl` already covers the surface under the container's
  egress rules.

## Consequences

- A spec that declares a host outside the pool refuses that server, naming it and the fix. The
  operator's remedy is editing `engagement.yaml` — one reviewed line — never a flag.
- The load is a partial-result tool: the in-scope subset lands, refused servers are rows in the
  receipt, and only a document with *nothing* usable is an error. A refused nested server takes only
  the operations under it, so a document is never half-read without saying which half.
- Diff scoping gains its declaration source and a new refusal: a changed file that carries a spec's
  format key but will not parse refuses the run, because a scope flag must not claim an assurance it
  could not compute.
- Endpoint-level state, the state-schema versioning decision, live-fetched specs, and a first-class
  HTTP caller are all now clearly *somewhere else*, which is the useful outcome: each has a home
  rather than a hook in this design.
- The `.styx/out/api/` inventory is a derived artifact with no pending-parse obligation — the watch
  is for scanner output, and no parser reads a rendering of a document the repository already holds.
