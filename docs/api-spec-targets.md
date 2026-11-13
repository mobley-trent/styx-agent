# styx — API specifications as targets

Decided by [#146 Design OpenAPI/Postman-driven API testing](https://github.com/mobley-trent/styx-agent/issues/146)
(child of the map [Wayfinder: v1.3 reach & provider designs](https://github.com/mobley-trent/styx-agent/issues/144)),
delivering [`docs/red-team-roadmap.md`](red-team-roadmap.md) §1 item 9 — OpenAPI/Postman-driven API
testing — and the target-declaring source that [`docs/headless-ci.md`](headless-ci.md) §11 deferred
diff scoping to. Keystone rationale:
[`docs/adr/0014-a-specification-declares-facts-never-authorization.md`](adr/0014-a-specification-declares-facts-never-authorization.md).

This document decides **how an API specification becomes an authorized target**. It does not
decide what executes the resulting requests, does not add state entities, and does not touch the
capabilities beside it: the run viewer and reports (item 10), the specialist subagents (item 11),
web search (item 12), and MCP transport (item 13) are their own tickets.

## 1. Scope

One question, six answers in the order the ticket asks them: format and placement (§2),
authorization (§3), what a load produces (§4), diff scope (§5), precedence (§6), and failure (§7).
Gating (§8) follows from the parser precedent.

Three boundaries are fixed before the details:

- **A specification is a fact source, never an authorization source.** It says what an API offers
  and where; whether styx may talk to that host is the engagement file's answer, and only the
  engagement file's. `docs/spec.md` §6.1 already states the shape — "the engagement file authorizes
  scope only" — and §7.1 gives the pool no second door.
- **A declaration is not an observation.** A document asserting that a service exists at a URL is
  its authors' claim, not something the harness saw. Engagement state records observations
  ([`docs/engagement-state.md`](engagement-state.md) §2), so a load must not write an observed
  shape it never observed.
- **A document is where the secrets are.** Postman `auth` blocks, `securitySchemes`, and collection
  variables are the likeliest live credentials the harness will ever read (spec §10.5). The load
  reports requirements; it never reproduces a value.

## 2. Formats and placement

### 2.1 One tool, sniffed by content

**`api_spec_load`, one required parameter, `path`.** Strict mode requires every declared property
to be `required` (spec §5.1, `internal/agent/schema_test.go`), so the schema is exactly:

```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Workspace-relative path to an OpenAPI, Swagger, or Postman document."
    }
  },
  "required": ["path"],
  "additionalProperties": false
}
```

One tool, not one per format, unlike the six parsers. The parser family is one-per-format because
each maps a *different* artifact onto a *different* set of entities and edges; here the output
contract is identical for every format — a set of declared servers and an endpoint inventory — and
the format is unambiguous from the document itself. Two tools would make the model guess which is
which and pay a failed call for the guess.

The format is sniffed by a distinguishing key, in this order:

| Document | Key | Accepted |
|---|---|---|
| OpenAPI 3 | `openapi: "3.0.x"` / `"3.1.x"` | yes |
| Swagger 2.0 | `swagger: "2.0"` | yes |
| Postman collection | `info.schema` containing `schema.getpostman.com` | yes, v2.1 only |
| anything else | — | refused |

Both JSON and YAML are accepted for OpenAPI and Swagger (`gopkg.in/yaml.v3` already decodes both
through one path); Postman collections are JSON in practice and a YAML one is accepted by the same
decoder. An unrecognised document is refused, **naming the keys it looked for and the one it
found nothing at** — never a loose sniff, never a regex pass over a human-readable blob. Swagger
1.x, RAML, API Blueprint, WSDL, GraphQL SDL, and Proto are named as unsupported and refused: each
would be a different extraction design, and none of them is what item 9 promised.

### 2.2 Named by the call, never discovered

**The only way the harness learns of a document is the `path` a call names.** No tree scan, no
activation-time scan, no `.styx/config.yaml` key. `docs/spec.md` §7.2's "No ambient auto-detection"
is the rule for engagements; a specification that silently governs a run because it happened to be
in the tree is the same failure wearing a different hat. An operator who wants a run to be
API-aware names the document, in the conversation or in the task text.

- **A spec belongs in the repository, not `.styx/`.** It is a reviewed, version-controlled source
  artifact — the thing a PR changes. `.styx/` is the gitignored artifact directory
  ([`docs/parser-tool-contracts.md`](parser-tool-contracts.md) §3), and a declaration filed there
  would be invisible to the review that authorizes it.
- **Path confinement** reuses `resolveWithin(WorkDir, path)`: no `..` escape, no symlink escape.
- **Not a parser, and no obligation.** A load reads a declaration, not a scanner's output, so it
  neither clears nor raises a **pending-parse obligation**; a spec file is invisible to that watch.

## 3. Authorization: the spec narrows, never widens

### 3.1 The match

**A declared server is usable iff its resolved addresses fall inside the engagement's pool.**

The pool is `targets:` as validated at the gate — IP literals, containing CIDRs, and the pinned
addresses of every hostname and wildcard entry (`docs/spec.md` §7.1–§7.2). A declared server is
resolved **once, at load**, and its resolved addresses are pinned for the session exactly as an
engagement hostname's are; every request against them re-resolves and must land inside the pinned
set, unchanged from §7.2.

Resolution-at-load is what lets a name-declared server meet a CIDR-authorized engagement
(`https://api.acme.example` inside `10.0.0.0/24`). Matching the pool entry as a string instead
would strand every such engagement — a CIDR can never equal a hostname — and checking only per
request would leave the load unable to refuse anything, which §3.3 depends on.

- **Any resolved address outside the pool refuses the whole server.** A name resolving to one
  in-scope and one out-of-scope address is refused, not narrowed to the in-scope one: the harness
  cannot choose which address a request will land on, so accepting the name would be accepting the
  out-of-scope one (§7.2's answer-binding defence, applied before the first request rather than
  after).
- **A name that resolves to nothing refuses the server**, naming the name and the entries it
  missed.
- A server already written as an IP literal matches by containment, with no resolution at all.

### 3.2 No widening, by any route

There is **no prompt, no flag, no preset, and no acceptance path** that adds a target a spec
declared. An out-of-scope declaration is refused with the fix named in its reason:

```
refused: https://api.acme.example/v2 — api.acme.example resolves to 203.0.113.9,
         outside engagement targets (10.0.0.0/24, app.acme.example)
```

The fix is the operator editing `engagement.yaml` — a reviewed change — which is what §7.1, ADR-0007,
and `docs/headless-ci.md` §11.2 ("No preset and no flag adds a target; widening stays a human
editing the engagement file") already require. In a non-interactive run there is no operator to ask,
which settles the question the other way for that path; for the interactive path the answer must
still be the same, or a spec would be a scope-widening gadget with a card attached.

### 3.3 Refused is not failed

The ticket's rule is that an out-of-scope declaration is **named and refused, never silently
skipped**, and a document may hold several servers at once. So:

- **The in-scope subset loads.** Every refused server appears in the receipt's `refused[]` with its
  URL, its host, and a reason. Nothing is skipped silently and nothing is dropped quietly.
- **A refused server takes only what it governs.** OpenAPI 3 allows `servers` at root, path, and
  operation level; Postman allows folder-level variables and absolute request URLs. **Every level
  declares**, and a refused nested server removes only the operations under it — the inventory
  reports those operations as `unavailable` with the refusal reason, so a document is never
  half-read without saying which half.
- **If no server is in scope, the load is a tool error**, not a success with an empty inventory: a
  document that authorizes nothing usable has told the run nothing, and reporting `ok: true` would
  invite the model to retry against a surface it does not have.
- **Non-HTTP schemes are refused** (`ws`, `wss`, `grpc`, `file`): this tool ingests HTTP API
  declarations, and a scheme the harness cannot make an HTTP request to is not a target it can
  authorize.

### 3.4 Postman base URLs

A Postman collection's base URL is usually a variable — `{{baseUrl}}/v2/users`. Values come from
**the document itself**, and only from it:

- the collection's own `variable` block, plus folder-level variables that shadow it;
- a `{{var}}` the document does not define is an **unresolved declaration**, refused with the
  variable named (`unresolved: {{baseUrl}} — no value in the collection`).

There is no sibling `*.postman_environment.json` search and no second path argument. An environment
file is where the *secrets* live, it is not the document the operator named, and picking one
because it sat beside the collection is a guess — and "an inferred-nothing target is an error, never
a guess" (`docs/parser-tool-contracts.md` §2). An operator who wants an environment-backed
collection exports a collection that carries its base URL, or writes the spec down as OpenAPI. The
refusal says so.

## 4. What a load produces

### 4.1 State: the declared host, and only that

**A load writes one `host` entity per in-scope declared server, tagged `declared`**, upserted on the
existing natural key (`addresses`), with the server's hostname recorded as the `hostname` attribute
and every resolved address in `addresses[]`. Re-loading the same document reuses the same ids.

**It writes nothing else.** No `service`, no finding, no credential, no edge, no new entity kind:

- `service.state` admits `open` / `closed` / `filtered` — every one an observation. A declared port
  has no honest value among them, and writing `open` for a port nothing touched would make the
  forensic record lie (`docs/engagement-state.md` §2).
- Adding a `declared` value would widen a closed enum that ADR-0004 closed, and a
  `schema_version: 1` document carrying it is one an older build must refuse — which collides with
  the state-schema versioning decision already in the map's fog. **Declared services, and endpoints
  as entities, enter state when that decision lands**, not before.
- An endpoint is a declared fact, never a finding. Nothing here sets `status` or `verification`, and
  nothing here is evidence.

### 4.2 The surface: receipt plus inventory artifact

The load returns a **receipt** — the parser receipt's shape, so the model meets one pattern:

```json
{
  "tool": "api_spec_load",
  "document": "api/openapi.yaml",
  "format": "openapi-3.1",
  "ok": true,
  "servers": {"declared": 3, "usable": 1, "refused": 2},
  "hosts": {"new": 1, "updated": 0},
  "operations": {"total": 184, "unavailable": 12},
  "auth": [{"scheme": "bearerAuth", "type": "http", "in": "header", "name": "Authorization"}],
  "redacted": 2,
  "refused": [{"server": "https://api.other.example", "host": "api.other.example",
               "reason": "out of scope: not in engagement targets"}],
  "unresolved": [],
  "skipped": [],
  "inventory": ".styx/out/api/openapi-3f9c1a.json",
  "warnings": []
}
```

The **full inventory** — every operation's method, path template, effective server, and auth
requirement — is written to **`.styx/out/api/<document-stem>-<hash>.json`** and paged by
`read_file`, because a real spec has hundreds of operations and pasting them would spend a turn's
budget on the first call. The artifact is:

- **derived, not evidence**: it is a rendering of a document the repository already holds, so nothing
  cites it as proof of anything;
- **gitignored** with the rest of `.styx/`, and **outside the pending-parse watch** — a harness-written
  derivative is not scanner output, and no parser reads it;
- **rewritten** on each load of the same document (the hash is over the document path, so a changed
  document replaces its inventory rather than accumulating versions).

The receipt carries counts, the auth **requirements**, and the pointers; the model reads the
inventory when it wants the surface.

### 4.3 Secrets

**Requirements in, values never.** For each distinct scheme the document declares, the receipt and
the inventory carry its name, its type (`http`/`apiKey`/`oauth2`/`openIdConnect`), and where it
travels (header / query / cookie) — never a header value, token, cookie, or variable value.

- **Variable names are fine; values never are.** `{{apiKey}}` names a requirement; its value never
  leaves the document.
- **A literal secret in the document is counted, not echoed** — one receipt line,
  `redacted: 2 literal credential values`, never the value, not even truncated: a truncated key is
  still a key.
- **Nothing from the document enters state as a `credential`.** Importing one would put a repo file's
  secret into the loot store and within one `state_query` of model context. Credentials enter state
  the way they always do — through a parser that observed them, or through the model recording what
  it found.

### 4.4 What executes the surface

**Nothing new.** The load names the surface and the hosts; requests are made with `bash` + `curl` in
the container, under the existing container egress rules, or through the #145 browser and proxy.
No new network tool, no new scope predicate, no second path to the network.

A first-class `http_request` (methods, bodies, harness-injected credentials from state) is a real
capability and a different design: it is a new network tool owing its own scope edge, and item 9
does not ask for it.

## 5. Diff scope: what a changed spec declares

`docs/headless-ci.md` §11 settled the semantics of `--scope-mode diff` / `--diff-base` and deferred
the flag because nothing in a tree declared a target. This is that source, and §11's rules survive
contact unchanged — declarations not literals, intersection not union, an explicit resolved base, an
empty mapping as a successful no-op, legibility, reversal out. Three refinements follow.

### 5.1 Which changed files are declarations

A changed file is a **candidate declaration** iff both hold:

- its extension is `.json`, `.yaml`, or `.yml`; and
- its content carries a format key from §2.1 — `openapi`, `swagger`, or a Postman `info.schema`.

A candidate is then loaded by the same loader, harness-side, with **no state write**: the scope
computation runs before the first turn, a CI run may exit without ever taking one, and writing state
from a scope calculation would be a side effect nobody asked for and nothing audits.

Extension alone is not enough (every Go project holds YAML that declares nothing) and content alone
is too expensive (decoding every changed file). A **changed Postman environment file is not a
declaration** — it declares no server, and it is where the secrets are.

### 5.2 A broken declaration refuses the run

§11.2 says a changed file that declares nothing contributes nothing. That covers a README, a
workflow, and a spec-shaped file with no servers. It does **not** cover a file that carries a format
key and fails to load:

**A candidate that will not parse refuses the run (`1`) before the container starts, naming the file
and the parse error.**

A scope flag is an assurance, and it must not claim one the run cannot keep (§11.2, pointed at a
document instead of a ref). A run narrowed from a document it could not read has tested either
nothing or everything while claiming the spec's scope — and a PR that breaks the API's own spec is
exactly the change a reviewer wants the pipeline to stop on. This refines §11.2's wording: *a file
that declares nothing* contributes nothing; *a file whose declarations were unreadable* is a refusal.

### 5.3 What narrows, and what only informs

- **Hosts narrow.** The changed candidates' usable declared hosts are unioned across documents (two
  specs declaring one host name one target) and **intersected with the pool** — §11.2's
  intersection, never union, unchanged: a diff removes targets from the engagement's set and can
  never add one.
- **Refused declarations contribute nothing** and are named in a note, like any out-of-scope target
  in a diff.
- **Unchanged documents contribute nothing.** A source-only change does not drag its spec's hosts
  in; only a document the diff touched declares.
- **Changed operations inform, never authorize.** The diff's changed operations on a narrowed host
  are reported to the model as run context — `changed: POST /users/{id}, GET /users/{id}/orders` —
  so an API run is aimed at the change. They sit in the frozen engagement context set before the
  first turn (§7.4's lifetime, not the state digest's), and they authorize nothing: authorization
  stays host-level, because that is the only granularity the gate, the container edge, and the
  audit can all enforce identically.

## 6. Precedence, in one table

| Declared server | Result |
|---|---|
| resolves entirely inside the pool | usable; host written; operations in the inventory |
| resolves partly outside the pool | refused whole (answer-binding), named |
| resolves to nothing inside the pool | refused, naming the name and the entries missed |
| a `{{var}}` the document does not define | refused as unresolved, naming the variable |
| non-HTTP scheme | refused, naming the scheme |
| in a diff-scope run, out of scope or refused | contributes nothing, named in a note |
| in a diff-scope run, the only declarations | `0` with §11.2's no-op line |
| every server refused in an interactive load | tool error: nothing usable was declared |

Never a prompt, never a widening, never a silent skip.

## 7. Failure

Strict, atomic, non-fatal, never silent — the parser contract's failure discipline (§7), applied:

- **Unrecognised or unsupported document** → nothing written, a structured error naming the expected
  keys, the file, and a sample of what was found.
- **A refused server** is a partial result, not an error: the batch commits and the receipt carries
  the `refused[]` rows (§3.3).
- **A malformed operation** (no method, no path, a template that will not parse) → skipped row with a
  reason, in `skipped[]`; the rest commit.
- **An empty-but-valid document** → `ok: true` with zero counts. A document declaring no server at
  all is a refusal instead: with no base URL there is nothing to authorize, and `swagger: 2.0`'s
  relative-only form is exactly that case.
- **Size**: the document is read under a hard ceiling with a clear error rather than an OOM, and the
  load is bounded by a wall-clock timeout, matching `read_file`'s 4 MiB cap and the parsers' limits.
- **Truncation**: a receipt or inventory over the capture bound truncates with an artifact pointer,
  like any tool output.

## 8. Gating, presets, and the tool table

- **Engagement mode only.** Safe mode denies `api_spec_load` — there is no pool to check a
  declaration against and no store to write the host into — and engagement mode allows it,
  audit-logged, exactly like `state_*` and the six parsers (`docs/spec.md` §6.1). The audit row
  carries the document, the count of usable and refused servers, and every resolved address, because
  a load is where a target set is decided.
- **No scope targets of its own.** Every declaration was checked at load, and the requests that
  follow are ordinary network calls checked as they always are; a `Targets` field here would
  double-check a document rather than a destination.
- **All four presets** (`coder`, `recon`, `exploit-dev`, `log-triage`) receive it, as they receive
  the parsers: `recon` is the primary consumer, and a subagent told to test an API must be able to
  read the API's own declaration. Provenance carries subagent attribution as always.
- **Not `ExploitClass`, not `Destructive`, not network.** Through the normative order like everything
  else: schema validation → verdict → audit → dispatch.

## 9. Explicitly not in this design

- **A spec fetched over HTTP** (`GET /openapi.json` from an in-scope host). Real red-team value, and
  a live-fetch pipeline with its own scope check, its own write-then-load step, and its own
  redaction question for whatever auth the fetch needs. Recorded as fog on the map, not smuggled in
  here.
- **`service` and `endpoint` entities.** Waiting on the state-schema versioning decision (§4.1).
- **A first-class `http_request` tool** (§4.4).
- **An environment-file search** for Postman variables (§3.4), and **tree discovery** of documents
  (§2.2).
- **Endpoint-granularity scope.** A new scope dimension would have to run through the gate, the
  container edge, and the audit identically; changed operations inform instead (§5.3).
- **Auto-deriving targets from source literals.** Ruled out by `docs/headless-ci.md` §11.2 and not
  reopened here.

## 10. Spec touchpoints (applied by the implementation tickets)

- **§5.1** — add `api_spec_load` to the built-in tool table with its `{path}`-only schema.
- **§5.4** — add it to all four preset allowlists.
- **§6.1** — mode defaults: safe = deny, engagement = allow (audit-logged), and record that a
  declaration is a scope *check*, never a scope grant.
- **§10.6** — record `.styx/out/api/` as a derived, gitignored inventory directory with no
  pending-parse obligation.
- **[`docs/headless-ci.md`](headless-ci.md) §11** — name this document as the declaration source,
  refine "contributes nothing", and add the broken-declaration refusal (§5.1–§5.3).
- **Roadmap §1 item 9** — point at this document.
