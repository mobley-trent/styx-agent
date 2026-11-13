# styx — remote MCP transport and OAuth

Decided by [#150 Design remote MCP transport and OAuth](https://github.com/mobley-trent/styx-agent/issues/150)
(child of the map [Wayfinder: v1.3 reach & provider designs](https://github.com/mobley-trent/styx-agent/issues/144)),
delivering [`docs/red-team-roadmap.md`](red-team-roadmap.md) §1 item 13. Keystone rationale:

- [`docs/adr/0019-a-remote-mcp-endpoint-is-infrastructure-never-a-target.md`](adr/0019-a-remote-mcp-endpoint-is-infrastructure-never-a-target.md)
  — why the endpoint is not scope-checked, and what that costs.
- [`docs/adr/0020-authorization-is-an-operator-act-never-a-session-side-effect.md`](adr/0020-authorization-is-an-operator-act-never-a-session-side-effect.md)
  — why nothing opens a browser on the operator's behalf.

This document decides **how a remote MCP server connects, how it authenticates, where its tokens
live, what happens when that fails, and what any of it changes about the safety model**. It does not
reopen the local stdio transport (spec §5.5), the policy gate (spec §6), or the egress model for
container traffic (spec §5.2, [`docs/browser-and-proxy.md`](browser-and-proxy.md)).

## 1. Scope

The ticket asks five things in order: config (§2), token custody (§6), the OAuth flow (§7), failure
and revocation (§8–§9), and egress (§10). Limits (§3), the connection itself (§4), the no-implicit-auth
rule (§5), tool-list changes (§11), state (§12), and the TUI surface (§13) follow from those answers;
§14–§15 are testing and the implementation boundary; §16 records what is deliberately left open.

Three boundaries are fixed before the details:

- **The gate does not move.** A remote tool is a tool. Same normative order (spec §5.3), same rule
  table, same audit, same `mcp__<server>__<tool>` namespace. Remote transport is not a scope grant
  and not a scope exemption — it is a way to reach the server, and nothing else.
- **Authorization is a human act.** A grant that lets a third party act with the operator's
  credentials is taken once, by the operator, deliberately (§5). No session opens a browser because
  the model chose a tool.
- **A server is third-party infrastructure.** The harness gates the calls it dispatches. What a
  server does with them — including any network it reaches on its own — is the server's conduct, and
  §10 says so out loud rather than implying a guarantee the harness cannot make.

## 2. Config: one list, two transports

`mcp.servers` stays one list and one name namespace. An entry gains an explicit `transport`
discriminator:

```yaml
mcp:
  servers:
    # Existing shape, unchanged: command present, transport inferred.
    - name: ghidra
      command: ghidra-mcp
      args: ["--headless"]

    # Remote over streamable HTTP, OAuth by default.
    - name: vendor
      transport: http
      url: https://mcp.vendor.example/mcp

    # Remote, static token referenced from the environment (§10.5).
    - name: fleet
      transport: http
      url: https://mcp.fleet.example/mcp
      auth: bearer
      token_env: FLEET_MCP_TOKEN

    # Remote, open server.
    - name: internal
      transport: http
      url: https://mcp.internal.example/mcp
      auth: none

    # Remote, preregistered OAuth client (a registrar that refuses DCR, §7).
    - name: registrar-only
      transport: http
      url: https://mcp.registrar.example/mcp
      auth: oauth
      client_id: styx-public-client
      timeout: 45s
      connect_timeout: 15s
      max_response_bytes: 2097152
      max_retries: 3
```

| Key | Applies to | Default | Notes |
|---|---|---|---|
| `transport` | all | inferred: `stdio` when `command` is set, `http` when `url` is set | Explicit value is `stdio` or `http`. No other value is accepted. |
| `command`, `args`, `env` | `stdio` | — | Unchanged from spec §5.5. |
| `url` | `http` | — | Must be `https://`. `http://` is accepted only for a loopback host (`127.0.0.1`, `::1`, `localhost`). |
| `auth` | `http` | `oauth` | One of `oauth`, `bearer`, `none`. |
| `token_env` | `http` + `auth: bearer` | — | Name of an environment variable holding the token. Never a value. |
| `client_id` | `http` + `auth: oauth` | — | Preregistered OAuth client id (§7). Public, so it may live in config. |
| `timeout` | `http` | `30s` | One request's budget, discovery calls included. |
| `connect_timeout` | `http` | `10s` | TCP + TLS + initialize. |
| `max_response_bytes` | `http` | `1048576` (1 MiB) | Cap on one response body or SSE event. |
| `max_retries` | `http` | `3` | The SDK's own retry count for a failed request; below its default of 5 so a dead endpoint fails visibly fast. |
| `disabled` | all | `false` | Unchanged: configured but not launched/connected. |

Validation is strict, and every rule exists to keep a key from being silently ignored:

- `transport` and `url` must describe the same thing: `command` with `transport: http` is an error,
  `url` with `transport: stdio` is an error, `command` and `url` together is an error. No precedence
  rule, no "url wins".
- `args` and `env` on an `http` entry are errors, not ignored. A token pasted into `env` for a remote
  server is exactly the mistake §6 exists to prevent, so it refuses rather than half-working.
- `token_env` is required with `auth: bearer` and refused with any other `auth`. `client_id` is
  refused unless `auth: oauth`.
- An `http` URL that is neither HTTPS nor loopback is refused by name, because a bearer token over
  cleartext is a credential leak the operator did not intend to authorize.
- `transport: sse` is refused with a message naming streamable HTTP as its replacement. The Go SDK
  ships an `SSEClientTransport`; styx does not use it. SSE is deprecated in the MCP specification in
  favour of streamable HTTP, and a second transport means a second failure taxonomy, a second set of
  tests, and a shape the ecosystem is leaving. One transport, done properly.
- Everything else about the existing block — `name` required and unique across both transports,
  declaration order, project-over-global overlay semantics, unknown keys tolerated — is unchanged.

**Backwards compatibility.** Every config that parses today parses identically: no `transport`, a
`command`, and the same five keys. The name namespace is shared, so a remote server can never shadow
a stdio server or a built-in.

## 3. Limits

None of these are optional, which is why they have defaults rather than being undefined behavior:

- **A hung server must not hang the harness.** `timeout` bounds one request; a discovery call, a
  tool call, and a token refresh each get their own budget. Expiry is a tool-level error naming the
  server and the elapsed budget, never a blocked loop.
- **A chatty server must not eat the context window.** `max_response_bytes` caps one response body
  and one SSE event, and truncation is stated in the result the model receives — the same contract
  tool-output truncation already has at capture (spec §4.5).
- **Retries are bounded and visible.** `max_retries` covers a failed request, and exhausting it is a
  tool error. There is no background reconnect loop (§9).

## 4. Transport and connection

Streamable HTTP, via `mcp.StreamableClientTransport`, with the standalone SSE stream left enabled:
server-initiated notifications are how a tool-list change arrives (§11), and this is the transport
the specification points at.

- **A new connector beside the old one.** `mcpclient.Connector` is already the seam that keeps the
  SDK out of the app layer; `HTTPConnector` joins `StdioConnector` and receives the entry's `url`,
  limits, and OAuth handler. Tests keep substituting an in-memory transport either way.
- **One HTTP client per server**, built from the entry's limits and never `http.DefaultClient`:
  timeouts on the client, the byte cap on the body, redirects refused. A redirect on a fixed endpoint
  is a configuration surprise, not a hops question — and following one would move both the endpoint
  and the `Authorization` header somewhere the operator never declared.
- **No proxy environment variables.** `HTTP_PROXY`/`HTTPS_PROXY` are not consulted in v1.3. Routing
  the harness's own traffic through an operator's proxy is a real story, but it is an egress decision
  with its own trust question, and it is not this one (§16).
- **Proxies are not in the path.** Remote MCP traffic is harness-side, like the model provider's; it
  does not traverse the session container, the interception proxy, or the capture
  ([`docs/browser-and-proxy.md`](browser-and-proxy.md) §4). There is no capture of MCP traffic, and
  therefore no capture to redact — the `Authorization` header never exists anywhere the model or the
  capture can see.
- **Server-initiated requests are refused.** The streamable transport carries server→client requests
  (`sampling/createMessage`, `roots/list`, `elicitation/create`). styx refuses all of them with a
  protocol error and records one lifecycle note. A server does not get to invoke the model: the model
  is the untrusted party the harness mediates, and letting a vendor endpoint ask it for a completion
  would be a second agent loop with none of the gate. Tool-list notifications (§11) are the one
  server-initiated message styx acts on.
- **Reconnection is foreground.** A dropped connection is `closed` (§9); the next tool call attempts
  one fresh connect, on demand, inside its own timeout. Nothing reconnects in the background.

## 5. Authorization is an operator act

Startup connects each enabled server and attempts discovery. A 401 during discovery marks the server
`auth_required` and moves on: it does not open a browser, does not block the session, and does not
make "read one file" wait behind an OAuth flow.

The flow starts only from an explicit operator action:

- `/mcp` → select a server → *authorize*, or
- `styx mcp auth <server>` before the session (the only route in `-n`, §8).

Two consequences, both intended:

- **The model can never propose a grant.** A lazy-on-first-tool-call flow would make the model's
  choice of tool the thing that opens a browser; that puts the untrusted party in the position of
  proposing a trust decision. It does not get that position.
- **A mid-session 401 does not raise a card.** The server moves to `auth_required`, the call returns
  the error of §9, and the operator authorizes through `/mcp` when they choose to. The SDK's
  one-shot "retry after `Authorize`" is available only when a flow the operator just completed
  supplied the token; a 401 with no authorization in flight never starts one. See
  [ADR-0020](adr/0020-authorization-is-an-operator-act-never-a-session-side-effect.md).

This is the same posture ADR-0007 takes for policy prompts, applied to a non-policy gate: nothing
gains authority because a session would find it convenient.

## 6. Token custody

**Location.** Per project, per server, outside the repository:

```
~/.local/share/styx/mcp/<project>/<server>-<hash>/token.json     mode 0600
```

`<project>` is derived the way the session store and engagement state derive theirs (sanitized name
plus a short hash of the raw value), and `<hash>` is a short hash of the entry's `url`. Changing the
URL therefore never reuses a token: the old directory is orphaned, and the next authorization writes
a fresh one. Keying by server *name* alone would let an edited URL inherit a grant issued to a
different host.

**Contents.** The token set plus what the grant was issued to: access token, refresh token, token
type, expiry, issuer, granted scopes, and the OAuth client credentials DCR produced (a registered
client id must survive restarts, or the next session re-registers and some servers refuse the
duplicate). The file is written atomically (temp file + rename), so a crash leaves the previous token
or none — never a half-written one. A refresh is serialized by a short-lived lockfile beside it, so
two sessions refreshing at once cannot both spend a single-use refresh token; the loser re-reads.

**What may never see a token.** Not `.styx/config.yaml` or `~/.config/styx/config.yaml`, not
`STYX.md`, not the system prompt, not a tool result, not a session JSONL, not the audit's params, not
a lifecycle `Detail` string, not the TUI. The store's API hands out an `oauth2.TokenSource`, never a
string, so a caller cannot render what it never receives. An error path that would echo a token or a
`refresh_token` response body is a bug, and §14 tests for it.

**What the audit records.** Authorization, refresh, and revocation are audit entries (§9) carrying
server name, issuer, granted scopes, expiry, and the action — the *fact* that a grant exists and what
it covers. Never a token, never a client secret.

**What the operator sees.** In `/mcp` and in `styx mcp auth`: authorized, expired, or none, with the
expiry date and the scopes, plus the token file's path. Seeing the scopes matters more than seeing
the timestamp: it is the only place the operator can check what the server was actually granted.

**Static bearer tokens stay env-only** (§2). `token_env` names a variable and styx reads it at
connect time; it is never persisted, never written to a token file, and its absence is a
`auth_failed` lifecycle event naming the variable, not a startup refusal — the same fail-on-demand
rule as `DEEPSEEK_API_KEY` and `EXA_API_KEY` (spec §10.5).

## 7. The flow

Authorization-code + PKCE, public client, implemented through the SDK's `AuthorizationCodeHandler`;
styx supplies the two pieces the SDK deliberately leaves to the caller — how the browser end happens,
and where the token lives.

**Client registration.** Dynamic Client Registration (RFC 7591) by default, because it is what MCP
servers actually implement and it makes a remote entry work from one `url` line. A server that only
accepts registered clients gets `client_id` in its entry, which switches that server to
preregistration. styx hosts no Client ID Metadata Document: it is a local binary, and inventing a
hosted endpoint would put a second party in the token path for no benefit.

**Scopes.** As discovered from the resource metadata or the `WWW-Authenticate` challenge — styx does
not narrow or extend them. `offline_access` is requested when the server advertises it, since §6
persists a refresh token on purpose.

**The browser end.** A loopback listener on `127.0.0.1:<ephemeral>` receives the redirect, and the
authorization URL is shown on an **authorization card** in the live region:

```
┌─ authorize vendor ─────────────────────────────────────────┐
│ https://mcp.vendor.example/mcp  ·  issuer: auth.vendor.com │
│ scopes: files:read  fleet:write                            │
│                                                            │
│ Open:  https://auth.vendor.com/authorize?...               │
│ Waiting for the callback on 127.0.0.1:49321    4:58        │
│ [o] open in browser   [p] paste redirect URL   [esc] cancel│
└────────────────────────────────────────────────────────────┘
```

- **The card is not a permission prompt.** It is not a verdict, no policy engine issued it, and
  answering it authorizes a *server*, not a call. It renders separately for that reason.
- **Five-minute window**, countdown visible, `esc` cancels. Expiry is `auth_failed`, with the reason
  naming the timeout.
- **`o` opens a browser** through the platform opener. **`p` accepts a pasted redirect URL** for the
  host that has no browser to open — an SSH session, a container, `BROWSER` unset — which is the
  ordinary case for a terminal harness on a remote Unix box, not an edge case. Pasting the redirect
  URL is the same code path the listener would have received; PKCE and the state check still apply.
- **No terminal, no card.** A run with no TTY behaves as `-n` does (§8).
- **On success** the token is stored (§6), audited, and the server is re-discovered: the tools it was
  hiding behind the 401 register now.

## 8. Non-interactive runs

`-n` never starts a flow. There is no browser, no card, and no prompt to convert into a permission —
the operator is not there (ADR-0007). Concretely:

- No usable stored token → the server comes up `failed` with the reason `auth_required`, a lifecycle
  event, and tool calls that return an error naming `styx mcp auth <server>`. **The run proceeds**;
  it is not refused, and it is not made unusable by one un-authorized server.
- A refresh token is still used, because that grant was authorized when a human completed the flow;
  spending a refresh token is not a new authorization. A failed refresh is a tool-level error.
- `auth: bearer` works headless with the environment variable set, which is the intended way to run a
  token-authenticated server in CI.
- **No new exit code.** A missing MCP server is a tool error, like any other unavailable tool; the
  run's exit status keeps meaning what [`docs/headless-ci.md`](headless-ci.md) §8 says it means.
  A run that needed the server and could not use it fails as a run fails — a turn error — not as a
  gate.

## 9. Failure, refusal, and revocation

Remote failures join the taxonomy stdio already has, with two states added because auth is an
actionable fact rather than a failure:

| State | Means | Operator sees | Model sees |
|---|---|---|---|
| `connecting` | dialing, TLS, initialize | status line | nothing yet |
| `ready` | connected, tools registered | tool count | the tools |
| `auth_required` | reachable, request rejected with 401/403, no usable token | lifecycle event + `/mcp` row naming the fix | tool error: not authorized; the operator must authorize this server |
| `auth_failed` | the flow was cancelled, timed out, refused, or is impossible under `-n` | the reason | tool error naming the state |
| `failed` | could not connect, TLS refused, DNS failed, `token_env` unset, refresh failed | lifecycle event with the reason | tool error naming the server and the reason |
| `closed` | the connection dropped mid-session | lifecycle event | tool error; the next call attempts one foreground reconnect |

Rules that hold across the table:

- **Nothing crashes the loop.** Same rule as a stdio server that dies mid-session (spec §5.5).
- **Nothing is silently dropped.** A call on an unavailable server returns an error naming the state
  and the fix; it is never reported as a successful empty result.
- **No background retry.** A retry that eventually succeeds would add tools to a session on its own
  schedule; the operator's next action is the retry.
- **Errors carry no secrets.** The state and reason name the server, host, and — for auth — the fix.
  They never include a header, a token, or a response body that could contain one.

**Revocation.**

- `styx mcp auth --revoke <server>` deletes that project's stored authorization; `--revoke --all`
  deletes every stored MCP authorization for the user. Both ask for confirmation, because a grant
  that is silently gone is the kind of surprise this repo's posture forbids in the other direction.
- Deletion is **audited** (server, issuer, scopes, timestamp) before the file is removed. An
  authorization whose audit entry cannot be written is refused and no token is stored — audit stays
  fail-closed. A revocation whose audit entry fails still deletes (deletion is the safe direction)
  and says so loudly, rather than keeping a token to protect a record.
- `/mcp` → *revoke* does the same thing interactively.
- **Revocation is local.** Deleting the file ends styx's use of the token. The token itself remains
  valid at the issuer until it expires or is revoked there, and the documentation says that in those
  words. styx has no relationship with the issuer's management API and will not claim one.
- A revoked or expired token surfaces as `expired`/`auth_required` on the next call or in `/mcp`, not
  as a mysterious tool failure: the 401 is what produces the state.

## 10. The endpoint is infrastructure, never a target

A remote endpoint is a fixed URL a human wrote in a reviewed config file. It is not passed as a tool
argument, it is not discovered from a document, and it is not a place styx intends to *act against* —
so it is infrastructure, in the same class as the model provider's endpoint, and the engagement's
target pool has nothing to say about it:

- Connecting is **not scope-checked**. It is allowed because the operator declared it, exactly as the
  model endpoint is allowed for the same reason.
- It is **not added to the container's egress allowlist** (spec §5.2). That allowlist governs traffic
  from the session container; this traffic comes from the harness process and never touches the
  container's network. Adding it there would widen container egress for traffic that cannot use it.
- It is **not a `Targets` declaration**, and no MCP tool can declare one. `Tool.Targets` is a built-in
  property precisely because a harness that cannot see a destination cannot check it
  (ADR-0013) — which is the honest reason an MCP tool never gets a scope verdict on what it reaches.

The limit this buys, stated plainly because it is the cost of the decision:

> **A server's own downstream I/O is outside scope enforcement.** When a remote MCP server receives
> a call, whatever it fetches, scans, or stores is the server's conduct. The harness gates the call it
> dispatches, and nothing else. A stdio server has the same boundary already — it runs as a host
> process with unbounded network — so this is not new exposure so much as newly explicit exposure:
> remote adds a third party that can reach the target without styx dispatching anything.

What that means for an operator, in order of how much it helps:

1. **Installing a remote server is installing third-party infrastructure.** It is a trust decision
   comparable to installing an MCP binary, and larger in reach, because the vendor holds the
   credential and the network.
2. **Tool calls are still gated per call, in both modes.** `mcp__*` is unknown to the default rule
   table, so it resolves to `prompt` in safe *and* engagement mode; engagement widens nothing by
   itself (spec §6.1, §6.2). A human therefore sees every MCP call interactively, and a headless run
   denies every one the operator did not write an allow rule for.
3. **A call's arguments are a disclosure to the vendor.** In engagement mode those arguments name
   targets — the same class of disclosure ADR-0018 gates for search, but here it is the per-call
   content the operator implicitly authorized by declaring the server. An engagement that forbids
   telling a vendor about the target does not configure a remote server, and the point of the
   prompt-by-default rule is that the disclosure is visible as it happens.

Refused alternatives, and why: scope-checking the endpoint would treat tooling as a target and prompt
or hard-deny every run in a CI image pointed at `mcp.vendor.com` that the operator already authorized
by writing it down. A per-server OSINT-style ROE flag would be a second gate on the same disclosure,
and the call-level prompt already sits at the moment the data would leave. See
[ADR-0019](adr/0019-a-remote-mcp-endpoint-is-infrastructure-never-a-target.md).

## 11. Tool-list changes

When a connected server sends `notifications/tools/list_changed`, styx re-discovers its tools,
replaces that server's descriptors, and emits a lifecycle event naming what was added or removed.

This is not the background reconnect §9 refuses. That refusal was about a retry loop admitting tools
on its own schedule; a tool-list change is the server saying, on the connection the operator
authorized, that its surface moved — and the reason a session and a deployed vendor server diverge is
exactly the case where silently calling a stale schema would fail the repair layer in the most
confusing possible way. Nothing is admitted un-gated either way: descriptors are validated against the
policy engine and the audit on every call, and the gate was never a one-time admission of a tool set.

If re-discovery fails, the server goes to the state the failure implies (`failed` or `closed`) and
keeps its previous descriptors for no longer than the next call, which will fail against the real
connection rather than pretend the old list is current.

## 12. Nothing reaches engagement state

A remote MCP call writes no entity, no finding, no credential, and no host. Its result is ordinary
tool content. Credentials a server *returns* are model context at worst, never state: state is written
only through `state_update` and the parsers (spec §10.6). Auth metadata stays in the token file and
the audit, and never in the record.

## 13. Surface

- **`/mcp`** lists every configured server — remote and stdio — with transport, status, auth state,
  tool count, and, where it applies, expiry and scopes. It is where *authorize* and *revoke* live. A
  session with three servers where the panel shows two of them is a support question waiting to
  happen, and the status line cannot hold a per-server tool count plus an auth state.
- **The status line** gains nothing new: it keeps the summary it has, because the panel is the detail.
- **The stream** gets lifecycle events as it already does for stdio: connecting, ready with a count,
  `auth_required` with the fix, failed with the reason, closed, and tools changed.
- **`styx mcp`** is the CLI mirror, for the runs that never open the TUI:
  - `styx mcp auth <server>` — authorize (interactive terminal required; prints the URL and accepts a
    pasted redirect when no browser can be opened).
  - `styx mcp auth --revoke <server>` / `--revoke --all` — delete stored authorizations, audited.
  - `styx mcp auth` with no argument — list configured servers with transport, status, and auth state;
    read-only, the CLI form of the panel.
  - Exit codes follow the existing command convention: `0` success, `1` the operation failed (no such
    server, flow refused, no terminal), `2` usage or config error.

## 14. Testing

No live vendor in CI. What the design needs proven:

- **A stub streamable-HTTP MCP server** (in-process) for discovery, calls, 401, drop, and
  `tools/list_changed`; the existing in-memory connector stays for stdio paths.
- **A stub authorization server** issuing codes and tokens, so PKCE, state, DCR, preregistration,
  refresh, and expiry are exercised without a network.
- **Token custody**: file mode is `0600`, path derives project + URL hash, a changed URL does not
  reuse the old token, a token never appears in a lifecycle `Detail`, an audit entry, or a tool
  result.
- **The three-way gate**: an `mcp__*` call prompts in safe mode, prompts in engagement mode, and is
  denied in `-n` absent an overlay rule — the unchanged default, asserted because the design's whole
  claim is that it did not move.
- **`-n` behavior**: a 401 is `auth_required`, the run continues, no flow is attempted, and a
  refresh token is spent when present.
- **Validation**: `command`+`url`, `transport: sse`, `http://` non-loopback, `token_env` without
  `bearer`, and `args` on an `http` entry each fail with a message naming the key.
- **Concurrency**: two managers refreshing the same token serialize and leave one valid token.

## 15. Implementation shape

Boundaries only; the implementation is a later ticket.

- **`internal/config`** — `MCPServer` gains `Transport`, `URL`, `Auth`, `TokenEnv`, `ClientID`,
  `Timeout`, `ConnectTimeout`, `MaxResponseBytes`, `MaxRetries`; `validateMCP` grows the rules of §2.
- **`internal/mcpclient`** — `HTTPConnector` beside `StdioConnector`; `Server` gains the remote
  fields; `Status` gains `auth_required` and `auth_failed`; tool-list refresh in the manager; the
  refusal of server-initiated requests.
- **`internal/mcpauth`** (new) — the token store (§6), the flow and its card plumbing behind a small
  interface the TUI and the CLI both drive, the loopback listener, the paste parser, and the audit
  hook. It imports `mcpclient` for names and nothing from `agent`, so auth cannot reach the model.
- **`internal/app`** — wiring, the `styx mcp` command group, and the `-n` branch that reports rather
  than prompts.
- **`internal/tui`** — the `/mcp` panel and the authorization card, parsed from the same command
  registry that documents it (spec §9.4).
- **`internal/audit`** — the auth entry kind (§6, §9).

## 16. Deliberately not decided

- **OS keyring custody** for tokens. The right hardening path once the file layout has proven itself;
  it adds a platform dependency to the one subsystem whose risk is token handling, so it is a
  follow-up decision, not a first shape.
- **SSE as a transport.** Refused in §2; revisit only if a server styx must support ships nothing
  else.
- **Corporate proxy support** for harness traffic (`HTTP_PROXY`). A real egress story with its own
  trust question, and not this ticket's.
- **A spec-style public read path** and the OSINT classes — the map's fog, unchanged here.
- **Server-initiated sampling/elicitation**, refused in §4 rather than designed. Supporting it would
  be a second model surface behind a third party's control, and nothing in v1.3 needs it.
- **A per-server scope filter** beyond what the authorization server advertises. The SDK offers one;
  styx does not use it, because narrowing scopes without knowing the server's contract is guesswork
  and the card already shows what is being granted.
- **Token import/export** between machines, and any hosted client identity. It would make CI nicer and
  add a distribution channel for the one secret this design exists to keep local.
