# styx — browser and HTTP-proxy tooling

Decided by [#145 Design browser + HTTP-proxy tooling](https://github.com/mobley-trent/styx-agent/issues/145)
(child of the map [Wayfinder: v1.3 reach & provider designs](https://github.com/mobley-trent/styx-agent/issues/144)),
delivering the reach half of [`docs/red-team-roadmap.md`](red-team-roadmap.md) §1 item 8.
Keystone rationale:
[`docs/adr/0013-reach-tools-are-harness-side-and-the-proxy-is-the-scope-edge.md`](adr/0013-reach-tools-are-harness-side-and-the-proxy-is-the-scope-edge.md).

This document decides **what the two reach tools are and how they stay inside the safety
model**. It does not decide implementation structure beyond the boundaries the invariants
force, and it does not touch the capabilities beside it: OpenAPI/Postman targets (item 9),
the run viewer (item 10), and the webapp specialist subagent (item 11) are their own tickets.

## 1. Scope

One question: **which surface owns a Playwright-class browser and a Caido/Burp-class
interception proxy, and what are their contracts?** Six answers, in the order the ticket
asks for them: ownership (§2), contract (§3–§4), state (§5), gating (§6), and failure (§8).

Three boundaries are fixed before the details:

- **The reach tools change the toolkit, not the enforcement.** Scope, ROE hard limits, the
  policy choke point, audit, and container egress behave exactly as they do today. A browser
  is not a new safety layer with its own exceptions.
- **Every destination is checked at the harness.** The scope check for a page load, a click,
  a redirect hop, and a replayed request all resolve to the same predicate the policy engine
  and `web_fetch` already use (spec §7.2).
- **Nothing secret reaches the model** (spec §10.5). Cookies, cookies' values, and
  `Authorization` headers are harness-visible and model-invisible, without exception.

## 2. Ownership: both are harness-side built-ins

The browser and the proxy are **built-in tools**, not MCP-supplied servers, and one design
covers both.

The reason is structural, not stylistic. The harness's only way to learn a call's destinations
is `Tool.Targets` (spec §6, `policy.Call.ScopeTargets`), which a built-in declares and an MCP
tool cannot: `mcpScopeTargets` infers targets from argument names and values, which works for a
tool whose destination is an `ip` parameter and fails for a browser, whose next destination is
usually **not an argument at all**. A click navigates to wherever the page says. An
MCP-supplied browser is therefore a scope hole, and closing it would need a new bridge letting
a server declare destinations it was never passed — a larger design than this one, and one
nothing in v1.3 requires.

Roadmap §4 keeps MCP as the extension point for capability styx does not own (RE toolchains,
forensics, an exploitation framework). The browser and the proxy are not that: the harness has
to enforce their scope itself, so it has to own them.

**Consequence:** these are the first network tools whose enforcement does not rest on the
model declaring where it is going. §3.3 and §4.2 close that gap for the browser (per-request
checks at the proxy) and for replay (a URL parameter that is a `Target`).

## 3. The browser

### 3.1 Process and placement

**A host subprocess, launched by the harness, from a pinned browser build.**

- The pinned session image deliberately ships no browser (["GUI or desktop packages:
  absent"](sandbox-image.md) §2.1), and it stays that way: the browser is a **host
  prerequisite**, the same way `ssh_logs` already treats the operator's `ssh` client as its
  transport. An absent browser is a tool-level error naming the prerequisite, never a silent
  downgrade.
- The harness launches it with an isolated profile (§5), `--proxy-server` pointing at the
  harness proxy, and QUIC/WebRTC disabled so no second network path exists that would skip
  the proxy. HTTP/2 over TCP is fine; anything that could egress outside the proxy is not.
- The harness drives it over CDP on a loopback port with a per-launch token; the port is
  bound to `127.0.0.1` and never exposed.
- **The honest cost, stated where an operator will read it:** hostile page content renders on
  the operator's machine, inside the browser's own sandbox, as the operator's user. That is
  the same trust posture as the operator's own browsing, and the status bar says
  `browser: host` so it is never implied otherwise. §10 records the container-resident
  alternative as the hardening path.

### 3.2 Tool contract

Six tools, one per verb. Strict mode requires every declared property to be `required`
(spec §5.1, `internal/agent/schema_test.go`), so a single `browser` tool with an action enum
would force placeholder arguments on every call and give the repair layer one more shape to
guess at.

| Tool | Parameters (all required) | Purpose |
|---|---|---|
| `browser_navigate` | `url` | Load an absolute http(s) URL in the active page. |
| `browser_read` | `handle`, `max_chars` | Read the page or one element as text; empty `handle` means the whole page. |
| `browser_click` | `handle` | Activate an element by its handle. |
| `browser_type` | `handle`, `text`, `submit` | Type into an element; `submit` presses Enter after. |
| `browser_screenshot` | `full_page` | Write a PNG artifact and return its path. |
| `browser_download` | `handle` | Activate an element that triggers a download and return the artifact path. |

`browser_navigate.url` is the tool's `Targets` source: the URL's host, exactly as
`web_fetch` derives it. A call that cannot parse a host declares no targets and is refused by
the handler, never resolved as target-free.

**Handles.** `browser_read` returns a bounded aria snapshot (default 8192 characters, capped
at 32768) in which every interactive node carries a stable, per-snapshot number. `click` and
`type` take that number, never a CSS selector:

- the model can only address elements it actually read, so it cannot invent a selector that
  reaches something it never observed;
- an unknown or stale handle is a distinct tool error (`stale handle: take a fresh snapshot`),
  which is diagnostic instead of silent;
- the snapshot and the action speak one vocabulary, so a snapshot is never a guess at what the
  action will hit.

The same discipline the terminal preview snapshot uses, applied to a page.

### 3.3 Navigation and scope

`browser_navigate` re-resolves its host and pins the connection the way `web_fetch` does
(spec §7.2): the pre-flight verdict comes from `Targets`, and the connection is made to a
verified in-scope address.

**Redirects are followed, hop by hop.** `web_fetch` refuses a redirect outright because a
one-shot fetch can afford to; a browser that refuses redirects is not a browser — logins, CDNs,
and every `http`→`https` hop would break. Each hop is a fresh request, so each hop is a fresh
scope check at the proxy (§4.2). An out-of-scope hop produces:

- a structured 403 page in the browser (so the model sees *why* the page is not the one it
  asked for, rather than a truncated document),
- an audit entry with the closed-set reason `out-of-scope`,
- a tool result naming the refused hop and the host that was outside scope.

Subresource loads (`<img>`, `<script>`, XHR/fetch) are scope-checked the same way per request.
A page cannot exfiltrate by loading an off-scope pixel.

### 3.4 Read and screenshot output

`internal/model` has no image path, and vision is provider breadth (item 15, ADR-0002), not
this ticket. So:

- `browser_read` returns **text**: the aria snapshot, or one element's subtree, truncated to
  `max_chars` with an explicit truncation line.
- `browser_screenshot` writes a PNG to `.styx/out/browser/<session>/shot-<n>.png` and returns
  its path with the URL, title, and viewport size. **No base64 body enters context**, and no
  tool ever returns pixels as data. A screenshot is an artifact the operator (or a later
  vision-capable model) looks at, and an evidence ref a finding can point at.
- `browser_download` writes into `.styx/out/downloads/<session>/`, keeps the server-supplied
  filename only after sanitizing it to a basename, and returns the path plus size and content
  type. Downloads are artifacts, not context. Executing one is `bash` in the container, under
  the ordinary rules — nothing about a download makes it trusted.

### 3.5 State

See §5.

### 3.6 Secrets

**No tool returns a cookie value, a `Set-Cookie` value, an `Authorization` header, or any
storage value.** `browser_read` reads the DOM, not the storage areas. Where the model needs to
reason about auth state it gets **metadata**: cookie names with domain, path, flags, and
expiry; storage key names; whether the page is authenticated. Values stay inside the profile,
which the harness owns and the model cannot read, and inside the capture, whose redaction
boundary §6.5 defines.

This holds in safe mode and engagement mode alike. There is no reveal prompt: spec §10.5 is not
a default.

## 4. The proxy

### 4.1 Shape: capture, replay, tamper-on-replay

The proxy **records every request and response, and replays captured exchanges with edits.**
It does not implement a live interception queue.

- A breakpoint that pauses a request is the one Burp feature an agent has no surface for: there
  is no in-flight tool call to raise a card on, and pausing a navigation stalls a page load the
  model is waiting on. An unattended run (spec §10, [`docs/headless-ci.md`](headless-ci.md))
  could never answer it at all.
- The capability that matters for red-team work is: **see everything that went over the wire,
  then re-send it with a tampered parameter.** That is replay, and it needs no pause.
- Replay is also the safer shape: a replay's destination is an explicit `url` parameter, so it
  is a scope-checked tool call, whereas a forwarded breakpoint's destination is whatever the
  page chose.

### 4.2 Egress plumbing

The proxy is the **single egress path for reach traffic**, and it is the harness's enforcement
point for traffic that is not a tool call:

- The browser dials only the proxy (§3.1); the container's `curl`, `ffuf`, and scanners reach
  it through the proxy environment the harness already sets (`containerlayer.Manager.ProxyURL`),
  so a scanner's traffic is captured and scope-checked the same way a page load is.
- **The env var is not the enforcement.** With capture on, the harness programs the session's
  firewall to permit egress only to the proxy's own listener, so a tool that ignores
  `HTTPS_PROXY` is denied at the edge instead of passing uncaptured. Where the firewall cannot be
  programmed, the harness-local egress proxy is already the container's only path (spec §5.2).
- Per request the proxy re-resolves the destination and matches the engagement's **pinned IP
  set** — the same set the container firewall programs (spec §5.2). Egress is IP-based, so a
  hostname-level check at the proxy is what makes the pinned set meaningful for names.
- With an engagement active, the proxy runs **MITM mode** (§6.4). Without one — safe mode — it
  is a plain CONNECT tunnel with **no capture**: there is no pinned scope to enforce and nothing
  to attribute a capture to, and the prompt on the browser tool is the guard, exactly as the
  nil-scope path in `internal/netfetch` documents today.

### 4.3 Scope verdicts: deny, never prompt

A proxied request gets **deny or pass**. Out-of-scope is a structured `403` carrying the
reason, a `out-of-scope` audit entry, and a line in the capture. It is **never a prompt**:

- a prompt needs a call in flight and a card to render it on; a tunnel has neither, and an
  unanswered one is a hung browser;
- the operator's widen is the engagement file, not a mid-stream card;
- the model is not left guessing: the 403 body and the tool result name the refused
  destination, so it can change course, which is what the prompt would have bought anyway.

The tool call that *starts* the browser or the proxy was itself policy-gated (§6), so the
operator approved the capability before any traffic existed.

### 4.4 CA custody and container trust

- **One CA per engagement**, at `~/.local/share/styx/pki/<project>/<engagement>/ca.pem` with
  its key beside it at mode `0600`, created on first use and reused for the engagement's life
  (`<project>`/`<engagement>` derived exactly as the session and state stores derive theirs,
  spec §10.6).
- **Container trust:** the certificate is bind-mounted read-only and installed at session start
  (`update-ca-certificates`) so container tooling validates the MITM. An install the harness
  cannot confirm **refuses the session** rather than running with TLS that silently fails or,
  worse, silently skips verification.
- **Browser trust:** the browser never gets the CA installed system-wide. It launches with the
  CA's SPKI pinned on its command line, so exactly one process trusts exactly one CA, and the
  operator's own browsing is untouched.
- The key never leaves its directory, is never logged, and never appears in a prompt, a capture,
  or a tool result.

### 4.5 Captures

- **Location:** `.styx/out/captures/<session>/capture-<n>.jsonl`, one record per exchange
  (method, URL, status, headers after redaction, bounded bodies, timing, and the exchange id
  replay uses).
- **Rotation:** a segment closes at **8 MiB** and the next opens; the receipt and every tool
  result name the current segment, so an evidence ref is always `capture-<n>.jsonl#<id>` and
  stays valid.
- **Body bounds:** bodies over **256 KiB** are elided with their size and digests recorded;
  replay of an elided body says so instead of sending a truncated one.
- **Gaps are explicit:** a proxy restart writes a `gap` record naming the time, so a capture is
  never silently discontinuous.
- **Retention:** segments are evidence and are never auto-pruned; removal is the operator's act,
  like any other artifact (`docs/parser-tool-contracts.md` §3).
- **Redaction boundary:** the capture files hold the **real bytes**. Redaction applies only to
  what reaches the model (§3.6, §4.6). This is what keeps "replay as captured" useful: an
  authenticated exchange re-sent from the capture still authenticates, while the model never
  sees the credential that made it work.

**No pending-parse obligation.** The obligation watches for a *finished* artifact a parser can
consume (`docs/parser-tool-contracts.md` §4). A capture segment is written continuously for as
long as the browser runs, and no v1.3 parser maps an HTTP exchange onto engagement-state ops;
a "new artifact" nudge per request would drown the state digest in a line nobody can clear. So
captures are evidence without an obligation, the state digest does not mention them, and the
model reads them through the filtered tools below rather than by re-reading the file.

### 4.6 Tool contract

| Tool | Parameters (all required) | Purpose |
|---|---|---|
| `proxy_history` | `filter`, `limit` | List recent exchanges; `filter` is a glob over `METHOD host path` (empty = all), `limit` bounds the count. |
| `proxy_exchange` | `id` | One exchange in full: redacted request and response, headers, bounded body. |
| `proxy_replay` | `id`, `method`, `url`, `headers_json`, `body` | Re-send; empty string means "as captured". `headers_json` is a JSON object string, the same string-carried shape the `skill` tool uses for a free-form object. |

- `proxy_replay.url` is a `Target`, so a replay is scope-checked like `web_fetch`: changing the
  destination is a scope question, and changing it out of scope is a prompt, not a free pass.
- A replay of an `id` that no longer exists (rotated away, or never captured) is a tool error
  naming the id, never a synthesized request.
- `proxy_history` and `proxy_exchange` never return a redacted header's value; `proxy_replay`
  accepts a header the model supplies, which is model-invented by definition and is audited
  verbatim like any other parameter (spec §7.5).

## 5. Browser and proxy state

| Item | Where | Lifetime |
|---|---|---|
| Browser profile (cookies, storage, cache) | `~/.local/share/styx/browsers/<project>/<engagement>/` | The engagement, single-writer locked |
| Downloads, screenshots | `.styx/out/downloads/<session>/`, `.styx/out/browser/<session>/` | The session's artifacts, retained |
| Captures | `.styx/out/captures/<session>/` | The session's artifacts, retained |
| Proxy CA | `~/.local/share/styx/pki/<project>/<engagement>/` | The engagement |

- **Per-engagement profile, outside the repo.** An authenticated login is the expensive,
  engagement-scoped fact: re-authenticating every session would make authenticated testing
  cost a login flow per session, and the profile holds cookies, which §10.5 keeps out of the
  project tree for the same reason engagement state lives outside it. The profile is guarded by
  the same pid-checked lockfile discipline as the state store (spec §10.6): one writer, readers
  allowed, a second writer refused with a clear message.
- **The browser process and the proxy process are per-session** (§7): their state dies with
  the session; the profile and the CA outlive it.
- **Safe mode keeps no profile** — with no engagement there is no directory to scope it to, so a
  safe-mode session gets an ephemeral profile deleted at session end.

## 6. Gating, presets, and the rule table

| Tool | Safe mode | Engagement mode | Targets | Tags |
|---|---|---|---|---|
| `browser_*` | prompt | in-scope → allow, out-of-scope → prompt | `browser_navigate.url` host | none |
| `proxy_history`, `proxy_exchange` | **deny** | allow, audited | none | none |
| `proxy_replay` | prompt | in-scope → allow, out-of-scope → prompt | `url` host | exploit-class: **no** |

- **`browser_*` is `web_fetch`-shaped.** It is a network capability, so it prompts by default
  in both modes and engagement scope is what widens it — never the mode flag alone (spec §6.2).
- **`proxy_history` / `proxy_exchange` are `state_query`-shaped.** They read a record that only
  exists inside an engagement and reach no network, so safe mode denies them where there is
  nothing to read, and engagement allows them audited. Neither carries targets, so the rule
  table alone decides (spec §6.1).
- **`proxy_replay` is not exploit-class.** It re-sends a request the engagement's own scope
  already permitted; `exploit_allowed: false` is a gate on exploitation tooling, not on replaying
  a captured request. It stays destructive-free and is audited per call.
- **Presets** (spec §5.4): `browser_*` to `recon` and `exploit-dev`; `proxy_*` to `exploit-dev`
  only. `coder` and `log-triage` stay network-free, as they are today. The webapp specialist
  preset (item 11) inherits from `exploit-dev` when that design lands, not from this one.
- **A non-interactive run can browse only in scope**, because every prompt there is a
  `no-operator` denial (ADR-0007). Nothing here widens a headless run.

## 7. Lifecycle

- **Lazy start.** The first browser tool call launches the browser; the first proxy-backed
  request starts the proxy (which in engagement mode means MITM, CA, and capture). No
  `browser_start` / `proxy_stop` tools exist: there is no process for the model to leak and
  no lifecycle verb for it to sequence wrongly.
- **One of each per session.** A single browser with a single active page, a single proxy.
  Tabs, parallel browsers, and per-target sessions are §10.
- **Teardown:** session end, `/mode` returning to safe mode (spec §7.3), and engagement
  deactivation all stop both processes and flush the capture. The profile and CA stay.
- **Visible state:** the status bar carries `browser: host` and `proxy: capture` (or `proxy:
  tunnel` in safe mode) beside the existing isolation indicator, so neither process is ever
  running invisibly (spec §9.1).

## 8. Failure taxonomy

Every failure below is a **tool-level error with a named cause**, audit-logged where an action
was attempted. None crashes the loop, and none silently bypasses a check.

| Failure | What happens |
|---|---|
| Browser binary absent or wrong version | Tool error naming the prerequisite and the pinned version; the capability is unavailable for the session, everything else works. |
| Browser crash / renderer OOM | Tool error; the next browser call relaunches with the profile (and its cookies) intact. |
| Browser CDP unreachable mid-call | Tool error naming the transport; the browser is relaunched on the next call, and the profile lock is released. |
| Proxy restart | Same CA is reused; a `gap` record is written to the capture; restart is audited; tool calls during the gap fail with a transport error rather than passing unchecked. |
| CA install into the container fails | Session refuses to start the proxy path; the message names the mount and `update-ca-certificates`. No MITM, no capture, no degraded TLS. |
| Certificate mismatch / verification failure | Hard tool error naming the host, the mismatch, and the CA in play. **Never** an insecure-skip-verify fallback, never a silent retry. |
| Out-of-scope request or redirect hop | 403 + audit `out-of-scope` + tool result naming the hop (§4.3). |
| Stale or unknown element handle | Tool error telling the model to take a fresh snapshot. |
| Capture disk full | Capture write fails closed: the exchange is refused rather than passing uncaptured, and the error is visible. |
| A container tool ignores the proxy environment | Denied at the firewall, which permits egress only to the proxy listener while capture is on (§4.2). Never a silently uncaptured request. |
| Profile locked by another session | Tool error naming the locking session, the same discipline the state store uses (spec §10.6). |
| Screenshot / download path unwritable | Tool error; the artifact is not announced as written. |

**The rule:** a failure in the reach layer is always **visible at the tool boundary**. There is
no path where the browser is silently absent, the proxy silently passes traffic it did not
check, or a capture silently loses exchanges.

## 9. Audit and observability

- **The audit log records decisions, not traffic** (spec §7.5): tool calls and their verdicts,
  proxy lifecycle (start, restart, stop), every scope denial, and CA creation/installation. A
  per-request audit entry would make the forensic record unreadable and enormous; the capture is
  the traffic record, and it is an artifact under `.styx/out/`.
- The capture is the model's source for traffic and the operator's source for evidence; the two
  views differ only by redaction (§6.5).
- `proxy_history` results are bounded and ordered newest-first, so a long capture is readable
  without paging machinery.

## 10. Explicitly not in v1.3

Live interception queue / breakpoints / forward-and-edit-mid-flight · request thumbnails or any
image in model context (vision is item 15) · multiple tabs, multiple browsers, or per-target
browser sessions · a container-resident browser (needs a sandbox-image release; §3.1 records the
host posture instead) · an MCP-supplied browser or proxy (needs a destination-declaring bridge,
§2) · automatic form filling, crawling, or spidering as a harness capability (the model drives
each step, which is what keeps every navigation a checked call) · WebSocket/gRPC capture (HTTP
only in v1.3) · HAR export as a file format (the capture is JSONL; a HAR renderer can come with
the run viewer, item 10) · cookie or storage value access by the model, with or without a prompt
· a capture parser (no pending-parse obligation, §4.5) · replay of an elided body (says so
instead).

## 11. Spec touchpoints (applied by the implementation tickets)

- **§5.1** — add the nine tools to the built-in tool table with their strict schemas, the
  `browser_navigate.url`/`proxy_replay.url` target source, and the host-prerequisite note.
- **§5.4** — `browser_*` to `recon` and `exploit-dev`; `proxy_*` to `exploit-dev`.
- **§6.1** — `browser_*` and `proxy_replay` as `web_fetch`-shaped prompt rules;
  `proxy_history` / `proxy_exchange` on the `stateAction` branch (deny in safe mode).
- **§6.2** — the proxy as a scope enforcement point for non-tool traffic (403 + audit, never a
  prompt), beside the container firewall.
- **§7.2** — redirect-hop scope checks for the browser.
- **§9.1** — `browser:` and `proxy:` status-bar indicators.
- **§10** — the profile, pki, capture, screenshot, and download paths; the `.styx/out/`
  convention extends to them; no pending-parse obligation and why.

## 12. Verification (what the implementation must prove)

- **Scope:** a local TLS target and a local proxy; in-scope request passes, out-of-scope request
  is 403'd and audited, and a redirect to an out-of-scope host is refused at the hop while the
  in-scope page still loads.
- **Redaction:** a capture containing `Authorization`, `Cookie`, `Set-Cookie`, and a
  `?token=` query is redacted in `proxy_exchange` output and intact on disk; `proxy_replay`
  with empty strings still authenticates.
- **Rotation:** crossing 8 MiB starts a new segment, the receipt names it, and a restart writes
  a `gap` record.
- **Failure:** a killed browser relaunches with cookies intact; a failed CA install refuses the
  proxy; a certificate mismatch never falls back to skipping verification.
- **Gating:** safe-mode `proxy_history` is denied, in-scope `browser_navigate` is allowed in
  engagement mode, and a non-interactive run cannot widen either.
- All of it offline: a loopback stub serves the pages and the API, so no test touches a real
  target and CI needs no network.
