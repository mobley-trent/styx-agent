# styx-agent — Buildable Spec (v1)

A distributable, Go-based terminal agent harness (Claude Code / Pi-class: rich TUI, tools,
MCP plugins, subagents, session memory) for coding plus red-team, reverse-engineering, and
blue-team work — with harness-enforced dual-mode safety for an untrusted model.

**Status:** resolved spec. Every section records decisions already grilled and closed on the
[wayfinder map](https://github.com/mobley-trent/styx-agent/issues/1); each cites the ticket
holding the rationale. Nothing here is open for re-litigation in the implementation effort —
new requirements go through the issue tracker, not silent deviation.

**Glossary:** [CONTEXT.md](../CONTEXT.md) is the canonical domain language. This spec uses
those terms without redefining them. (Per the map's Notes, ticket links below render as
`issues/N`.)

**Implementation-effort first act:** scaffold the Go module exactly per §2 and stand up the
CI gate per §11 — the spec assumes neither exists yet.

---

## Table of contents

1. [Overview & design principles](#1-overview--design-principles)
2. [Module layout](#2-module-layout)
3. [Model layer (DeepSeek)](#3-model-layer-deepseek)
4. [Agent loop](#4-agent-loop)
5. [Tools](#5-tools)
6. [Policy engine & permission model](#6-policy-engine--permission-model)
7. [Engagement file & safety model](#7-engagement-file--safety-model)
8. [Skill packs & MCP](#8-skill-packs--mcp)
9. [Terminal UI](#9-terminal-ui)
10. [Storage: sessions, memory, config](#10-storage-sessions-memory-config)
11. [Testing & evals](#11-testing--evals)
12. [Distribution & updates](#12-distribution--updates)
13. [Out of scope (v1)](#13-out-of-scope-v1)
14. [Decision index](#14-decision-index)

---

## 1. Overview & design principles

styx-agent (binary `styx`) is a single static Go binary: a chat-centric terminal agent with
Claude Code-grade capabilities — streaming TUI, built-in + MCP tools, subagents, session
memory — plus a dual-mode safety architecture for security work.

Design principles (each traces to a closed ticket):

- **The harness is the safety boundary.** The model is untrusted. Permission checks, scope
  enforcement, and audit logging happen in Go, at one choke point — the policy engine.
  The model suggests; the harness enforces. (#4)
- **One agent loop.** Subagents are tools inside it, never separate orchestrators; every
  tool call — built-in or MCP — passes the same policy gate. No agent framework. (#6, #5)
- **Scope is authorization; rules are limits.** The engagement file authorizes *targets*
  (scope); ROE flags are standing limits that hard-deny and are never promptable. (#7)
- **Execution never touches the host.** All tool execution happens in a per-session
  container; engagement scope is enforced at the container's network edge, not just in
  parameter checks. (#13)
- **Fail closed.** Audit-write failure denies the call; unparseable engagement files refuse
  to start; unenforceable isolation degrades visibly, never silently. (#7, #13)
- **Security tooling arrives as MCP servers; styx ships none.** The spec names recommended
  community servers with capability contracts. (#8, #14)
- **No self-updater, ever** — a security harness never rewrites its own binary. (#15)

### Platform & provider commitments

- Linux + macOS; static binaries, CGO disabled, amd64 + arm64, glibc-agnostic, macOS 13+.
- Model provider: **DeepSeek API** only in v1, pinned model IDs, OpenAI-compatible wire.
- Container runtime: Docker (Podman via compatible socket works but is untested).
- Source: `github.com/mobley-trent/styx-agent`, Apache-2.0.

### Locked technology picks (from the ecosystem research, #5)

| Concern | Pick |
|---|---|
| Agent loop | Hand-rolled — no framework (ADK-Go / LangChainGo / Eino rejected: their abstraction sits exactly where the policy engine must live) |
| LLM client | `openai-go` pointed at `https://api.deepseek.com` |
| TUI | Charm v2: Bubble Tea v2 + Lip Gloss v2 + Bubbles |
| MCP | Official `modelcontextprotocol/go-sdk` |
| Container exec / networking | Official Docker SDK for Go; host firewall programmed directly |
| Release engineering | goreleaser |

Gaps the project builds itself (its original value): policy engine + engagement-file
enforcement, permission-prompt UX, session persistence, skill-pack system, DeepSeek repair
layer, container egress enforcement.

---

## 2. Module layout

Per the scoping note on the assembly ticket (#11): project scaffolding is out of the map's
scope, but its design-level residue — module layout and package boundaries — is specified
here so the implementation effort starts mechanically. Boundaries follow the harness rule:
everything above the wire is harness; everything the model says is input.

```text
styx-agent/
├── cmd/styx/                # main package: flag/env parsing, root command
├── internal/app/            # startup wiring: config load, engagement gate, TUI boot
├── internal/agent/          # the agent loop: turn state, bounds, compaction integration
├── internal/agent/subagent/ # dispatch_subagent engine + preset registry
├── internal/model/          # ModelClient seam; openai-go→DeepSeek client; cache layout
├── internal/model/repair/   # strict-schema arg validation; structured-error repair layer
├── internal/mcpclient/      # MCP servers over stdio: discovery, calls, lifecycle (§5.5)
├── internal/policy/         # policy engine: rule table, JSON-pointer globs, ROE, verdicts
├── internal/diff/           # pure line diff for write/edit review (§9.2)
├── internal/engagement/     # engagement file load/validate, scope pins, DNS pinning
├── internal/containerlayer/ # per-session bridge, egress allowlist, fallback proxy, DNS
├── internal/tui/            # Bubble Tea program, stream, status bar, prompt cards, blocks
├── internal/sessions/       # session JSONL append-only store, resume
├── internal/memory/         # STYX.md load, engagement-notes appender
├── internal/skills/         # SKILL.md discovery (global+project), frontmatter parse
├── internal/skillpacks/     # the four packs: prompt sections, allowlist deltas
├── internal/config/         # global+project YAML merge, env secrets, defaults
├── internal/audit/          # session audit JSONL writer, fail-closed semantics
├── internal/update/         # release-latest check, per-source upgrade hint
└── internal/testdata/       # shared fixtures: transcript fixtures, stub-server cases
```

Package rules:

- **`internal/policy` is pure.** It imports nothing from `tui`, `model`, or `agent`. The
  engine is a total function: (tool call, mode, scope, rule table, clock) → verdict. This
  keeps the §11 policy tests table-driven and fast.
- **The `ModelClient` interface is the only path from the loop to the wire.** `agent`
  depends on the interface (declared beside the loop), never on the concrete DeepSeek
  client; `internal/model` implements it, `internal/model/repair` validates its tool-call
  output. Tests bind fakes and the stub server here (§11).
- **`internal/containerlayer` is the only package that touches the host network stack**
  (Docker networking, `nft`/`iptables`, the fallback proxy). Nothing else knows the
  mechanism, only the guarantee: egress = pinned scope, or visibly degraded.
- **All model- and policy-facing content is data**: system-prompt sections, skill-pack
  workflow text, SKILL.md files, transcript fixtures live under `internal/testdata/` or
  `embed`-ded data files, never as Go string literals — the post-v1 eval seam (§11) and the
  prompt golden snapshots both depend on this.

---

## 3. Model layer (DeepSeek)

Research: `docs/research/2026-09-28-deepseek-api.md`; decision #3. Environment facts
(live-verified): #10.

### 3.1 Provider & models

- Pin explicit model IDs — never aliases: **`deepseek-flash`** is the default;
  **`deepseek-v4-pro`** for hard reasoning. The configured IDs are validated against
  `GET /models` at startup; an unknown ID is a startup error.
- Model config carries the model's context-window size — the compaction trigger (§4.5)
  rescales automatically when the operator swaps models.
- Cost tracking uses the usage payload's `prompt_cache_hit_tokens` /
  `prompt_cache_miss_tokens` fields, with peak/off-peak price awareness.

### 3.2 The ModelClient seam

```go
// ModelClient is the ONLY path from the agent loop to the wire.
type ModelClient interface {
    // StreamTurn streams one model turn for the given request, yielding text
    // deltas, reasoning deltas, and tool-call descriptors as they arrive.
    StreamTurn(ctx context.Context, req ModelRequest) (<-chan StreamEvent, error)
}
```

The concrete signature may adjust during implementation; the seam's guarantees are the
contract: single model boundary; an in-process fake and an OpenAI-compatible stub server
both implement it; recorded-session replay is a stub-server mode (§11.2).

### 3.3 Wire behavior

- Native OpenAI-compatible tool calling, **strict mode on all built-in tools** (`strict:
  true`, `/beta` endpoint); thinking mode composes with tool calls; `reasoning_content`
  streamed and never shown as final answer text.
- **429/5xx handling:** jittered exponential backoff, max 5 attempts; SSE keep-alives must
  not be read as stalls.
- **Parallel tool calls capped at 8** per turn (the API allows 128; 8 keeps policy prompts
  reviewable).
- **Cache-aware prompt layout:** the system prompt + engagement context form a byte-stable
  prefix (never edited mid-session — see §4.5 and §7.4) so DeepSeek's exact-prefix cache
  stays warm; the compaction design engineers churn away (low watermark, no rolling
  summarization).
- **Censorship posture:** topic-level (politically sensitive) censorship exists in the
  model; no evidence of refusal of offensive-security tasks. Design consequence already
  absorbed: the harness enforces everything; nothing safety-critical relies on model
  cooperation. Engagement data transits DeepSeek infrastructure — **secrets never enter
  model context** (§5.1, §10.5).

---

## 4. Agent loop

Decision #6, amended by #12 (auto-compaction). One hand-rolled loop; no framework.

### 4.1 Turn cycle

System-prompt assembly → model call (streaming) → repair/validation of tool calls →
policy-engine verdicts → tool dispatch (parallel up to 8) → tool results appended → repeat,
until the model returns a final answer or a bound trips.

- **Strict mode + repair layer:** every tool-call argument is validated against the tool's
  JSON schema. Invalid arguments produce a structured error fed back to the model —
  **max 2 repairs per turn**, then the turn aborts with a TUI-visible error.
- **Bounds (config-overridable):** main loop **200 turns**; each subagent run **40 turns**.
- Tool execution happens only inside the session container (§5.2); web tools run through
  harness-side fetchers, not the container.
- Every tool call's verdict is audit-logged (§7.5) *before* execution; fail closed on
  audit-write error.

### 4.2 Subagents

`dispatch_subagent` exposes an isolated-context agent run as an ordinary tool:

- A role is (system prompt, tool allowlist, turn bound). **One nesting level** — subagents
  never receive `dispatch_subagent`.
- The report returns as the dispatch tool result.
- Subagent tool calls pass the same policy engine; their permission prompts surface in the
  main TUI stream with subagent attribution (user decision, #6).
- Built-in role presets: `coder`, `recon`, `exploit-dev`, `log-triage` — see §5.4.

### 4.3 Streaming & events

Model deltas, tool starts, verdicts, results, compaction events, and subagent activity are
emitted as typed events on a session event bus; the TUI (§9) and the session JSONL (§10.1)
are both consumers. Nothing renders that isn't also persisted.

### 4.4 Turn aborts and errors

Model transport failure after retries, repair-layer exhaustion, or a hard deny that makes
the turn incoherent aborts the turn with a visible error card; the session stays resumable.

### 4.5 Context management & compaction

Three layers, in order:

1. **Tool-output truncation at capture** (configurable cap) — the first line always
   survives so eviction summaries stay meaningful.
2. **Auto-compaction, default-on** (`compaction.mode: auto|manual`), firing **only between
   turns** at **85% of the model's context window**; hysteresis requires freeing ≥25 points
   (down to ≤60%) before the trigger re-arms. Progressive strategy: **tool-result eviction
   first** (keep first-line summaries); **LLM summarization of the oldest segment** only if
   still >80%, targeting a ~50% watermark. Last `keep_turns` (default 10) stay verbatim.
   Fires without asking, notifies after: inline stream card, status-bar level, session-JSONL
   event. `/compact` remains the manual override and accepts a custom instruction.
3. **Never compacted, ever:** system prompt, STYX.md, engagement context, ROE state, audit
   trail. The model may forget a file listing; never an authorization boundary.

Cache economics: compaction invalidates the exact-prefix cache once (~one-time cost); the
hysteresis band, byte-stable prefix, low watermark, and no-rolling-summarization rule keep
churn engineered away. #12.

---

## 5. Tools

Decisions #6 and #8; the assembly ticket's fold note adds the skill tool here (#11).

### 5.1 Built-in tool set (v1)

| Tool | Purpose | Network? |
|---|---|---|
| `read_file` / `write_file` / `edit_file` | file ops in the session workspace (container FS) | no |
| `glob` / `grep` | repo orientation primitives | no |
| `bash` | shell commands, container-only | container egress rules apply |
| `code_exec` | multi-language snippets (`lang` parameter; python3 first) against runtimes present in the container image | container egress rules apply |
| `web_fetch` | harness-side URL fetch | scope-checked |
| `ssh_logs` | read-only remote log fetch over SSH; harness-enforced read-only command allowlist (cat/tail/grep/zgrep-class) | scope-checked |
| `dispatch_subagent` | spawn a role-preset subagent | n/a (delegates to its tools) |
| `skill` | invoke a loaded agent skill (§8.4) | delegates to its steps |

One exec surface per mechanism: `bash` for shell, `code_exec` for language runtimes.
Strict mode applies to all built-ins; the repair layer validates their arguments.

### 5.2 Execution isolation (applies to `bash` and `code_exec`)

All exec runs in a **per-session container** (never the default bridge, never host
networking):

- **Egress enforcement:** the harness programs an nftables/iptables allowlist (prefer `nft`
  backend; detect and fall back) in `DOCKER-USER`/`FORWARD`, scoped to the session's bridge
  interface, derived from the engagement scope's pinned IPs plus the run's own needs
  (model-provider endpoint, package mirrors). Cleaned up on session end. #13.
- **DNS:** the harness is the authoritative resolver for scope — hostnames resolve once at
  engagement load, IPs are pinned, and every network call's actual destination must land in
  the pinned set (rebinding dies at the egress drop). Egress is IP-based, so container-side
  resolver differences cannot widen scope.
- **Degraded isolation (v1, clearly labeled):** when the host firewall can't be programmed
  (no privileges, remote socket, macOS runtimes without a programmable netns), the
  container runs with **no external network** plus a **harness-local egress proxy** that
  resolves destinations itself and forwards only to pinned scope IPs. Degradation is
  surfaced three ways, never silently: status-bar indicator, one-time stream banner, audit
  entry. #13.
- **v1.x hardening path (specced, not required):** user-space netstack (gVisor-style) as
  the container's only network path — no host-firewall dependency, identical on macOS.
- Container egress failure = tool-level denial with reason, audited as a hard deny.
- The harness never mounts the host Docker socket into the session container.

### 5.3 Tool-call flow (normative order)

```
model tool call → schema validation (repair layer) → policy engine verdict
  → audit write → dispatch (container or harness) → result/truncation → model
```

Nothing bypasses this order — MCP tools included.

### 5.4 Subagent presets (built-in)

| Preset | Tools | Network |
|---|---|---|
| `coder` | fs + bash/code_exec | none |
| `recon` | web_fetch + bash + fs-read | scope-checked |
| `exploit-dev` | exec + fs + web_fetch | scope-checked, engagement-gated |
| `log-triage` | fs-read + code_exec | none |

None receive `dispatch_subagent`. Presets are pack-agnostic (§8.5).

### 5.5 MCP tools

MCP servers arrive as ordinary tool descriptors and pass the same policy gate; the harness
validates MCP tool arguments itself regardless of server-side strictness. Recommended
servers per pack: §8.6. styx ships none.

Implementation: servers are configured per project under `mcp.servers` in
`.styx/config.yaml` (`name`, `command`, `args`, `env`, `disabled`), launched over stdio via
the official Go SDK, and their tools registered as `mcp__<server>__<tool>`. An MCP tool
call follows the same normative order as any built-in (§5.3) — schema validation against
the server's own advertised input schema, then the policy engine, then the audit write,
then dispatch — and the tool name family is addressable by the rule table (`mcp__*`,
`mcp__<server>__*`). A malformed call is repaired or denied by the harness and never
passed through. Connection lifecycle (connecting / ready / failed / closed) is emitted on
the session bus and rendered in the stream and the status line; a server that fails to
launch or disconnects mid-session is a visible tool-level error, never a loop crash.

---

## 6. Policy engine & permission model

Decisions #6 and #7. This is the single choke point of the entire safety model — a pure
decision function (§2): (tool call, mode, scope, rule table, clock) → verdict.

### 6.1 The three-action rule table

Every tool call resolves to exactly one verdict: **allow / prompt / deny**.

- Keys: tool name + glob matchers over JSON-pointer parameter paths — e.g. `bash.command`,
  `web_fetch.url`.
- Spec-defined default tables per mode; an optional project config overlay
  (`.styx/config.yaml`) adds custom rules. Precedence: deny > prompt > allow; project rules
  may narrow defaults and may widen prompts to allows, but **may never weaken the ROE
  hard limits (§6.3) or engagement scope checks**.
- The engagement file authorizes **scope only, never tool rules**.

### 6.2 Mode interaction

- **Safe mode (default):** permissive reads, guarded writes/exec/network — consequential
  actions prompt.
- **Engagement mode** (active only after passing the engagement gate, §7.2):
  - engagement active **and** target in scope → **auto-allow, audit-logged**;
  - target out of scope → **prompt** (the operator consciously widens by editing the
    engagement file); 
  - ROE violations → **hard deny, never promptable**;
  - the mode flag alone widens nothing.
- **Plan-block pre-authorization** (§9) skips per-step prompts for the actions a plan
  lists, but never overrides hard denies, ROE violations, or scope checks.

### 6.3 ROE hard limits

From the engagement file's ROE flags (§7.1):

- `exploit_allowed: false` → exploit-class tooling hard-denied even in-scope in engagement
  mode (recon/scan unaffected).
- `destructive_forbidden: true` → destructive-tagged calls hard-denied (rm-class exec,
  destructive payloads). RE sample detonation is destructive-tagged (§8.3).
- `time_window` → network/exec outside the window denied regardless of scope.

ROE is a standing limit, not a per-call ask.

### 6.4 Permission prompts

When the verdict is prompt: an inline TUI card (§9.3) with **allow-once / allow-this-
session / deny-this-session**. Session-scoped only; the prompt flow never writes
persistent config.

### 6.5 Audit

Every verdict is written to the per-session audit JSONL (§7.5) **before** execution;
a failed audit write denies the call. Fail closed.

---

## 7. Engagement file & safety model

Decision #7, activation wording amended by #9.

### 7.1 File format

`engagement.yaml` — hand-authored, version-controlled, machine-validated:

```yaml
apiVersion: styx.engagement/v1
name: acme-q4-redteam          # label; appears in TUI + audit entries
operator: eddy                 # informational; recorded in audit (not an auth mechanism)
expires: 2026-10-15T23:59:59Z  # optional; stale = refuse to start. Absent = evergreen
targets:                       # single authorization pool — flat, no groups
  - 10.0.0.0/24                # CIDR
  - 192.0.2.44                 # IP literal
  - app.acme.example           # hostname: resolved once at load, IP pinned into scope
roe:                           # machine-checked flags only — nothing expressive-but-unenforced
  exploit_allowed: true        # master gate for exploit-class tooling
  destructive_forbidden: true  # hard-denies destructive-tagged calls
  time_window:                 # optional; outside window denied regardless of scope
    start: "08:00"
    end: "18:00"
    tz: America/New_York       # explicit tz; default UTC if omitted
```

Scope match: in scope iff the target matches any pool entry — IP literal, containing CIDR,
or pinned hostname/IP. Wildcard domains use the `*.acme.example` form, matched against the
pinned IP set their expansion resolves to at load.

### 7.2 The engagement gate

- **Strict, refuse-to-start validation**: file must parse, every target must resolve, ROE
  flags must come from the closed v1 set. No partial scopes.
- **Activation only via the engagement gate**: `styx --engagement <file>` at launch, or
  `/engagement` in-session (a picker over discovered engagement files). The two doors are
  the same gate — same validation, same refusal. Forgetting the flag means safe mode,
  never the reverse. No ambient auto-detection.
- At validation, hostnames resolve once; resolved IPs are pinned. Every network call
  re-resolves the actual destination and must land inside the pinned IPs (rebinding
  defense; enforced again at the container edge, §5.2).

### 7.3 Deactivation

`/mode` returns to safe mode; the engagement context (including its pins and container
egress rules) is torn down. Session ends also tear down (§5.2 cleanup).

### 7.4 Model visibility

The harness injects a scope summary (targets, ROE flags, expiry) into the system prompt —
**advisory self-restraint only**; all enforcement stays in the policy engine and the
container egress layer. This section participates in the byte-stable prompt prefix (§3.3):
it is set at gate activation and never mutated mid-session.

### 7.5 Audit log

- Per-session JSONL: `styx-audit-<timestamp>.jsonl` in the project dir. One JSON object
  per decision: timestamp, mode, tool name, **full verbatim params**, verdict
  (allow / prompt / allow-once / allow-session / deny / hard-deny), reason (in-scope match,
  ROE flag, rule-table entry), subagent attribution, isolation state.
- The audit file is the forensic record of what the agent attempted; local and
  operator-owned. Secrets and real engagement targets never leave the operator's machine
  except into the audit file itself.
- **Fail closed**: audit-write failure denies the tool call.
- Engagement end appends a timestamped engagement-notes block to STYX.md (§10.2).

---

## 8. Skill packs & MCP

Decisions #8 and #14; the skill tool fold note (#11).

### 8.1 What a pack is

A pack = **workflow prompt sections + tool-allowlist deltas + tailored subagent-preset
references**. No new harness surface — packs reuse the role-preset engine (§4.2). All four
ship in v1 and are **always available**; there is no persona or mode switching.

### 8.2 Composition & activation

- **Layered system prompt:** coding workflow guidance is always present. Each security
  pack contributes a compact always-on guidance section plus its MCP tools; the harness
  injects a pack's **full workflow section** when its domain is detected — engagement
  active → red team; RE MCP server connected → RE; log/IR artifacts opened → blue team.
- The harness decides injection; the model never selects packs. Pack state is visible in
  the TUI status bar (§9.2). Injection happens at session start / gate activation and is
  part of the byte-stable prefix — never swapped mid-session.

### 8.3 The four packs

- **Coding** (the Claude Code core): inner-loop workflow prompts — plan → edit → test →
  iterate, diff-before-apply discipline, repo orientation (glob/grep-first), test-running
  norms. Tools: the built-in set, no network beyond `web_fetch`. Default preset: `coder`.
- **Red team — four-phase lifecycle:** recon (passive→active) → enumeration/scanning →
  exploitation (**hard-gated by `exploit_allowed`**) → post-exploit (privesc, persistence
  *documentation*, reporting). Each phase's workflow prompt names its tools, which preset
  to dispatch (recon phase → `recon`, exploit-dev phase → `exploit-dev`), and **stop
  conditions** (ROE boundaries, time_window, scope edges).
- **RE & malware — static default, detonation gated:** static analysis (Ghidra headless /
  radare2 via MCP; decompile, xref, binary-diff workflows) runs in the default container.
  **Any dynamic execution of analyzed samples is destructive-tagged**: requires engagement
  mode **and** an explicit prompt — never auto-allowed even in-scope in engagement mode.
- **Blue team — analyst co-pilot:** local-files co-pilot (log parsing/triage via fs-read +
  `code_exec`), IR playbook checklists as workflow prompts, forensic artifact guidance via
  MCP (Volatility-class). Adds nothing to the tool set beyond `ssh_logs` (§5.1).

### 8.4 Agent skills (SKILL.md) — and the skill tool

Distinct from packs (CONTEXT.md). styx-agent reads the SKILL.md format (compatible with
`~/.agents/skills`):

- **Discovery:** global (`~/.agents/skills`, XDG-equivalents honored) + project
  (`.styx/skills`); project skills shadow global ones on name collision.
- **Invocation:** the user via a `/skills` picker or `/<skill-name>`; the model via a
  dedicated **`skill` tool** (§5.1), exposed only for skills carrying model-invocation
  metadata in their SKILL.md frontmatter.
- **skill tool schema** (strict mode, repair layer applies as to any tool):

  ```json
  {
    "name": "skill",
    "parameters": {
      "type": "object",
      "properties": {
        "skill":     { "type": "string", "description": "Skill name (directory/SKILL.md slug)" },
        "reason":    { "type": "string", "description": "Why this skill fits the current task" },
        "args_json": { "type": "string", "description": "A JSON object string of arguments for the skill's steps ({} for none): strict mode rejects a free-form object, so it is carried as a string, like propose_plan's params_json" }
      },
      "required": ["skill", "reason", "args_json"],
      "additionalProperties": false
    }
  }
  ```

- **Feedback into the loop:** a skill's steps are **workflow prompt content** — on
  invocation the harness loads the skill's SKILL.md body and returns it as the tool result
  (plus any args echoed back), so the model executes the steps with its ordinary tools
  under ordinary policy. A skill is never a code plugin; it cannot grant tools or widen
  policy. Skill-file writes follow normal write/edit rules; project skills allow the agent
  to add skills for a repo.

### 8.5 Presets and packs

Packs **reuse the four built-in presets** (coder, recon, exploit-dev, log-triage); pack
workflow prompts reference which preset to dispatch per phase; presets stay pack-agnostic.

### 8.6 Recommended MCP servers (capability contracts)

styx ships no MCP servers; the spec names concrete recommendations (survey: #14, details in
`docs/research/2026-09-28-security-mcp-servers.md`). Any conformant server works; users pin
their own.

| Pack | Need (capability contract) | Recommended | Alternative |
|---|---|---|---|
| Red team | port scanning / service enumeration (standard scan types, structured output) | `vorota-ai/nmap-mcp` | `PhialsBasement/nmap-mcp-server`; `cyproxio/mcp-for-security` (SQLMap/FFUF/Masscan extras) |
| RE | decompile / xrefs / rename-retype on loaded binaries | `LaurieWired/GhidraMCP` | `cyberkaida/reverse-engineering-assistant` (ReVa) |
| RE (headless, containerized) | project-wide multi-binary analysis without the GUI | `pyghidra-mcp` | — |
| Blue team | memory/forensic artifact analysis (Volatility 3 plugin coverage) | `OMGhozlan/Volatility-MCP-Server` | `Kirandawadi/volatility3-mcp`; `0xhackerfren/Windows-Memory-Forensics-MCP` |
| Blue team (logs) | log triage | — | covered by built-ins (`fs` + `code_exec` + `ssh_logs`); no log MCP recommended |

radare2 MCP servers are thin/experimental — r2 stays a container CLI via `bash`. ghidra /
r2 are user-installed prerequisites (JDK 17 present satisfies Ghidra 11.x; #10).

---

## 9. Terminal UI

Decision #9. Charm v2 stack (Bubble Tea v2 + Lip Gloss v2 + Bubbles).

### 9.1 Layout

**Chat-centric scrolling stream**: model output, tool results, diffs, subagent activity,
prompt cards, and system banners render inline in one stream. A persistent one-line status
bar always shows: operating mode (safe/engagement), active pack, model, isolation state
(container ok / degraded), compaction level, and in-scope targets when engaged.

### 9.2 Diffs & plan flow

- Every write/edit renders a syntax-highlighted diff inline with per-diff Accept / Reject
  plus accept-all-rest-of-turn.
- A proposed multi-step plan renders as a **plan block** before execution begins. Approval
  is **turn-scoped pre-authorization**: it authorizes exactly the actions the plan lists
  for that turn (skipping their per-step prompts) — and never overrides hard rules: ROE
  violations and deny-rule matches still hard-deny, out-of-scope network targets still
  prompt, anything not in the approved plan prompts normally. No separate plan mode in v1.

### 9.3 Permission prompts

Inline cards at the point the action occurred: tool name, parameters, risk class
(including ROE-check result), subagent attribution if any, and the session-scoped options
(§6.4). Keyboard-first (y/n/a), mouse-clickable; scrolling context stays visible above.

### 9.4 Slash commands

Core ten: `/help` `/compact` `/clear` `/resume` `/model` `/mode` `/engagement` `/pack`
`/status` `/memory` — plus `/skills` and `/<skill-name>` for agent skills (§8.4).

### 9.5 Degraded isolation & subagent rendering

- Degraded isolation surfaces three ways: persistent status-bar indicator, one-time
  prominent stream banner (stating what is restricted), audit entry.
- Subagents render as inline collapsible blocks: spinner + live preview line while
  running, expandable to full transcript. Their permission prompts surface in the main
  stream with attribution.

### 9.6 Themes

One polished dark theme + one light variant, auto-selected from terminal background
detection; no user theme config in v1.

---

## 10. Storage: sessions, memory, config

Decision #9; compaction session events from #12.

### 10.1 Sessions

- One **append-only JSONL file per session** under `~/.local/share/styx/sessions/<project>/`
  — messages plus tool calls/results, compaction events, engagement gate activations.
  Crash-safe, inspectable. Nothing renders in the TUI that isn't persisted.
- `/resume` opens a picker over past sessions for the project.
- **Compatibility contract:** session JSONL is same-major compatible — new event types
  additive, readers tolerate unknown keys.

### 10.2 Project memory (STYX.md)

- `STYX.md` at the repo root, auto-loaded into the system prompt (CLAUDE.md-style);
  user- and agent-editable under normal write rules.
- At engagement end, the harness appends a **timestamped, structured engagement-notes
  block** (targets, model-flagged findings, artifacts produced). Never silent, never
  model-invented after the fact.

### 10.3 Config

- YAML throughout: global `~/.config/styx/config.yaml`, per-project overlay
  `.styx/config.yaml`. Project wins on conflict. Consistent with `engagement.yaml`.
- Keys named by decisions: `model` (pinned IDs), permission-rule overrides,
  `compaction.mode` (default `auto`) / `compaction.threshold` (0.85) /
  `compaction.keep_turns` (10), `update_notifier` (default on).
- New keys additive; readers tolerate unknown keys (same-major contract).

### 10.4 Skills directories

Global `~/.agents/skills` (XDG-equivalents honored) + project `.styx/skills`; project
shadows global on name collision (§8.4).

### 10.5 Secrets

**Env-only.** `DEEPSEEK_API_KEY` from the environment; never in config files, never in
model context, never persisted by styx.

---

## 11. Testing & evals

Decision #16. CI gate: GitHub Actions, every push/PR to `main`.

### 11.1 Per-commit gate

1. `go vet` + `golangci-lint`.
2. `go test -race ./...` covering:
   - **Policy-engine unit tests** — rule-table matching, JSON-pointer glob semantics,
     per-mode defaults vs project overlay, allow/prompt/deny resolution, ROE hard-deny vs
     out-of-scope prompt distinction.
   - **Engagement-gate refuse-to-start tests** — malformed YAML, unresolvable targets,
     unknown ROE flags, stale `expires`.
   - **Agent-loop integration tests** against the faked model — turn caps (200/40),
     parallel cap (8), 429/5xx backoff, repair-layer bounds (2 repairs → turn abort),
     subagent preset allowlists, compaction triggers (85% + 60% re-arm hysteresis), audit
     JSONL shape + fail-closed on write error.
   - **Prompt golden snapshots** — byte-exact rendered system prompt per
     (mode × skill pack × engagement-state) combination; guards the byte-stable prefix the
     cache economics and engagement framing depend on; asserts the engagement scope-summary
     injection renders.
3. **Container-egress tests** run in the same gate on `ubuntu-latest` (root VMs with
   Docker): hermetic — the "allowed target" is a self-spun helper listener, the "denied
   target" an unroutable TEST-NET address; no real internet. Tests `t.Skip` gracefully
   when privileges/firewall backend are absent (local macOS runs). The degraded fallback
   (egress proxy) is pure Go: its tests are unconditional, run everywhere.

### 11.2 The model is faked on one seam

- **`ModelClient`** (§3.2) is the only path from the loop to the wire.
- **Layer 1 — fake model:** in-process implementation, per-test scriptable (canned
  responses, fault injection, turn counting). All loop/policy/compaction tests use it; no
  test talks to a live model.
- **Layer 2 — stub server:** in-repo OpenAI-compatible stub (Go `httptest`, runnable
  standalone) speaking real SSE + `tool_calls` + strict-mode behavior, with injected
  faults (429s, malformed tool-call JSON). Covers the openai-go client path and the repair
  layer.
- **Recorded replay is a mode of the stub server** — it serves captured transcripts
  instead of a live model. No third replay mechanism.

### 11.3 Fixtures

- A repo script copies a session JSONL → **scrubs** it (secrets, real engagement targets —
  engagement data never enters the repo) → normalizes into a **versioned transcript
  format** (CONTEXT.md: transcript fixture).
- Fixtures live in the shared `internal/testdata/transcripts/`; stub-replay and driver
  tests consume the same files.
- No shipped record mode in the harness — capture is "run a session, run the script".

### 11.4 Evals: deferred, seam kept

- **Automated quality evals deferred post-v1** (nondeterministic, costly, flaky in CI).
- Seam kept: prompts and skill-pack content stay **pure data** (§2) so a future eval
  harness slots in without rework.
- v1 ships a **manual pre-release smoke checklist**: one short curated task per pack
  (coding, red team, RE, blue team), run by hand against live DeepSeek before cutting a
  release.

### 11.5 Explicitly outside the v1 bar

Live-model calls anywhere in CI (never); automated quality evals (deferred); fuzzing
(post-v1; first targets: engagement-file parser, rule-table glob matcher, repair-layer
argument validator); TUI end-to-end automation beyond a launch smoke test; coverage gates
(report only); concurrency chaos tests of the firewall layer.

---

## 12. Distribution & updates

Decision #15; release engineering pick from #5.

### 12.1 Install surfaces

| Surface | OS | Status |
|---|---|---|
| Homebrew tap → `brew install mobley-trent/styx/styx` | macOS 13+ | **Blessed** |
| Install script → `~/.local/bin` | Linux | **Blessed** |
| GitHub release archives (per-arch tar.gz, documented verification) | both | works-but-unsupported |
| Manual binary download | both | works-but-unsupported |
| Linuxbrew via the same tap | Linux | works-but-unsupported |
| `go install github.com/mobley-trent/styx-agent@latest` | both | works-but-unsupported |
| Community AUR package | Arch | unsupported third-party |

- The tap repo (`mobley-trent/homebrew-styx`) is created once when the release pipeline
  lands; goreleaser pushes the formula from then on.
- Linux blessed path: `curl -fsSL https://raw.githubusercontent.com/mobley-trent/styx-agent/main/install.sh | sh`
  — picks arch, verifies the checksum, installs to `~/.local/bin`.
- `go install` builds may report `devel` from `debug.ReadBuildInfo`; the update notifier
  is disabled for source builds.

### 12.2 Release verification

- goreleaser publishes SHA256SUMS always, signed with **keyless cosign** (GitHub Actions
  OIDC). The install script verifies checksums automatically; the README documents
  `cosign verify-blob` for the manual path.
- **No macOS notarization in v1** (brew/curl downloads carry no quarantine xattr);
  document the `xattr -d com.apple.quarantine` workaround for browser downloads.

### 12.3 Update channel

- **No self-updater, no auto-update — a standing rule.** `styx update` compares current vs
  latest release and prints the exact upgrade command for the detected install source
  (gh-CLI style).
- TUI update notifier: a single fetch of the GitHub releases-latest endpoint, nothing else
  leaves the machine. Opt out via `update_notifier: false` or `STYX_NO_UPDATE_NOTIFIER=1`.
  Auto-disabled for source builds and **while engagement mode is active**.
- Channels: **stable only** — SemVer git tags → GitHub Release → tap + script updated by
  the same goreleaser pipeline. No nightly/beta/LTS.

---

## 13. Out of scope (v1)

Ruled beyond this destination (map: Out of scope; #2, #15, #16). Each returns only as a
fresh effort if the destination is redrawn:

- **Windows support** — Linux + macOS only in v1.
- **Project scaffolding as a map activity** — the implementation effort's first act (§2 is
  its blueprint).
- **SOC integrations, vector memory, agent swarms** — named at charting; none in v1.
- **Self-updater / auto-update** — standing rule, not a v1 simplification (§12.3).
- **User-space netstack egress (gVisor-style)** — specced as the v1.x hardening path
  (§5.2), not required for v1.
- **Automated quality evals, fuzzing, TUI e2e automation** — post-v1 (§11.4–11.5).
- **macOS notarization, nightly channels, additional model providers** — v1.x+ territory.

---

## 14. Decision index

Every spec section traces to one closed wayfinder ticket on
[the map](https://github.com/mobley-trent/styx-agent/issues/1):

| Ticket | Decision |
|---|---|
| #2 | Buildable spec as destination; Go; Linux+macOS; distributable; this repo |
| #3 | DeepSeek v1 provider; pinned IDs; strict mode; repair layer mandatory; censorship posture |
| #4 | Dual-mode safety; engagement file; container isolation; harness-enforced, model untrusted |
| #5 | Stack: no framework, openai-go, Charm v2, official MCP Go SDK, Docker SDK, goreleaser |
| #6 | One loop, subagents-as-tools; built-in tool set; rule table; bounds; presets |
| #7 | engagement.yaml schema; strict gate; DNS pinning; ROE hard denies; audit JSONL fail-closed |
| #8 | Pack anatomy; layered prompts; MCP-first; four pack designs; ssh_logs; detonation gating |
| #9 | Stream + status bar TUI; diffs; plan block; prompt cards; slash commands; skills; sessions; STYX.md; config; themes |
| #10 | Environment verified live (DeepSeek tool calls, Docker, nftables, MCP runtimes); zero blockers |
| #11 | This assembly: module layout (§2) and skill tool (§5.1, §8.4) folded in |
| #12 | Auto-compaction default-on; 85% trigger, 60% re-arm; progressive strategy; engagement never compacted |
| #13 | Per-session bridge + DOCKER-USER egress allowlist; DNS authority; degraded fallback surfaced; v1.x netstack |
| #14 | Recommended MCP servers per pack; styx ships none |
| #15 | Blessed install paths; cosign verification; no self-updater; stable only; compat contract |
| #16 | CI gate; ModelClient fake + stub server + replay; egress tests; scrubbed fixtures; evals deferred |

Research artifacts: `docs/research/2026-09-28-deepseek-api.md`,
`docs/research/2026-09-28-go-ecosystem.md`,
`docs/research/2026-09-28-security-mcp-servers.md`.
