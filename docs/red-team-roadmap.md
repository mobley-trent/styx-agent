# styx — v1.x red-team capability roadmap

Decided by [Decide the v1.x red-team capability roadmap](https://github.com/mobley-trent/styx-agent/issues/61)
(child of the map [Wayfinder: styx prototype → adoptable red-team agent](https://github.com/mobley-trent/styx-agent/issues/53)),
on the fact base of [Capability gap: styx vs OpenCode / Pentestcode / Strix](https://github.com/mobley-trent/styx-agent/issues/60)
(`docs/research/2026-10-05-capability-gap-opencode-pentestcode-strix.md`).

The destination is to close the gap to OpenCode / Pentestcode / Strix — an "ultimate
red-team agent" — **without** giving up the harness as the safety boundary. Every capability
below is subordinate to the existing invariants: one policy choke point, scope is
authorization, ROE flags hard-deny and are never promptable, execution stays in the
per-session container at the pinned network edge, and audit is fail-closed. The capabilities
that would break those invariants are explicitly declined (§4).

This document is the decided roadmap. Concrete designs graduate onto the map as tickets;
implementations follow once each design is decided.

## 1. Adopted capabilities

### Substrate — v1.1

1. **Persistent engagement state + evidence model.** A per-engagement structured store —
   hosts, services, findings (severity, status, evidence, confidence), credentials, access,
   segments — that survives sessions and feeds the prompt. Lives *inside* the engagement
   boundary and reuses the existing gate. Never compacted away, never model-invented
   (spec §4.5, §10.2).
2. **Parser-backed pentest tools.** `nmap_parse`, `nuclei_parse`, `sqlmap_parse`,
   `gobuster_parse`, `cme_parse`, `bloodhound_parse`-class tools that write structured
   findings into engagement state, with Pentestcode's *parser-mandatory-after-CLI* invariant.
   Built into the harness rather than delegated to MCP because the parser→state invariant is
   a harness concern.
3. **Relationship graph + attack-path reasoning.** Typed entity edges (`CREDENTIAL_FROM`,
   `ADMIN_OF`, `PIVOT_TO`, …) plus a cost-based path search (Dijkstra + Yen's K-shortest,
   K=3) with confidence/OPSEC modifiers. A pure computation over engagement state; paths are
   surfaced as *suggestions*, never auto-executed steps.

### Operating surface — v1.2

4. **Preloaded offensive sandbox image.** Replace `python:3.12-slim` with a styx-maintained,
   cosign-published security image (nmap, nuclei, ffuf, sqlmap, semgrep, trivy, …), still
   egress-pinned by the existing firewall layer. The single highest-leverage match for
   Strix's out-of-the-box toolkit without adopting its weaker governance.
5. **Headless / CI mode with severity gating.** `-n/--non-interactive`;
   `--fail-on critical|high|medium|low|info` exiting `2` at/above threshold (exit codes
   0/1/2); `vulnerabilities.json` / `.csv` and `findings.sarif` (SARIF 2.1.0); diff-scoped PR
   scans (`--scope-mode diff`, `--diff-base`).
6. **USD budget cap.** A `--max-budget`-style cumulative ceiling across root and child agents
   with graduated wrap-up warnings, enforced on the cost signal styx already tracks.
7. **Exploitation-phase orchestration within the ROE.** Exploitation runs as a state-driven
   phase that is auto-allowed when in-scope + engagement mode (as every in-scope action
   already is), with destructive actions still prompting; plus an explicit engagement-file
   **exploitation autonomy level** an operator may set to widen in-scope exploit approval.
   See [ADR-0003](adr/0003-autonomous-exploitation-boundary.md).

### Reach — v1.3

8. **Browser + HTTP-proxy tooling.** A Playwright-class browser and a Caido/Burp-class
   interception/replay proxy, scope-checked like any network tool.
9. **OpenAPI/Postman-driven API testing.** An API spec can be a target; its declared base
   URLs are authorized inside the engagement.
10. **Report generation + local run viewer.** Markdown/JSON (later SARIF) generated from
    engagement state; a `view`-class viewer over the existing session/audit JSONL.
11. **Specialist subagents + parallel orchestration.** Add webapp, identity (AD), post-exploit,
    and critic presets with context carry. **One nesting level is retained for now** (spec
    §4.2); deepening it stays a conscious later decision.
12. **Web search / OSINT tool.** A scope-checked network tool.
13. **MCP remote/HTTP transport + OAuth.** Extend `internal/mcpclient` beyond stdio, behind
    the same policy gate.
14. **Child-session UX.** Expose subagent runs as inspectable sessions.
15. **Provider breadth + per-agent model routing.** General OpenAI-compatible endpoints, a
    per-agent model override, and a small model for title/summary work; DeepSeek stays the
    default. See [ADR-0002](adr/0002-provider-breadth-and-per-agent-routing.md).

## 2. Sequencing

| Release | Contents |
|---|---|
| **v1.1 — substrate** | Persistent engagement state + evidence model; parser-backed tool contracts; relationship graph + attack-path reasoning |
| **v1.2 — operating surface** | Preloaded offensive sandbox image; headless/CI + `--fail-on` + structured output; USD budget cap; exploitation-phase orchestration + ROE autonomy level |
| **v1.3 — reach & providers** | Browser + proxy; OpenAPI/Postman; reports + run viewer; specialist subagents + orchestration; web search/OSINT; MCP remote/OAuth; child-session UX; provider breadth + per-agent routing |

The substrate lands before anything that writes to it, and each phase is reviewable behind
the safety invariants before the next opens.

## 3. Partial adoption

- **Auto-select skills per agent — partial.** Harness-selected packs stay authoritative; the
  model gets *ranked per-agent skill suggestions* surfaced in the prompt, not the selection.
  Reserved for the design work that follows the substrate.

## 4. Declined — out of scope for v1.x

- **Plugin / arbitrary custom-tool API (OpenCode).** Contradicts the single policy choke
  point and the "a skill is workflow text, never a plugin" invariant (spec §5.3, §8.4).
  Extensibility extends MCP instead.
- **LSP integration.** Low value for a red-team-first harness; OpenCode's own docs call it
  "not always a net positive" and Pentestcode removed it.
- **Public session sharing.** Incompatible with an audit trail and engagement targets that
  must never leave the operator's machine (spec §7.5, §10.5).
- **Self-updater / auto-update.** Standing rule (spec §12.3).
- **Desktop app / IDE plugins / ACP / Windows.** Outside the terminal-first, Linux+macOS
  scope (spec §13).
- **Strix Cloud / enterprise surfaces, autofix-to-PR.** Local-first OSS; autofix also
  conflicts with engagement scoping and the "never silent" audit posture.
- **`free` mode bypassing scope checks (Pentestcode).** Actively unsafe; scope is
  authorization enforced in the harness (spec §1, §6.2).
- **Full autonomy: engagement mode alone removing the exploitation prompt.** The harness
  stays the safety boundary (ADR-0003).
- **Cross-engagement learning / global knowledge store.** Deferred — a security harness
  exporting engagement-derived knowledge is a data-governance problem. Local-only if
  revisited.

## 5. Open — designs yet to be decided

Graduated as tickets on the map, or still in its fog: the findings/state schema, parser→state
contracts, graph/path algorithm (substrate); headless severity-gating details and sandbox-image
contents (operating surface); and the reach and provider designs.
