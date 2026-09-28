# Security MCP server survey — 2026-09-28

Research ticket: https://github.com/mobley-trent/styx-agent/issues/14
Context: skill-pack decision in https://github.com/mobley-trent/styx-agent/issues/8

Verdict: every capability contract named in the skill-pack decision is satisfiable
today with existing community MCP servers. styx-agent ships none of them (MCP-first
decision) and only recommends. All are community-maintained, stdio transport,
heterogeneous quality — users pin their own versions.

## Red team (recon / scanning)

| Server | Notes | Verdict |
|---|---|---|
| `vorota-ai/nmap-mcp` | Production-grade nmap wrapper; standard scan types, actively maintained | **Recommended** |
| `PhialsBasement/nmap-mcp-server` | Older, simpler nmap wrapper | Alternative |
| `cyproxio/mcp-for-security` | Collection: SQLMap, FFUF, NMAP, Masscan and more | Optional extras for recon/scan |

Satisfies the port-scanning / service-enumeration capability contract.

## Reverse engineering

| Server | Notes | Verdict |
|---|---|---|
| `LaurieWired/GhidraMCP` | De-facto standard; v2.x, ~110 tools (decompile, disasm, xref, rename, retype); large active community | **Recommended** |
| `cyberkaida/reverse-engineering-assistant` (ReVa) | Ghidra MCP with more workflow-shaped tools | Alternative |
| `pyghidra-mcp` | Headless Ghidra; project-wide, multi-binary analysis | **Recommended for headless/container use** — matches styx static-analysis mode |

radare2 MCP servers exist but are thin/experimental vs GhidraMCP; r2 stays out of the
recommended table (r2 CLI remains available in-container via `bash`).

## Blue team (forensics / memory)

| Server | Notes | Verdict |
|---|---|---|
| `OMGhozlan/Volatility-MCP-Server` | Volatility 3 wrapper; most complete plugin coverage | **Recommended** |
| `Kirandawadi/volatility3-mcp` | Volatility 3 plugins as MCP tools | Usable alternative |
| `0xhackerfren/Windows-Memory-Forensics-MCP` | 33 tools; Vol3 + MemProcFS + CLR/SOS backends | Windows-focused alternative |

## General

- No dedicated log-tooling MCP server is needed: the blue-team pack covers logs via
  built-in fs-read, `code_exec`, and the new scope-policed `ssh_logs` tool.
- Common caveats: community servers, heterogeneous quality, stdio transport, no
  supply-chain guarantees. Consistent with the skill-pack decision that styx ships
  none and only recommends; the spec's recommended-server table pins nothing.

Feeds the MCP recommended-server table in docs/spec.md (spec-assembly ticket #11).
