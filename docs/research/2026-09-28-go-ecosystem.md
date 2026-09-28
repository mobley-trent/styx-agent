# Research: Go agent-harness ecosystem (TUI, agent loops, LLM clients, MCP, container exec)

*Wayfinder ticket: [#5 Go agent-harness ecosystem](https://github.com/mobley-trent/styx-agent/issues/5) · Research date: 2026-09-28. Release info verified against current release pages as of this date.*

## Verdict — recommended stack

| Concern | Recommendation | Why |
|---|---|---|
| Agent framework | **No framework — hand-rolled loop** on the OpenAI-compatible API | Styx's loop is small and the safety policy must sit *inside* it; frameworks (ADK-Go, LangChainGo, Eino) add abstraction tax and model-provider coupling we don't want. Zero framework = zero dependency churn. |
| LLM client | **openai-go** (`github.com/openai/openai-go`) pointed at `https://api.deepseek.com` | OpenAI-compatible; no DeepSeek-specific Go SDK required. Streaming + tool calls supported. |
| TUI | **Charm v2 suite: Bubble Tea v2 + Lip Gloss v2 + Bubbles** (out of beta Feb 2026; v2.0.10 as of Sep 2026) | The de-facto standard for rich Go TUIs; v2 is production-ready. |
| MCP | **Official `modelcontextprotocol/go-sdk`** (v1.x, Tier 1, maintained with Google) | Over `mark3labs/mcp-go` (the popular pre-official lib) for long-term maintenance. Both client *and* server support — styx can also expose itself as an MCP server later. |
| Container exec | **Official Docker SDK for Go** (`github.com/docker/docker/client`) | Stable, ubiquitous. Podman presents a Docker-compatible socket, so one integration covers both. |
| Distribution | **goreleaser** (GitHub Releases + Homebrew tap + `go install`) | Standard Go path; single static binaries are Go's superpower here. |

## Notes per component

### Agent frameworks — surveyed and rejected (for the core loop)

- **Google ADK-Go** — 1.0 as of mid-2026, code-first, A2A protocol support. Rejected: Google-model-centric assumptions, abstraction over the message loop is exactly where our policy engine must live.
- **LangChainGo** — port of Python LangChain; trails the original in coverage/pace. Rejected.
- **CloudWeGo Eino** — capable orchestration framework (ByteDance). Rejected for core loop; worth borrowing patterns (graph orchestration) if subagent dispatch gets complex.
- Verdict source: [Zep: Building Agents in Go Without a Framework](https://blog.getzep.com/agentic-development-in-go/), [Applied Go: AI and Go in 2026](https://appliedgo.net/spotlight/ai-and-go/).

### TUI — Bubble Tea v2

- Charm v2 (Bubble Tea/Lip Gloss/Bubbles) left beta **Feb 2026**; actively released (v2.0.10, Sep 2026). Elm-architecture model maps cleanly to agent loop events (streaming tokens as Msgs).
- Companion libs we'll want: `bubbles/textarea` + `viewport` for the chat pane, `lipgloss` for diff coloring, `x/exp/teaview`-style components for split panes (plan/accept flow, diff viewer).
- Source: [Charm v2 announcement](https://charm.land/blog/v2/).

### MCP — official Go SDK

- `github.com/modelcontextprotocol/go-sdk`, Tier-1 official SDK (in collaboration with Google), supporting protocol rev `2026-07-28`; v1.7+ current. Client + server in one package.
- Since styx's policy engine mediates *every* tool call, MCP tools arrive as ordinary tool descriptors and pass through the same permission gate as built-ins — no special-casing.
- Source: [modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk).

### Container exec

- Docker SDK for Go: create container → start → exec → stream output. Alternatives (exec-ing `docker` CLI directly) lose structured exit codes/streaming. Podman compatibility via its Docker-compatible API socket is adequate for our needs; document both.
- For macOS: Docker Desktop/OrbStack/colima all expose the same socket; spec should require "a Docker-compatible socket" rather than Docker-the-product.

## Gaps we build ourselves (not available off the shelf)

1. **Policy engine / engagement-file enforcement** — nothing in the Go ecosystem does target-scoped network/exec authorization. Core original value of styx.
2. **Permission prompt UX** — permission gates live in the TUI layer; hand-rolled.
3. **Session persistence format** — hand-rolled (JSONL transcript + project memory file).
4. **Skill-pack system** — prompt/workflow layer on top; hand-rolled.
5. **Repair layer for DeepSeek tool-call quirks** — validate JSON args, structured error feedback, turn bounds (see DeepSeek research file).
