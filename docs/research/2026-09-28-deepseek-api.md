# Research: DeepSeek API as the v1 model provider

*Wayfinder ticket: [#3 DeepSeek API as the v1 model provider](https://github.com/mobley-trent/styx-agent/issues/3) · Research date: 2026-09-28. api-docs.deepseek.com was unreachable from this environment; findings verified against secondary sources that cite the official changelog/pricing pages directly (linked below). Re-verify model IDs against the official docs before implementing.*

## Verdict

DeepSeek is viable as the v1 provider for styx-agent, with two design consequences:

1. **Pin explicit model IDs, not aliases.** The API's model naming churns fast (two deprecations in 2026 alone). The harness should treat model IDs as configuration, validated at startup against the `/models` endpoint.
2. **The censorship risk for security work is moderate and mostly topic-based, not capability-based.** Structural mitigations (harness-enforced policy, per ticket Safety architecture) cover the harness's needs; task-level refusals for offensive content are a workflow risk to be handled with prompt framing and, if needed, fallback routing.

## Current models (as of 2026-09-28)

| Model | API ID | Status | Context | Price (peak, per 1M tok) |
|---|---|---|---|---|
| DeepSeek V4.1 Flash | `deepseek-flash` | **Current default** (since 2026-09-10) | 1M | $0.30 in / $1.20 out; cache-hit in $0.006 |
| DeepSeek V4 Pro 0813 | `deepseek-v4-pro` | Current, no end date published | 1M | $1.32 in / $3.96 out; cache-hit in $0.044 |
| `deepseek-chat` / `deepseek-reasoner` | — | **Retired 2026-07-24** (aliases; mapped to V4-Flash modes) | — | — |
| `deepseek-v4-flash` | — | **Retired 2026-09-10** (temporarily routes to `deepseek-flash`) | — | — |

- Peak hours: 01:00–04:00 and 06:00–10:00 UTC Mon–Fri (excluding CN holidays); off-peak bills at **half**. Relevant for long agent runs: schedule heavy batch/offline analysis off-peak.
- Concurrency: account-level limits — 500 slots (V4 Pro), 2,500 (V4.1 Flash). HTTP 429 beyond limits; the harness needs jittered-backoff retry regardless of key count.
- Sources: [benchr migration checklist](https://benchr.org/articles/deepseek-api-aliases-retired) (verified against official changelog), [BenchLM pricing registry](https://benchlm.ai/deepseek/api-pricing) (linked to official pricing pages).

## Tool calling / agentic capability

- **Native tool calling** on V4-family models, OpenAI-compatible `tools` array; results returned via `message.tool_calls`, replied to with `role: "tool"` messages. Parallel tool calls supported (up to 128/turn).
- **Strict mode**: `"strict": true` in the function definition + `/beta` endpoint forces schema-conformant arguments. Useful for styx-agent's safety-critical tools (target-scoped exec params).
- **Thinking mode + tool calling work together** on V4 (this was unreliable on R1-era models). Thinking tokens bill as output tokens; a division of labor (reasoning-heavy planning turns vs. cheap execution turns) is a documented cost lever. Note: `reasoning_content` streaming to a TUI needs handling in the harness.
- **MCP**: DeepSeek documents native MCP support; regardless, styx-agent's harness mediates tools itself (harness-enforced policy), so MCP is consumed at the harness layer.
- Known rough edge: community reports of V4 models occasionally confusing tool calls and text output in agentic loops ([r/LocalLLaMA](https://www.reddit.com/r/LocalLLaMA/comments/1vtu779/i_really_want_deepseek_v4_to_work_as_a_local/)) — the harness's repair layer (validate JSON args, structured error feedback, max-turn bounds) is mandatory, not optional.
- Sources: [official tool calls guide](https://api-docs.deepseek.com/guides/tool_calls/) (via search), [Floatboat hands-on guide](https://floatboat.ai/zh/blog/deepseek-agent-function-calling).

## Censorship / content filtering

- **Topic censorship exists and is input-phase consistent** for politically sensitive topics ([NDSS 2026 paper](https://www.ndss-symposium.org/wp-content/uploads/2026-s1761-paper.pdf); [NIST CAISI evaluation](https://www.nist.gov/system/files/documents/2025/09/30/CAISI_Evaluation_of_DeepSeek_AI_Models.pdf)).
- **For security work specifically**: no strong evidence of systematic refusal of offensive-security/exploit-dev tasks — researchers report the opposite (models readily generate malware/vulnerable code; [CrowdStrike](https://www.crowdstrike.com/en-us/blog/crowdstrike-researchers-identify-hidden-vulnerabilities-ai-coded-software/), [esentire](https://www.esentire.com/blog/deepseek-ai-what-security-leaders-need-to-know-about-its-security-risks)). The practical risks for styx-agent are (a) politically-charged prompt content (e.g. attribution discussions, certain APT names) triggering refusals, and (b) data-privacy: API traffic goes to DeepSeek infrastructure — the harness's docs must state that engagement data leaves the machine, and secrets/credentials must never enter model context.
- Architecture answer (already decided in [#4 Safety architecture](https://github.com/mobley-trent/styx-agent/issues/4)): treat the model as untrusted; all guardrails enforced in Go.

## Design consequences for the harness

1. Model IDs live in config (`deepseek-flash` default, `deepseek-v4-pro` for hard reasoning), validated at startup against `/models`.
2. OpenAI-compatible client (works with `openai-go` pointed at `https://api.deepseek.com`) — no DeepSeek-specific SDK needed.
3. Retry layer: 429 w/ jittered backoff; ignore SSE keep-alive lines in streaming.
4. Repair layer: validate tool-call JSON, structured error feedback to the model, bounded turns.
5. Handle `reasoning_content` in streaming (display suppressed/folded in TUI; logged for audit).
6. Context management: 1M window eases compaction pressure but tool outputs must still be truncated; cache-hit pricing rewards stable system-prompt prefixes (put stable engagement context early in the prompt).
7. Cost tracking in the TUI should read `prompt_cache_hit_tokens`/`prompt_cache_miss_tokens` and peak/off-peak hour awareness.
