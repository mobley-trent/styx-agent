# CONTEXT.md — styx-agent

Glossary for the styx-agent domain. Deliberately free of implementation detail: this is
the shared language, not the spec.

## Core concepts

**Harness**
The Go binary the human runs. Owns the agent loop, the tool registry, the policy
engine, and all safety enforcement. The model is untrusted; the harness mediates
everything.

**Agent loop**
The single hand-rolled cycle of system-prompt assembly → model call → tool dispatch →
tool results → repeat, bounded by a turn cap. There is exactly one loop; subagents run
inside it as tools, never as separate orchestrators.

**Tool**
A named, schema-described capability the model may invoke (file operations, exec,
network fetch, subagent dispatch, or an MCP-provided tool). Every tool call passes
through the policy engine; there are no special cases.

**code_exec**
The multi-language execution tool: runs a snippet in a language runtime present in the
container, selected by a `lang` parameter. Distinct from `bash`, which runs shell
commands in the same container.

**MCP tool**
A capability provided by an external MCP server, arriving as an ordinary tool
descriptor and passing through the same policy gate as built-ins.

## Safety model

**Safe mode**
The default operating mode: permissive reads, guarded writes/exec/network, permission
prompts for anything consequential.

**Engagement mode**
The explicitly authorized operating mode for offensive work, unlocked by an engagement
file. Widenings over safe mode come only from scope matches (below), never from the
mode flag alone.

**Engagement file**
The human-authored declaration of authorized targets and rules of engagement. Checked
on every network/exec action. It authorizes *scope*, not tool rules.

**In scope**
An action whose target parameters match the engagement file (host / CIDR / domain).
In-scope + engagement mode → auto-allow, audit-logged. Out-of-scope → prompt.

**Policy engine**
The harness component that resolves every tool call against the permission rule table
and the engagement scope. The single choke point of the entire safety model.

**Permission rule table**
The three-action table (allow / prompt / deny) keyed on tool name plus glob matchers
over JSON-pointer parameter paths, with spec-defined defaults per mode and an optional
project config overlay.

**Permission prompt**
The live TUI ask when the policy engine returns *prompt*: allow-once, allow-this-session,
or deny-this-session. Session-scoped only; never writes persistent config.

## Agents

**Subagent**
An isolated-context agent run dispatched by the main loop through `dispatch_subagent`,
defined by a role preset: system prompt + tool allowlist + turn bound. One nesting
level; subagents cannot dispatch subagents. Reports return as the dispatch tool result.
Its tool calls pass through the same policy engine; prompts surface live in the TUI
with subagent attribution.

**Role preset**
A built-in subagent definition. v1 presets: `coder`, `recon`, `exploit-dev`,
`log-triage`.

## Model interaction

**Repair layer**
The harness component that validates tool-call arguments against their schemas and
feeds structured errors back to the model, bounded per turn.

**Strict mode**
DeepSeek's schema-enforced tool-calling mode, applied uniformly to all built-in tools.

**Compaction**
Reduction of conversation context. v1: tool-output truncation at capture plus manual
`/compact` — never automatic.
