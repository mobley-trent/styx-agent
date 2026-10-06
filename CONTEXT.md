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

**Engagement gate**
The single strict checkpoint every engagement activation passes through, whether
raised at launch or in-session. Same validation, same refuse-to-start behavior, no
weaker second door.

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

**Degraded isolation**
Container execution when the harness cannot enforce container egress at the host's network
edge: the container gets no external network plus a harness-mediated egress path scoped to
the engagement. A visible, audited downgrade — never silent, never the quiet default.

## Engagement state & findings

**Engagement state**
The per-engagement structured record — hosts, services, findings, credentials, access, and
network segments — that survives sessions and feeds the prompt as a derived view.
Observations only: authorization is never part of it. Never compacted away, never
model-invented.

**Finding**
A structured result in engagement state: a vulnerability or observation with severity,
status, confidence, and its evidence.

**Evidence**
The verification record attached to a finding. A finding without evidence is unvalidated.

**Credential**
A captured secret — password, hash, key, or token — with its principal and where it came from.

**Access**
A foothold: an established principal operating on a target at a stated level (user, admin, system).

**Segment**
A labeled network range grouping hosts in engagement state.

**Relationship graph**
The typed entity graph over engagement state — how hosts, services, credentials, and access
relate.

**Attack path**
A suggested route through the relationship graph from current access to a target, surfaced
for the model to act on. A suggestion, never an auto-executed step.

**State digest**
The compact, derived view of engagement state appended to the conversation when state changes — a view of the record, never the record itself.

**Provenance**
The harness-stamped origin of a state mutation: tool or model, subagent attribution, session, and timestamp. Never model-supplied.

**Exploitation autonomy level**
The operator-set engagement flag that widens in-scope exploit approval within the rules of
engagement. It never lifts ROE hard limits, and full autonomy is out of scope.

## Parsers & artifacts

**Parser tool**
A harness-owned tool that turns one scanner's raw output into typed engagement-state writes,
one per scanner (nmap, nuclei, sqlmap, gobuster, cme, bloodhound). The only path from scanner
output into state.

**Artifact**
A preserved raw tool output file that a parser reads and a finding cites as evidence.

**Parse receipt**
The compact summary a parser returns after a parse — what it wrote and what it skipped — so
the model sees the result without re-reading the raw output.

**Pending-parse obligation**
The harness-tracked record that a scanner artifact has not yet been parsed, surfaced in the
state digest. Advisory, never a block.

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

## Skills & memory

**Skill pack**
One of the four built-in domain bundles (coding, red team, reverse engineering, blue
team): workflow prompts, allowlist deltas, and preset references layered onto the
system prompt. Not a Skill.

**Skill**
A SKILL.md-defined agent capability the user or the model can invoke, loaded from
global and project skill directories. Project skills shadow global ones by name.
Distinct from a Skill pack.

**Skill tool**
The tool through which the model invokes a Skill. Returns the skill's workflow content as
its result for the model to execute with its ordinary tools. It grants no tools and widens
no policy; a skill is workflow text, never a plugin.

**STYX.md**
The per-project memory file, auto-loaded into the system prompt. User- and
agent-editable. Engagement notes live here.

**Engagement notes**
The timestamped, structured record the harness appends to STYX.md when an engagement
ends. Never silent, never model-invented after the fact.

## Model interaction

**Repair layer**
The harness component that validates tool-call arguments against their schemas and
feeds structured errors back to the model, bounded per turn.

**Strict mode**
DeepSeek's schema-enforced tool-calling mode, applied uniformly to all built-in tools.

**Compaction**
Reduction of conversation context: tool-output truncation at capture, plus threshold-triggered compaction — old tool results are evicted first, and the oldest conversation segment is summarized into a state summary only if eviction isn't enough. Never touches the system prompt, engagement context, ROE state, or audit records. Manual `/compact` remains available as an override.

## Terminal interface

**Plan block**
The TUI presentation of a proposed multi-step plan before execution. Approving it
pre-authorizes exactly the listed actions for that turn; it never overrides hard
denies, ROE violations, or out-of-scope checks.

**Live region**
The bottom strip of the terminal UI that is re-rendered every frame: the input editor,
the status bar, any live prompt card, and the in-flight streaming partial. Everything
above it is committed transcript printed once into the terminal's own scrollback and
never rewritten.

## Testing

**Fake model**
The in-process, per-test-scriptable stand-in for the model. It implements the
harness's single model boundary and is the only path tests take into the agent
loop; no test talks to a live model.

**Stub server**
A local OpenAI-compatible model server for client-path testing: real streaming,
tool calls, strict-mode argument enforcement, and injected faults. Recorded
sessions replay through it as a mode; there is no separate replay mechanism.

**Transcript fixture**
A scrubbed, versioned recording of a styx session, derived from a persisted
session and kept in the shared test-data directory. Secrets and real engagement
targets never enter the repo.
