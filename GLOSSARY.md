# GLOSSARY.md — styx-agent

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

**Non-interactive run**
A run with no terminal and no operator (`-n`): one task, one turn, every promptable verdict denied,
and output split between an answer stream and an operational transcript. A prompt here is a
refusal, never a permission; authority comes only from what a human wrote down before the run.

**Degraded isolation**
Container execution when the harness cannot enforce container egress at the host's network
edge: the container gets no external network plus a harness-mediated egress path scoped to
the engagement. A visible, audited downgrade — never silent, never the quiet default.

## Reach

**Browser tool**
The harness's own browser capability: load a page, read it, act on it. Harness-owned rather than
MCP-supplied because the harness must enforce scope on destinations the model never passes as
arguments.

**Element handle**
The snapshot-scoped identifier an action uses to name a page element. The model can address only
elements it has read, and a handle from an older snapshot is refused rather than guessed at.

**Interception proxy**
The harness's egress path for reach traffic: it records HTTP exchanges, replays them for the
model, and enforces engagement scope on every request that is not itself a tool call. Recording
and tampering are separate acts; it never pauses traffic waiting for a human.

**Capture**
The recorded exchange stream of one session, kept on disk as evidence. It holds real bytes;
sensitive values are redacted where the capture becomes model context, never on disk.

## API declarations

**API declaration**
An OpenAPI, Swagger, or Postman document saying what an API offers and where it is served. A fact
source, never an authorization source: it names a surface, and the engagement decides whether any of
it is reachable.

**Declared host**
A host an API declaration serves from, recorded in engagement state tagged `declared` because nothing
observed it. It is recorded at all only because its address was inside the engagement's pool at load.

**Declared surface**
The endpoint inventory a load produces — each operation's method, path, effective server, and auth
*requirement* — written as a derived artifact beside the receipt. A rendering of a document, not
evidence of anything.

**Refused server**
A server a declaration names that the engagement does not authorize, or one that cannot be resolved or
has no HTTP scheme. Named with its reason and never silently skipped; the operations under it are
reported unavailable.

## Sandbox image

**Sandbox image**
The pinned container image a session runs `bash` and `code_exec` in. Content-addressed by digest,
never by tag; the official image is signed and verified before use, and an operator may pin another,
which runs only as an explicitly authorized unverified image.

**Verified image**
A sandbox image whose digest signature, signing identity, and transparency-log inclusion were checked
against the harness's compiled-in policy before the container was created. A pre-pulled image whose
bundle was never verified is not one.

**Toolset manifest**
The image's own declaration — at `/etc/styx/toolset.json` — of the tools, versions, parser mappings,
wordlists, and tool-data versions it carries, read once at session start so prompts and allowlists stay
truthful. Absent means unknown, never probed.

**Tool data**
The scanner payloads bundled into the sandbox image at build: nuclei templates, sqlmap tamper scripts,
semgrep rules, the trivy databases, and wordlists. Refreshed by an image release, never fetched at
runtime.

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
Held, never prospective — a foothold an exploit produced is still one you have.

**Segment**
A labeled network range grouping hosts in engagement state.

**Relationship graph**
The typed entity graph over engagement state — how hosts, services, credentials, and access
relate.

**Phase**
A stage named by the red team skill pack's workflow text (recon, enumeration, exploitation,
post-exploit). Prompt vocabulary, not a harness object: the harness holds no phase state and
never advances one.

**Attack path**
A suggested route through the relationship graph from current access to a target, surfaced
for the model to act on. A suggestion, never an auto-executed step.

**Capability step**
A derived, actionable projection of a relationship-graph edge into a directed, costed action —
pivot, harvest a credential, use one, or become admin. Derived on read; never a stored record.
Exploitation is not one: an exploit that ran is provenance on the foothold it produced, and one
still unrun is a terminal exploit step.

**Exploit step**
The priced, terminal step of a route whose target is a finding: the exploit you would have to run,
costed by the finding's confidence and verification. It ends the route and claims no foothold —
the record says nothing about what an unrun exploit yields, so the model records the real access
afterwards and the step disappears.

**Positioning route**
The capability route that puts the engagement in position to run an exploit, reported beside the
exploit step as its price. Its arrival level is real; the exploit's yield is not.

**Exploit opportunity**
An exploitable finding on a host or service current access can already reach, offered as a hint
beside an unreachable attack path. A hint rather than a priced step: naming the finding as a
target is what prices it.

**Exploitation candidate**
An unexploited finding priced for exploitation: its cheapest positioning route plus the terminal
exploit step, offered ranked beside the other candidates. A suggestion, never an authorization.

**Exploitation plan**
The ranked, capped list of exploitation candidates the harness offers. Not a **Plan block**:
nothing in it is pre-authorized, and it describes no sequence of steps.

**Path cost**
The cost of an attack path: the sum of its capability steps' costs, each a base cost modified by
the confidence and OPSEC-noise enums. A ranking, never a probability.

**State digest**
The compact, derived view of engagement state appended to the conversation when state changes — a view of the record, never the record itself.

**Provenance**
The harness-stamped origin of a state mutation: tool or model, subagent attribution, session, and timestamp. Never model-supplied.

**Exploitation autonomy level**
The operator's engagement-file choice of whether an exploit-class call in scope is approved
without a prompt (`auto`) or asks first (`prompt`, the default). It widens a verdict, never the
rules of engagement: scope, destructive tagging, the time window, and `exploit_allowed` all bind
before it, and full autonomy is out of scope.

## Parsers & artifacts

**Parser tool**
A harness-owned tool that turns one scanner's raw output into typed engagement-state writes,
one per scanner (nmap, nuclei, sqlmap, gobuster, cme, bloodhound). The only path from scanner
output into state.

**Artifact**
A preserved raw tool output file that a parser reads and a finding cites as evidence. Raw input to
styx, never a rendering out of it.

**Artifact directory**
`.styx/out/` at the project root: where scanners are asked to write raw output. Activation
creates it and gitignores it, because evidence does not belong in the repository.

**Parse receipt**
The compact summary a parser returns after a parse — what it wrote and what it skipped — so
the model sees the result without re-reading the raw output.

**Pending-parse obligation**
The harness-tracked record that a scanner artifact has not yet been parsed, surfaced in the
state digest. Advisory, never a block.

## Reporting

**Findings export**
The machine-readable rendering of a run's reportable findings — JSON, CSV, and SARIF — written at
the end of a non-interactive run. A view of engagement state at one moment: deterministic, and
never a second record.

**Reportable finding**
A finding an export carries: active, not `false_positive` or `fixed`, and not `refuted`. The
severity gate reads these except the `risk_accepted` ones.

**Severity gate**
The CI threshold (`--fail-on <severity>`) that fails a non-interactive run when the engagement holds
a gated finding at or above that severity. Reads the export's own set, never re-ranks or rewrites a
finding, and exists only because the run asked for it.

**Gated finding**
A reportable finding the severity gate may fail a run on: reportable, but not `risk_accepted` — risk
someone consciously took never fails a pipeline.

**Report**
The human-facing narrative generated from engagement state: remediation prose and a viewer. Prose
for a reader, as distinct from a findings export's records for a machine.

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

**Budget cap**
The per-run dollar ceiling a non-interactive run may spend on model turns, measured from the session's own usage accounting and priced by the configured per-model rates. One ceiling for the run, root and child agents alike; never an estimate made before a call, and never a per-engagement total.

**Budget note**
The harness-authored message appended to the conversation when a run passes a budget threshold: how much of the ceiling is spent, and that the model should wrap up. A view of the run's spend, announced once per level — ordinary transcript content, never part of the system prompt.

**Unpriced turn**
A completed model turn whose provider reported no usage, so the run's spend cannot be measured. A budgeted run ends rather than continue with a ceiling it cannot enforce.

## Terminal interface

**Plan block**
The TUI presentation of a proposed multi-step plan before execution. Approving it
pre-authorizes exactly the listed actions for that turn; it never overrides hard
denies, ROE violations, or out-of-scope checks.

**Live region**
The bottom strip of the terminal UI that is re-rendered every frame: the input editor,
the status bar, any live prompt card, the inline command menu, and the in-flight
streaming partial. Everything above it is committed transcript printed once into the
terminal's own scrollback and never rewritten.

**Command registry**
The harness's one declaration of the command surface: each command's usage line,
description, handler, and the picker options it offers. Dispatch, `/help`, the inline
slash-command menu, and the modal pickers all read it, so adding a command documents
and lists it in the same act. A **command picker** is the modal list a command with
options opens when it is run with no argument.

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
