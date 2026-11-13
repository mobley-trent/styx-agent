# Delegation authorizes nothing, so engagement mode allows it

`dispatch_subagent` has been a `prompt` in every mode since v1 (spec §6.1's default table). v1.3's
specialist presets (`docs/specialist-subagents.md`, #148) make fanning out an ordinary, frequent
move — several runs in one turn — and a prompt per dispatch turns that into a queue of cards held
behind one review mutex, for an act that grants no capability at all.

We therefore make the verdict mode-dependent: **`prompt` in safe mode, `allow` (audited) in
engagement mode**.

The reason is structural rather than a softening of the boundary. A dispatch carries no scope
targets — the arguments are a role name and a task string — so it is not a scope question. It
inherits the session's policy engine, audit writer, operator, and container; every call the run
makes is judged on its own, with subagent attribution, before it executes. Delegation is a *way to
organize work*, not a way to widen what work is allowed. Engagement mode already auto-allows every
in-scope non-destructive call, and the role gates refuse the presets that presume exploitation when
the rules of engagement forbid it — so there is nothing left for the dispatch prompt to protect
that the per-call verdict does not protect more precisely.

Safe mode keeps its prompt, because there the operator has declared no authorization at all:
spawning a worker that will itself go asking for permissions is a consequential act in its own
right.

## Considered Options

- **Prompt per dispatch, unchanged.** Zero risk, and it keeps a human eye on every spawn. Rejected
  because a four-way fan-out costs four queued approvals, which is exactly the friction that pushes
  an operator to blanket-approve without reading.
- **Allow-session after one approval.** One card, then a blank cheque for the rest of the session —
  including after a mode change or a new engagement file. Rejected: it converts a single conscious
  yes into a standing authorization the operator never re-gave, which is the shape ADR-0012 refused
  for exploitation.
- **Allow in both modes.** Simplest rule, one fewer branch. Rejected: the safe-mode prompt is the
  only moment an operator is asked whether work should be delegated at all when nothing is
  authorized yet.
- **A `dispatch_batch` tool with one verdict for a batch.** One card per fan-out and the cap in one
  place, but it fixes the fan-out shape in the harness, which is a small scheduler in a tool's
  clothes (ADR-0006). Rejected in the design (§5.2, §10).
- **Record-scoped allow — approve dispatches only for findings that appear in the plan.** Rejected
  for the reason ADR-0012 gives: the record is partly model-written, so it must not widen what runs.

## Consequences

- **A non-interactive run can fan out at all.** Prompts are denials when there is no operator
  (ADR-0007), so before this change `-n` could not delegate even inside an engagement. It can now,
  and still cannot in safe mode.
- Each dispatch is still audited with its verdict, so a fan-out is legible after the fact.
- The rule table gains one mode-dependent branch, and §6.1's list of mode-dependent entries grows
  from `state_*`/parsers/`api_spec_load`/`attack_path_suggest`/`exploit_plan_suggest` to include
  delegation — the same argument, one more row.
- Every protection that matters is unchanged: role gates still refuse `exploit-dev` and
  `post-exploit` without `exploit_allowed`, one nesting level still cannot be escaped because the
  tool is stripped from the allowlist, and every call a run makes still passes the gate.
- Anything that wants delegation prompted in engagement mode again, or wants a batch tool with one
  verdict, supersedes this ADR rather than routing around it.
