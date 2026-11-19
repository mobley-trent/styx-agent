# AGENTS.md

Guidance for AI coding agents working in this repository.

## Learning workspace

Harness-engineering teaching artifacts live in `learning/` — a self-contained workspace
(`MISSION.md`, `RESOURCES.md`, `NOTES.md`, `lessons/`, `reference/`, `assets/`,
`learning-records/`). It is gitignored and is not product code. When running a teaching
session, treat `learning/` as the workspace root and read `learning/MISSION.md` first.

## Review gate

Every implementation ends with a review of the diff, not just a green test run:

- Review the diff along two axes yourself — **Standards** (does this repo's documented
  conventions hold?) and **Spec** (does the change match the ticket or spec it implements?) —
  using this repo's checklist at `docs/agents/code-review.md`. That file is the `code-review`
  skill's procedure written down: load the skill if your harness has it, or follow the checklist
  directly if it doesn't. What matters is that the review happens, not which invocation path
  carried it; a harness without a skill-invocation tool is not an exemption.
- Fix what the review finds, or record why it is out of scope, before committing to the feature
  branch. A fix after the review reads clean still owes a rerun over the files it touched.
- The final message says what the review checked and what it changed. "Not run" is an acceptable
  answer; an unmentioned review is not.

## Agent skills

### Issue tracker

Issues and specs live in this repo's GitHub Issues (via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage roles, each label string equal to its name. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
