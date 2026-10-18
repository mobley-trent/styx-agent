# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`, filtering comments by `jq` and also fetching labels.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Open a PR**: `gh pr create --title "..." --body-file <file>`, with the summary/evidence shape from the `pr` skill.

Infer the repo from `git remote -v`; `gh` does this automatically when run inside a clone.

## Closing: the `Closes #<n>` clause only

**An issue is closed only by the `Closes #<n>` clause in a pull request body, at merge time.** Never run `gh issue close` for work that shipped or is about to ship — not to tidy up, not for a change the tree already holds, not even when the work looks finished. The one exception is a **rejection**, which has no work to ship: see [Rejections](#rejections-not-planned-the-only-hand-close).

- Put the clause in the PR body at creation: `Closes #67`, or `Closes #67, closes #68` for a batch. `gh pr create` with `--body-file` is the usual path; a PR opened without it gets the clause added with `gh pr edit --body-file`.
- The merge is what closes it, so the issue, the PR, and the merge commit record one link, and the close is never earlier than the change that justifies it.
- Before the merge the issue is **open and assigned** — the claim that the work is in flight. Comment the answer or the summary on the issue if useful, but leave the state to the merge.
- A decision that produces no code still needs a home for the clause: land the artifact as a PR. See [Issues with no code to land](#issues-with-no-code-to-land).

### Issues with no code to land

A clause needs a PR, and a PR needs a diff, so an issue whose work is a decision, spec, ADR, research note, or answer lands that artifact **in the repo** — usually `docs/`, `docs/research/`, `docs/adr/`, or `GLOSSARY.md` — and ships it with a PR carrying `Closes #<n>`, exactly like a code change. The decision tickets on map [#53](https://github.com/mobley-trent/styx-agent/issues/53) are the precedent: #73, #77, #79, #81, and #83 each landed a spec, research note, or ADR that way, and none of them touched product code.

If an issue's whole answer is a comment — a question, a "should we X?" — write the answer where it will be read again: a doc, an ADR, or a glossary entry. An issue whose answer is worth nothing durable is usually not an issue at all: answer it in the thread and leave the issue open until a doc that carries the answer lands. Research notes earn their place here too — findings left on a `research/<name>` branch that never merges are findings nobody can find again.

GitHub also honours the closing keyword in a commit message on the default branch. Keep it in the PR body regardless: the body is where a reviewer sees the link *before* the merge.

### Rejections: `not planned`, the only hand-close

**A duplicate, invalid, won't-fix, superseded, or out-of-scope issue is rejected, not resolved**, and it closes by hand:

```sh
gh issue close <n> --reason "not planned" --comment "<why>"
```

That is the only sanctioned `gh issue close`. Always pass `--reason "not planned"` — never `completed`, which would claim the issue was resolved — and always say why in the comment. A rejection is a scope decision, not a step on a route, so it never earns a wayfinder map's Decisions-so-far pointer; a ticket ruled beyond the destination belongs in the map's **Out of scope** section instead.

### The clause fires on the default branch

`Closes #<n>` closes the issue when the PR merges **into the repository's default branch**. A stacked PR merged into another feature branch does not close it: put the clause on the PR that lands in `main`, or repeat it there.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

When set to `yes`, PRs run through the same labels and states as issues, using the `gh pr` equivalents:

- **Read a PR**: `gh pr view <number> --comments` and `gh pr diff <number>` for the diff.
- **List external PRs for triage**: `gh pr list --state open --json number,title,body,labels,author,authorAssociation,comments` then keep only `authorAssociation` of `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`, or `NONE` (drop `OWNER`/`MEMBER`/`COLLABORATOR`).
- **Comment / label / close**: `gh pr comment`, `gh pr edit --add-label`/`--remove-label`, `gh pr close`.

GitHub shares one number space across issues and PRs, so a bare `#42` may be either: resolve with `gh pr view 42` and fall back to `gh issue view 42`.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --comments`.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.

- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body. `gh issue create --label wayfinder:map`.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue (`gh api` on the sub-issues endpoint). Where sub-issues aren't enabled, add the child to a task list in the map body and put `Part of #<map>` at the top of the child body. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: GitHub's **native issue dependencies**, the canonical, UI-visible representation. Add an edge with `gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`, where `<blocker-db-id>` is the blocker's numeric **database id** (`gh api repos/<owner>/<repo>/issues/<n> --jq .id`, _not_ the `#number` or `node_id`). GitHub reports `issue_dependencies_summary.blocked_by` (open blockers only, the live gate). Where dependencies aren't available, fall back to a `Blocked by: #<n>, #<n>` line at the top of the child body. A ticket is unblocked when every blocker is closed.
- **Frontier query**: list the map's open children (`gh issue list --state open`, scoped to the map's sub-issues / task list), drop any with an open blocker (`issue_dependencies_summary.blocked_by > 0`, or an open issue in the `Blocked by` line) or an assignee; first in map order wins.
- **Claim**: `gh issue edit <n> --add-assignee @me`, the session's first write.
- **Resolve**: `gh issue comment <n> --body "<answer>"`, then ship the artifact on a branch and open a PR whose body carries `Closes #<n>` (see [Closing](#closing-the-closes-n-clause-only)); the merge closes the ticket. Append the context pointer (gist + link) to the map's Decisions-so-far **once the merge has closed it** — the map indexes closed tickets only, so a ticket with a PR still open is not yet a decision on the route.
