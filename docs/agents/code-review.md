# Code Review Checklist

The two-axis review this repo's `AGENTS.md` review gate requires, written down so an agent can
run it without the `code-review` skill installed. The skill is the same procedure; where both are
available, either path yields the same review.

## The two axes

- **Standards** — does the diff conform to this repo's documented conventions?
- **Spec** — does the diff faithfully implement the ticket or spec it came from?

Keep them separate. A change can pass one axis and fail the other: standards-clean code that
implements the wrong thing, or exactly the requested behaviour written against every convention.
Reporting them apart stops one axis masking the other; never merge or rerank findings across axes.

## 1. Pin the fixed point

Take the point under review: a commit, branch, tag, `main`, or `HEAD~5`. If the user named none,
ask for it.

```sh
git rev-parse <fixed-point>            # a bad ref fails here, not mid-review
git diff <fixed-point>...HEAD          # three dots: against the merge-base
git log <fixed-point>..HEAD --oneline
```

An empty diff stops here: there is nothing to review.

## 2. Find the spec

In this order:

1. Issue references in the commit messages (`#123`, `Closes #45`), fetched with the workflow in
   `docs/agents/issue-tracker.md`.
2. A path the user passed as an argument.
3. A spec or plan file under `docs/`, `specs/`, or `.scratch/` matching the branch or feature name.
4. Otherwise ask. If there is no spec, skip the Spec axis and say so in the report.

## 3. Find the standards

Anything in the repo that documents how code should be written: `AGENTS.md`, `docs/`
(`docs/spec.md`, the tool contracts, the ADRs), `CODING_STANDARDS.md`, `CONTRIBUTING.md`, and the
language's own conventions where the repo states them.

On top of whatever the repo documents, always carry the **smell baseline** below. Two rules bind
it:

- **The repo overrides.** A documented repo standard always wins; where it endorses something the
  baseline would flag, suppress the smell.
- **Always a judgement call.** Each smell is a labelled heuristic ("possible Feature Envy"), never
  a hard violation. Skip anything tooling already enforces (`gofmt`, `go vet`, `golangci-lint`).

Each smell reads *what it is* → *how to fix*:

- **Mysterious Name**: a function, variable, or type whose name doesn't reveal what it does or
  holds. → rename it; if no honest name comes, the design is murky.
- **Duplicated Code**: the same logic shape appears in more than one hunk or file. → extract the
  shared shape, call it from both.
- **Feature Envy**: a method that reaches into another object's data more than its own. → move the
  method onto the data it envies.
- **Data Clumps**: the same few fields or params keep travelling together (a type wanting to be
  born). → bundle them into one type, pass that.
- **Primitive Obsession**: a primitive or string standing in for a domain concept that deserves its
  own type. → give the concept its own small type.
- **Repeated Switches**: the same `switch`/`if`-cascade on the same type recurs across the change.
  → replace with polymorphism, or one map both sites share.
- **Shotgun Surgery**: one logical change forces scattered edits across many files. → gather what
  changes together into one module.
- **Divergent Change**: one file or module is edited for several unrelated reasons. → split so each
  module changes for one reason.
- **Speculative Generality**: abstraction, parameters, or hooks added for needs the spec doesn't
  have. → delete it; inline back until a real need shows.
- **Message Chains**: long `a.b().c().d()` navigation the caller shouldn't depend on. → hide the
  walk behind one method on the first object.
- **Middle Man**: a class or function that mostly just delegates onward. → cut it, call the real
  target directly.
- **Refused Bequest**: a subclass or implementer that ignores or overrides most of what it
  inherits. → drop the inheritance, use composition.

## 4. Run both passes

One pass per axis. Where the harness supports parallel sub-agents, run the two in parallel so they
never pollute each other's context; otherwise run them in sequence and keep separate notes — the
second pass must not revise the first's conclusions.

**Standards brief** — report, per file or hunk where relevant: (a) every place the diff violates a
documented standard, citing the file and the rule; (b) any baseline smell spotted, named, with the
hunk quoted. Distinguish hard violations (documented-standard breaches) from judgement calls
(baseline smells); a documented repo standard overrides the baseline. Skip what tooling enforces.
Under 400 words.

**Spec brief** — report: (a) requirements the spec asked for that are missing or partial;
(b) behaviour in the diff that was not asked for (scope creep); (c) requirements that look
implemented but where the implementation looks wrong. Quote the spec line for each finding. Under
400 words.

## 5. Report

Present the two passes under `## Standards` and `## Spec`, verbatim or lightly cleaned. End with
one line per axis: the total findings and the worst issue *within that axis*. Do not pick a single
winner across axes — that is the reranking the separation exists to prevent.

The gate then asks for the findings to be fixed, or recorded as out of scope, before the branch is
committed, and for the final message to say what the review checked and changed.
