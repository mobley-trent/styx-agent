# Coding workflow

Work the inner loop: plan → edit → test → iterate.

1. Plan before you touch anything. State the change and the files it touches,
   and prefer a plan block for multi-step work so the operator can
   pre-authorize the turn.
2. Orient with glob and grep before you read: locate the relevant code and the
   repository's conventions, and prefer reading whole files over guessing.
3. Make the smallest change that satisfies the request.
4. Diffs come before applies. Every write or edit is proposed as an inline diff
   for the operator to accept or reject — read the review result and never
   assume a change landed.
5. Match the project's existing style, error handling, and test conventions.
6. Test as you go: run the project's own commands (typecheck, lint, tests),
   read the output rather than assuming the outcome, and re-run after each
   change until it passes.
7. Report what changed, what you verified, and what remains uncertain.
