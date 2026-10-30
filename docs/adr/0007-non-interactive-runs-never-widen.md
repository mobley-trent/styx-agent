# A non-interactive run never widens its own authority

styx's safety story is a human at the prompt (`docs/spec.md` §1, §6.4). A CI run has no human, so
every design that touches `-n/--non-interactive` is really asking what happens to the promptable
middle of the rule table. We decided that **a prompt is a refusal when nobody is there to be
asked**: `-n` resolves `prompt` to `deny` with the reason `no-operator`, and it changes nothing
else. Authority in a headless run can only come from something a human wrote down before the run —
a committed `permissions.rules` overlay or an engagement file's scope (spec §6.1, §6.2) — never
from a flag that grants on the human's behalf. The same line decides the two non-policy cards:
a diff is applied only when its call was already `allow`ed, and a plan is never pre-authorized.

## Considered Options

- **`-n` implies a preset widening (prompt → allow) because CI has no one to ask.** The obvious
  convenience, and the reason this ADR exists. It turns the absence of an operator into a grant:
  every out-of-scope target and every consequential exec that a human would have seen becomes
  silent. The engagement file's whole function — authorizing *scope*, not tool rules — would be
  bypassed by a transport flag. Rejected.
- **A `--yes` / `--allow-prompted` flag that the operator opts into explicitly.** Explicit, and
  still wrong: it makes the harness's safety a checkbox, moves a reviewed decision out of a file
  and into a CI script, and leaves the audit trail unable to distinguish "a human authorized this
  class of action in the overlay" from "someone passed a flag". Rejected in favour of the overlay
  that already exists for exactly this purpose.
- **Fail the run on the first prompt.** Safer-looking than denying, and worse twice over. In safe
  mode a prompt is the *ordinary* case — every guarded write and exec — so a bare `-n` run would be
  unusable outside engagement mode. And in engagement mode a prompt means "the model proposed
  something out of scope", which would let the model end a scheduled run by trying one bad thing;
  the run's outcome must not be the model's to trigger. Rejected.
- **Deny, keep running, and report the denial (chosen).** The action does not happen, the model
  sees a denial exactly as it sees a human's, the audit records `deny` with `no-operator`, and the
  run's summary reports a count so a partly-blocked run is never mistaken for a clean one.

## Consequences

- A bare `-n` run in safe mode is read-only: it reads, reasons, and reports, and cannot modify the
  workspace. That is the default, and changing it takes a committed, reviewed overlay rule — a
  human act, in a file, under version control.
- The denial path is structurally the same path an interactive deny takes, because the prompt sink
  is simply absent. There is no headless-only branch in the policy engine, and the decision
  function's signature does not change.
- The audit trail gains one reason value (`no-operator`) and no new verdict, so existing auditors
  keep reading the same closed vocabulary.
- `--fail-on` and the diff-scope flag inherit this posture: they can narrow what a run reports on
  and what it tests, and they can never add a target or widen a rule (spec §6.2). A CI-shaped flag
  passed without `-n` is a usage error rather than an ignored one, so the two never drift.
- Anything that wants headless autonomy beyond "act on what was pre-authorized" has to supersede
  this ADR, not route around it with a flag — the same bar ADR-0003 sets for exploitation autonomy.
