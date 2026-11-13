# A Report renders state and the ROE, never the audit

v1.3's report generation (`docs/reports-and-viewer.md`, #147) produces the human-facing document a
client or auditor reads. It has two inputs and no others: **engagement state** — the observations
the harness recorded — and **the engagement file**, read through the gate's own validation. It does
not read the audit trail, and it does not read the session JSONL.

The tempting third input is the audit trail, and the roadmap sentence invites it: a report that
narrates "what the agent did" needs the trail that recorded the decisions. We refused, for two
reasons that point the same way. `audit.Record.Params` is verbatim and **never redacted** by
contract — parameter objects are where request bodies, tokens, and passwords land, and a document
built from them is a leak with a filename. And the audit's question is not the report's: the trail
answers "did anything run outside the authorization", which is a forensic question asked by an
auditor reading decisions, while the report answers "what is this engagement's posture", asked by
someone who will never read a verdict. The state is already sufficient for everything the report
narrates — routes actually taken are `EXPLOITED_VIA`/`PIVOT_TO`/`ADMIN_OF` edges with provenance,
the timeline is the record's own `first_seen`/`last_seen`, footholds are `access` entities — so
reaching into the audit would buy nothing and import the liability.

The second half is authorization. Engagement state is observations only; `GLOSSARY.md` and
`docs/engagement-state.md` §2 both say authorization is never part of it. A report is *expected* to
state scope and rules of engagement, so the engagement file is a required input, read through the
same `engagement.Load` validation the gate applies: a report quoting an invalid authorization is
worse than no report, so the command fails rather than caveating it.

## Considered Options

- **State plus the audit trail.** The most complete document: turns, interruptions, refusals, prompt
  resolutions, isolation level — and the only way to say "this run was refused three times". Rejected
  because the trail carries unredacted parameters into a document meant to leave the machine, and
  because it makes the report a *run's* artifact. The Report is over an engagement that outlives any
  session; tying it to one session's decisions would produce a document that quietly forgets the
  findings a later session added.
- **State only, with the scope section derived from what was touched.** No second file, no
  authorization reading, and the section would then describe observed targets rather than authorized
  ones. Rejected: it answers a different question than the one a client asks, and a posture document
  whose authority section is inferred from traffic is a guess wearing a heading.
- **State plus audit, with a redaction pass over the trail.** Would recover the run narrative
  safely-ish, and it puts a redactor between the forensic record and a document — one that must be
  right every time, over free-form tool parameters whose secret-bearing shape is
  tool-specific. Rejected as a permanent correctness obligation bought to add facts the state already
  holds.
- **One artifact for machine and human (extend the export with a narrative).** Rejected by
  findings-export §9 and ADR-0008 before this ticket: it destroys byte-identical exports, and would
  need a `generated_at` that a CI diff cannot tolerate.
- **State and the ROE, with runtime facts left unsaid (chosen)**, and the document stating its own
  boundary and pointing at the audit trail's filename convention for everything it cannot claim.

## Consequences

- **A Report is deterministic**, so it inherits ADR-0008's test: two renders of one snapshot are
  byte-identical, and a diff between reports means the posture changed. It carries the store's
  `revision`, never a generated-at stamp.
- **A reader who wants the run's story is pointed at the audit trail**, by name and by convention, in
  the document's own header. Nobody is told a clean report means a clean run.
- **Report generation needs no run, no session, and no lock** — it can be produced interactively, from
  CI, or a month after the engagement closed, which is what makes it a document about an engagement
  rather than a souvenir of a session.
- **Secrets are excluded by construction**, not by a redaction pass: the renderer's input type
  (`engagementstate.Snapshot`) carries credential values, so "never render `Entity.Secret`" is a
  property of one function with a test, not a policy spread across formats.
- **The export and the Report share one reportable predicate** (`findingsexport.Reportable`) and one
  sort order. Two readers of one truth, and no third definition of "a finding this engagement
  reports".
- **Adding the run's narrative to a report later supersedes this ADR** rather than extending it — the
  same bar ADR-0006 sets for making advisory paths actionable, and it would need an answer to the
  unredacted-params problem first.
