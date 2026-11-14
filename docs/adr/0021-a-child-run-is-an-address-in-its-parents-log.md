# A child run is an address in its parent's log

v1.3 item 14 exposes subagent runs as inspectable sessions
([`docs/child-runs.md`](../child-runs.md), #151). The obvious shape, given the name the roadmap gave
it, is a child session: its own id, its own JSONL under the project's session directory, a pointer to
its parent. Everything needed to build that exists — the run is already bracketed in the parent's log,
so a writer could fork the slice into a file of its own at close.

It should not. **A run has no id, no file, and no store: it is an address — *(session, run id)* —
over events the parent session already persists.** The parent's JSONL is the record; a run is a slice
of it, and every view is a filter, not a stored artifact.

The parent's log already holds the whole run: a `KindSubagent` start carrying the role, run id and
brief, every event the nested loop emitted carrying that attribution, and a report, error or
cancellation closing it. What item 14 asked for was inspectability, and inspectability was missing an
address and a printout, not a place to keep the bytes. A second file would be a second writer
appending to a log the parent is still writing, with its own open, ordering and close semantics to get
wrong — against content that cannot be lost, because it is already in the one file that survives the
session.

Three facts make the slice decision cheaper than it looks, and one condition it imposes:

- **`/resume` never needed a child file.** `agent.Conversation` skips every event carrying a subagent
  attribution, so a worker's transcript is never replayed as the main agent's. Resume coherence is a
  property of attribution, not of layout.
- **A child file needs a parent pointer to be findable**, and a pointer whose only consumer is a tree
  is the first half of depth two — which the subagent design keeps closed
  ([`docs/specialist-subagents.md`](../specialist-subagents.md) §7). Building a data relationship for
  a capability that is out of scope is how out-of-scope capabilities arrive by accident.
- **The cost is a bigger parent log**, which is exactly what "one session, one record" means and is
  bounded by the 40-turn run bound and the four-run concurrency cap.
- **The condition: a run id must be unique within the session, not within the process.** That is a
  real change. `subagent.Runner.seq` restarts at zero in every process, so a session resumed once can
  already hold two `coder-1` runs. Harmless while the id was a fold key; fatal once it is an address.
  The dispatcher's sequence is therefore seeded from the log at resume — a fold over the replay
  `/resume` already performs.

## Considered Options

- **A session per run** (id, file, parent pointer). Gives a run a life of its own: it could be resumed,
  listed, or shipped. All three are wanted by nobody — a run is not resumable (its context is gone,
  and re-running it is a new dispatch), and listing is what the index does — while the second writer
  and the parent pointer are immediate costs, and the pointer is a depth-two shape bought early.
- **Fork the slice into a file at close.** Keeps one writer per file and gives the operator something
  to hand to someone else. Rejected: it duplicates bytes that are already durable, so the two copies
  can diverge under any future schema change, and "which copy is the record" becomes a question the
  audit cannot answer.
- **Keep process-scoped run ids and address a run as *(run id, turn)*.** No seeding, no change to the
  dispatcher. Rejected: every address everywhere becomes compound to work around a collision that only
  exists because the id was never asked to be an address before.
- **Opaque ids** (random suffix, per-process epoch). Collision-proof without reading the log, at the
  cost of the legibility the live block header depends on — and of two ids for one notion of "the
  second recon run".
- **An address over the persisted slice (chosen).**

## Consequences

- **The viewer gains two flags, and the session store gains no concept.** `styx view <session> --runs`
  prints an index; `--run <id>` prints one run through the same renderer. A session id still names one
  transcript, which is the contract the viewer design set
  ([`docs/reports-and-viewer.md`](../reports-and-viewer.md) §6.5).
- **Refusals become first-class in a run view.** They were always on the `tool_call` events; because
  a run view is a fold over one slice, the tally and the recap are derivable without a new record —
  the thing an operator opens a child to check.
- **The parent's plain view groups each run at its close**, since a run is only printed once it is
  whole. Concurrent runs interleave in the file and never in the view.
- **"Child session" is a misnomer, and the glossary says so.** The roadmap item keeps its name where
  it is cited; the thing it delivers is a child run.
- **Depth two would need the parent link this ADR refuses to add now.** That is deliberate: the field
  belongs to the decision that opens nesting, where its consumers can be designed with it.
- **A run can never outlive its session, and that is a feature.** A child run is inspectable for
  exactly as long as its parent is, which is the retention rule the operator already reasons about.
