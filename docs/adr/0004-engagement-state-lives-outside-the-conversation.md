# Engagement state lives outside the conversation; the prompt sees a derived view

The v1.1 engagement-state store is one operator-owned record per engagement, written only
through audited, schema-validated tools (`docs/engagement-state.md`). We decided the model
never holds the record itself: the system prompt stays a byte-stable prefix frozen at
session start (§7.4), and instead the harness tail-appends a compact, re-derivable **state
digest** when state changes. This makes the spec's two promises true by construction —
compaction can evict views of the state but never the state (§4.5), and no model output
can reach the store except through typed, audited ops (§10.2's "never model-invented").

## Considered Options

- **State section in the system prompt.** Most prominent placement, but stale after the
  first write — or it mutates the byte-stable prefix, destroying exact-prefix cache
  economics (§3.3) and violating §7.4 as written. Rejected.
- **State verbatim in the transcript.** Too large, compaction-sensitive, and it turns
  operator-owned records into summarizable conversation content. Rejected.
- **Tool-only visibility.** Zero standing token cost, but findings and graph state stay
  invisible unless the model remembers to query — the exact failure mode this substrate
  exists to prevent. Rejected.

## Consequences

- There is exactly one record; every consumer (prompt digest, §10.2 engagement-end notes,
  future v1.3 reports) derives from it.
- Digest messages are ordinary persisted, evictable transcript content; after compaction
  the harness re-appends one, and subagents never receive digests.
- The store's lockfile/versioning contract becomes part of the operator-facing surface:
  one writer per engagement, stores kept until the operator deletes them.
