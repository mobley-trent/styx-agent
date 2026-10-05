# Provider breadth and per-agent model routing

The v1 spec pinned a single DeepSeek provider with fixed model IDs (spec §3.1) and listed
additional providers as out of scope (spec §13). For v1.x we **adopt provider breadth behind
the existing `ModelClient` seam**: general OpenAI-compatible endpoints, a per-agent model
override, and a small model for title/summary work, with DeepSeek kept as the default. This
reverses the §3.1/§13 posture because provider breadth is table stakes against OpenCode,
Pentestcode, and Strix, and the seam already speaks the OpenAI-compatible wire — breadth is
mostly configuration, not architecture.

## Considered Options

- **Per-agent routing within DeepSeek only.** Smallest change, no new failure surface, but
  leaves the headline gap open.
- **Keep DeepSeek-only.** The v1 spec posture; rejected now that the destination is
  competitor parity.
- **Full multi-vendor SDKs.** Rejected: the OpenAI-compatible endpoints cover the field
  without adopting a second wire protocol.

## Consequences

- The `ModelClient` interface is unchanged, but the repair layer must stay
  provider-agnostic, and **strict mode is a DeepSeek-specific capability** — other providers
  get the repair layer without schema-enforced tool calls. This asymmetry must be visible.
- Spec §3.1 and §13 no longer govern providers; they are superseded for v1.x by this ADR and
  `docs/red-team-roadmap.md`.
