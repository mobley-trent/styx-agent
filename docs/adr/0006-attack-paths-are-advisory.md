# Attack paths are advisory: computed on read, never scheduled

Competitors close the "what do I do next" gap by making the planner an actor — Pentestcode
advances phases and launches the plan it computed. That inverts styx's reason to exist: the
harness, not the model and not a planner, is the safety boundary (ADR-0003). We therefore
**compute attack paths as a pure projection of engagement state and surface them as text
suggestions only**: the tool returns ordered, costed routes for the model to reason about, and
every step a model acts on goes through the ordinary policy gate and scope checks on its own.
The harness never schedules, pre-authorizes, or executes a suggested step, and the computation
is read-only — a *view* of the record (ADR-0004), never a second source of truth.

## Considered Options

- **A materialized path index, written as state changes.** Faster reads, but it creates a second
  record that can drift from the first — exactly the failure ADR-0004 exists to prevent — and
  v1 engagement sizes do not justify it. Rejected.
- **A planner that executes (or pre-authorizes) the cheapest route's steps.** The competitor
  shape. Rejected: it moves the safety boundary from the harness to the planner, and a
  pre-authorization driven by state (which the model partly writes) would let the model widen
  what runs.
- **Model-computed paths from `state_query` neighborhoods.** No harness cost model, no
  determinism, unbounded token cost, and the ranking becomes model-authored. Rejected.

## Consequences

- Path ranking is a pure function of stored enums, so it is golden-testable, reproducible, and
  ties break deterministically.
- Because paths are suggestions, the cost model can stay conservative without ever blocking a
  route the model knows better than the numbers do — a second-ranked route is still visible (K=3).
- Every suggested step is still subject to the policy engine when acted on: this tool widens no
  scope, no ROE limit, and no approval.
- Richer *inputs* to the ranking (per-instance detectability, outcome-shaped goals) require schema
  work on the engagement-state model; richer *agency* (phase auto-advance) requires superseding
  both this ADR and ADR-0003.
