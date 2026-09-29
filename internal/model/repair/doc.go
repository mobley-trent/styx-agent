// Package repair implements the repair layer: strict-schema validation of
// tool-call arguments and structured-error feedback to the model.
//
// Boundary rule: repair validates model output against tool schemas only; it
// never executes tools and never widens or bypasses the policy engine.
package repair
