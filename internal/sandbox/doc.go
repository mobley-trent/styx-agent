// Package sandbox is the pinned, signed session image: its identity, the
// signature verification that has to pass before its bytes are pulled, the
// trust cache that makes verification work offline, and the toolset manifest
// the image declares about itself (docs/sandbox-image.md §5–§9, ADR-0011).
//
// Boundary rule: this package is harness-side and is the single place in styx
// that learns sigstore. It never runs a container, never speaks to the model,
// and never decides whether a session may start — it answers one question
// ("did the workflow we trust sign this exact digest?") and returns an error.
// The container layer sees verification as an injected seam
// (containerlayer.ImageVerifier) and knows nothing about certificates.
package sandbox
