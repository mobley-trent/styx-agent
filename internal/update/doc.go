// Package update implements the update notifier and `styx update`: the
// release-latest check and the per-source upgrade hint.
//
// Boundary rule: update never rewrites the styx binary — there is no
// self-updater. It makes at most a single releases-endpoint fetch, disabled
// during engagement mode and for source builds.
package update
