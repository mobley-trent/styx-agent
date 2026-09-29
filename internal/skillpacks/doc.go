// Package skillpacks implements the four built-in skill packs (coding, red
// team, reverse engineering, blue team): workflow prompt sections, tool
// allowlist deltas, and preset references.
//
// Boundary rule: pack content is data, never Go string literals — prompt
// sections load from embedded data files so golden snapshots and the
// post-v1 eval seam stay byte-stable.
package skillpacks
