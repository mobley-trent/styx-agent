package skillpacks

import _ "embed"

// Pack prompt sections are data, never Go string literals (§8.1, §2): the
// prompt golden snapshots and the deferred eval seam both depend on the
// content being loadable outside the binary.
//
//go:embed promptdata/coding.md
var codingFull string

//go:embed promptdata/redteam-compact.md
var redTeamCompact string

//go:embed promptdata/redteam.md
var redTeamFull string

//go:embed promptdata/re-compact.md
var reCompact string

//go:embed promptdata/re.md
var reFull string

//go:embed promptdata/blueteam-compact.md
var blueTeamCompact string

//go:embed promptdata/blueteam.md
var blueTeamFull string
