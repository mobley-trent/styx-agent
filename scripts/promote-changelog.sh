#!/usr/bin/env bash
# promote-changelog.sh — promote the [Unreleased] section of a Keep a Changelog
# file to a released version. This is a pure text transform: no git, no I/O
# beyond the input file and stdout, so it is easy to test in isolation.
#
#   scripts/promote-changelog.sh v0.1.1 2026-10-05 https://github.com/owner/repo [input]
#
# It refuses to promote an empty [Unreleased] section — a release must record
# what changed — and refreshes the link definitions so [Unreleased] now compares
# from the new tag. The result is written to stdout; the caller decides where it
# goes.

set -euo pipefail

version="${1:-}"
date="${2:-}"
repo="${3:-}"
input="${4:-CHANGELOG.md}"

if [ -z "$version" ] || [ -z "$date" ] || [ -z "$repo" ]; then
	echo "usage: promote-changelog.sh vX.Y.Z DATE REPO_URL [input]" >&2
	exit 2
fi

[ -f "$input" ] || {
	echo "promote-changelog: $input not found" >&2
	exit 1
}

awk -v ver="$version" -v date="$date" -v repo="$repo" -v input="$input" '
  function fail(msg) {
    printf "promote-changelog: %s (%s)\n", msg, input > "/dev/stderr"
    exit 1
  }
  { lines[NR] = $0 }
  END {
    n = NR

    # The [Unreleased] heading.
    u = 0
    for (i = 1; i <= n; i++) if (lines[i] == "## [Unreleased]") { u = i; break }
    if (!u) fail("no \"## [Unreleased]\" heading")

    # The first released section after it.
    r = 0
    for (i = u + 1; i <= n; i++) if (lines[i] ~ /^## \[/) { r = i; break }
    if (!r) fail("no released section follows [Unreleased]")

    # The link-definition block at the bottom.
    l = 0
    for (i = r + 1; i <= n; i++) if (lines[i] ~ /^\[[^]]+\]: /) { l = i; break }
    if (!l) fail("no link definitions found")

    # An empty [Unreleased] means there is nothing to release.
    has = 0
    for (i = u + 1; i < r; i++) if (lines[i] ~ /^[[:space:]]*-[[:space:]]/) { has = 1; break }
    if (!has) fail("the [Unreleased] section has no entries; nothing to release")

    # Content: everything through [Unreleased], a fresh stanza for the new
    # version carrying the old body, then the previous released sections.
    for (i = 1; i <= u; i++) print lines[i]
    print ""
    print "## [" ver "] - " date
    print ""

    a = u + 1
    b = r - 1
    while (a <= b && lines[a] ~ /^[[:space:]]*$/) a++
    while (b >= a && lines[b] ~ /^[[:space:]]*$/) b--
    for (i = a; i <= b; i++) print lines[i]

    print ""
    for (i = r; i < l; i++) print lines[i]

    # Links: compare [Unreleased] from the new tag, and add the new tag.
    inserted = 0
    for (i = l; i <= n; i++) {
      if (lines[i] ~ /^\[Unreleased\]: /) {
        print "[Unreleased]: " repo "/compare/" ver "...HEAD"
        print "[" ver "]: " repo "/releases/tag/" ver
        inserted = 1
        continue
      }
      print lines[i]
    }
    if (!inserted) fail("no [Unreleased]: link definition found")
  }
' "$input"
