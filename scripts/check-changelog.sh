#!/usr/bin/env bash
# check-changelog.sh — require an [Unreleased] entry when product code changes.
#
#   scripts/check-changelog.sh [BASE] [HEAD]
#
# BASE defaults to origin/main and HEAD to HEAD. When the diff between them
# touches a product path, CHANGELOG.md must gain at least one new entry line
# inside its [Unreleased] section: RELEASING.md makes the changelog the source
# of truth, so the entry ships in the same change that needs it.
#
# Product paths — what can reach a user:
#   cmd/**        the CLI
#   internal/**   the harness
#   install.sh    the blessed Linux install path
# minus *_test.go and internal/testdata/**, which are tests and fixtures.
# Everything else (docs, README, CI, scripts, Makefile, go.mod, LICENSE,
# CHANGELOG.md itself) is exempt, so a docs-only or tooling-only change needs
# no entry. A product change with no user-visible effect carries the
# `no-changelog` label, which skips this check in CI.
#
# It compares commits: uncommitted work in the tree is not part of the range.
#
# Exit: 0 nothing to record, or a new entry was found; 1 a missing entry or a
# bad revision; 2 a usage error.

set -euo pipefail

die() { printf 'check-changelog: %s\n' "$*" >&2; exit 1; }
die_usage() {
	printf 'check-changelog: %s\n' "$*" >&2
	printf 'check-changelog: usage: scripts/check-changelog.sh [BASE] [HEAD]\n' >&2
	exit 2
}

case "${1:-}" in
-h | --help)
	sed -n '2,24p' "$0"
	exit 0
	;;
-*) die_usage "unknown flag: $1" ;;
esac

base="${1:-origin/main}"
head="${2:-HEAD}"

git rev-parse -q --verify "$base^{commit}" >/dev/null || die "unknown base revision: $base"
git rev-parse -q --verify "$head^{commit}" >/dev/null || die "unknown head revision: $head"

# Three dots: measure from the merge base, so a branch that is behind its base
# is judged on its own changes and not on what landed underneath it.
changed="$(git diff --name-only "$base...$head")" || die "cannot diff $base...$head"

product="$(awk '
  /^(cmd|internal)\// && !/^internal\/testdata\// && !/_test\.go$/ { print; next }
  /^install\.sh$/ { print }
' <<<"$changed")"

if [ -z "$product" ]; then
	printf 'check-changelog: no product paths changed in %s...%s; no entry needed\n' "$base" "$head"
	exit 0
fi

# The entry lines ("- ...") of the [Unreleased] section, one per line.
unreleased_entries() {
	awk '
    /^## \[Unreleased\]/ { inside = 1; next }
    inside && /^## \[/ { exit }
    inside && /^[[:space:]]*-[[:space:]]/ { print }
  ' <<<"$1"
}

head_changelog="$(git show "$head:CHANGELOG.md" 2>/dev/null)" || die "CHANGELOG.md is missing at $head"
base_changelog="$(git show "$base:CHANGELOG.md" 2>/dev/null || true)"

awk '/^## \[Unreleased\]/ { found = 1 } END { exit !found }' <<<"$head_changelog" ||
	die "CHANGELOG.md at $head has no '## [Unreleased]' heading; nothing could be promoted at release"

# A set difference, not a presence check: an entry that was already unreleased
# before this change does not cover it.
added="$(
	comm -13 \
		<(unreleased_entries "$base_changelog" | sort) \
		<(unreleased_entries "$head_changelog" | sort)
)" || die "cannot compare the [Unreleased] sections of $base and $head"

if [ -z "$added" ]; then
	{
		printf 'check-changelog: this change touches product paths but adds no\n'
		printf 'check-changelog: [Unreleased] entry to CHANGELOG.md:\n'
		printf '%s\n' "$product" | sed 's/^/check-changelog:   /'
		printf 'check-changelog: add one under "## [Unreleased]" (Added, Changed,\n'
		printf 'check-changelog: Fixed, ...), or apply the "no-changelog" label to the\n'
		printf 'check-changelog: pull request if the change has no user-visible effect.\n'
	} >&2
	exit 1
fi

printf 'check-changelog: %s new [Unreleased] entry line(s) cover:\n' "$(printf '%s\n' "$added" | wc -l | tr -d ' ')"
printf '%s\n' "$product" | sed 's/^/check-changelog:   /'
