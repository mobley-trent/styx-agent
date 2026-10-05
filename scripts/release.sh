#!/usr/bin/env bash
# release.sh — cut a stable release: verify, promote CHANGELOG.md, tag, push.
#
#   make release VERSION=v0.1.1
#   scripts/release.sh --dry-run v0.1.1
#
# This script never publishes anything itself. Pushing the tag is what triggers
# .github/workflows/release.yml (goreleaser archives, keyless-cosign SHA256SUMS,
# the Homebrew tap, and the release-notes extraction from CHANGELOG.md).
# Full process: RELEASING.md.

set -euo pipefail

die() { printf 'release: %s\n' "$*" >&2; exit 1; }
note() { printf 'release: %s\n' "$*" >&2; }

dry_run=0
version=""
while [ $# -gt 0 ]; do
	case "$1" in
	--dry-run) dry_run=1 ;;
	-h | --help)
		sed -n '2,11p' "$0"
		exit 0
		;;
	-*) die "unknown flag: $1" ;;
	*)
		[ -z "$version" ] || die "unexpected extra argument: $1"
		version="$1"
		;;
	esac
	shift
done

[ -n "$version" ] || die "usage: scripts/release.sh [--dry-run] vX.Y.Z"

# Stable SemVer only: release.yml skips any tag containing '-', so a pre-release
# tag would silently publish nothing.
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
	die "version must be a stable SemVer tag like v0.1.1 (no pre-release suffix)"

root="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not inside a git repository"
cd "$root"

[ -f CHANGELOG.md ] || die "CHANGELOG.md is missing"

# --- repository state --------------------------------------------------------
[ -z "$(git status --porcelain)" ] || die "working tree is not clean; commit or stash first"

branch="$(git symbolic-ref --short -q HEAD || true)"
[ "$branch" = "main" ] || die "releases are cut from main (currently on '${branch:-detached HEAD}')"

git fetch --quiet origin main
[ "$(git rev-parse main)" = "$(git rev-parse origin/main)" ] ||
	die "local main is out of sync with origin/main; pull first"

if git rev-parse -q --verify "refs/tags/$version" >/dev/null; then
	die "tag $version already exists locally"
fi
if git ls-remote --exit-code --tags origin "refs/tags/$version" >/dev/null 2>&1; then
	die "tag $version already exists on origin"
fi

latest="$(git tag -l 'v[0-9]*' | sort -V | tail -n1)"
if [ -n "$latest" ]; then
	newest="$(printf '%s\n%s\n' "$latest" "$version" | sort -V | tail -n1)"
	{ [ "$newest" = "$version" ] && [ "$latest" != "$version" ]; } ||
		die "$version is not newer than the latest release tag $latest"
fi

# --- changelog ---------------------------------------------------------------
origin_url="$(git config --get remote.origin.url)"
case "$origin_url" in
git@github.com:*)
	path="${origin_url#git@github.com:}"
	repo_url="https://github.com/${path%.git}"
	;;
https://github.com/*) repo_url="${origin_url%.git}" ;;
*) die "cannot derive a GitHub repo URL from origin: $origin_url" ;;
esac

today="$(date -u +%Y-%m-%d)"
promoted="$(mktemp)"
trap 'rm -f "$promoted"' EXIT

scripts/promote-changelog.sh "$version" "$today" "$repo_url" CHANGELOG.md >"$promoted" ||
	die "refusing to release: CHANGELOG.md could not be promoted"

if [ "$dry_run" = 1 ]; then
	note "dry run: the following CHANGELOG.md change would be committed"
	diff -u CHANGELOG.md "$promoted" || true
	note "dry run: would run 'make check', commit, tag $version, and push to origin"
	exit 0
fi

# --- verify ------------------------------------------------------------------
note "running the full CI gate (make check)"
make check

# --- promote, commit, tag, push ----------------------------------------------
mv "$promoted" CHANGELOG.md
git add CHANGELOG.md
git commit -m "Release $version"

git tag -a "$version" -m "Release $version"

note "pushing main and $version (this triggers the release workflow)"
git push --atomic origin main "refs/tags/$version"

note "pushed $version; the release workflow is now running:"
note "  ${repo_url}/actions/workflows/release.yml"
