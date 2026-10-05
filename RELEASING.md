# Releasing styx

styx ships stable SemVer releases only. One git tag moves all three surfaces
together:

1. the GitHub Release (archives + `SHA256SUMS`, signed keyless with cosign),
2. the Homebrew tap formula (`mobley-trent/homebrew-styx`),
3. what `install.sh` resolves as `latest`.

There is **no self-updater** and no separate publish step: **pushing a `vX.Y.Z`
tag is the release**, and `.github/workflows/release.yml` does the rest.

## The changelog is the source of truth

Every user-visible change gets an entry under `## [Unreleased]` in
[CHANGELOG.md](CHANGELOG.md), in the same pull request that makes the change.
Use the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) categories:
`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.

The release workflow extracts the tag's CHANGELOG section and uses it as the
GitHub Release body, so the release notes and the changelog can never drift. A
tag whose version has no CHANGELOG section fails the release.

Internal-only changes (refactors, tests, CI, tooling docs) do not need an entry.

## Cutting a release

From a clean, up-to-date `main`:

```sh
make release VERSION=v0.1.1
```

`make release` runs `scripts/release.sh`, which:

1. accepts only a stable `vMAJOR.MINOR.PATCH` tag — `release.yml` skips tags
   containing `-`, so a pre-release tag would publish nothing;
2. requires a clean tree on `main`, in sync with `origin/main`, with the tag
   absent locally and on the remote;
3. requires the new version to be greater than the latest existing tag;
4. promotes `## [Unreleased]` to `## [vX.Y.Z] - <date>` and refreshes the
   compare links, refusing to release an empty `[Unreleased]`;
5. runs the full CI gate (`make check`);
6. commits `Release vX.Y.Z`, creates an annotated tag, and pushes both
   atomically.

Preview the changelog promotion and the plan without changing anything:

```sh
make release-dry-run VERSION=v0.1.1
```

## Versioning

- **MAJOR** — an incompatible change to sessions, config, the engagement file
  format, or the tool/CLI surface.
- **MINOR** — a backwards-compatible capability.
- **PATCH** — a backwards-compatible fix.

Sessions and config are same-major compatible (README → Compatibility), so
MAJOR only moves for a real compatibility break.

## Verifying a release

The workflow's `verify` job downloads the published archives on both supported
OSes, runs `cosign verify-blob` against the workflow identity, checks each
archive against `SHA256SUMS`, and runs `styx --version`. To verify a manual
download yourself, use the README's `cosign verify-blob` snippet.

## If a release is broken

There is no un-publish: the tap and `install.sh` follow the latest release.
Ship a follow-up patch (`vX.Y.Z+1`). Never move or force-push an existing tag.
