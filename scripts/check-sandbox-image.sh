#!/usr/bin/env bash
# check-sandbox-image.sh — verify the sandbox image's pins and build artifacts.
#
#   scripts/check-sandbox-image.sh                          # static: pins and generation
#   scripts/check-sandbox-image.sh --resolve                # + every pin resolves on
#                                                          #   every architecture
#   scripts/check-sandbox-image.sh --image <ref> [--version <v>] [--platform <p>]
#                                                          # + the built image itself
#
# --version is the version the image was published as. Static mode defaults to
# image.json's own image_version, which is what a local build records; the
# publish workflow builds and checks the version it tags (§4.4).
#
# --platform selects the architecture to execute when <ref> is an index. The
# publish workflow checks amd64 natively and re-runs this whole file against the
# arm64 manifest under qemu, so both halves of the index are proved rather than
# one being assumed from the other (§4.3).
#
# Static mode needs only jq and python3. It regenerates the toolset manifest and
# the build information from sandbox/image.json exactly as the Dockerfile does —
# per architecture, because the apt pins are — validates the manifest against
# sandbox/toolset.schema.json, and checks every pinned input is recorded — so a
# broken pin or an unacceptable manifest fails a pull request instead of a
# monthly image build. With --image it also checks the image's own /etc/styx
# files are byte-identical to that generation, that every declared tool exists at
# its declared version, and that the baked tool data and offline environment are
# what the spec promises.
#
# --resolve needs docker. It asks apt inside the pinned base image, for every
# architecture, whether each pinned version is in that architecture's index — a
# version the archive no longer carries for one architecture fails here, which
# the static checks cannot see because the archive moves and the pins do not.
#
# Exit: 0 every check passed; 1 a check failed; 2 a usage error.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sandbox="$root/sandbox"
pins="$sandbox/image.json"
schema="$sandbox/toolset.schema.json"
validator="$sandbox/validate-toolset.py"
dockerfile="$sandbox/Dockerfile"
requirements="$sandbox/requirements-semgrep.txt"
image=""
version=""
platform=""
resolve=0

note() { printf 'check-sandbox-image: %s\n' "$*"; }
die() {
	printf 'check-sandbox-image: %s\n' "$*" >&2
	exit 1
}
die_usage() {
	printf 'check-sandbox-image: %s\n' "$*" >&2
	printf 'check-sandbox-image: usage: scripts/check-sandbox-image.sh [--image <ref>] [--version <v>] [--platform <p>] [--resolve]\n' >&2
	exit 2
}

# Every execution of the image goes through here, so a check run for another
# architecture can never accidentally execute the host's.
run_image() {
	if [ -n "$platform" ]; then
		docker run --rm --platform "$platform" "$@"
	else
		docker run --rm "$@"
	fi
}

while [ $# -gt 0 ]; do
	case "$1" in
	--image)
		[ $# -ge 2 ] || die_usage "--image needs an image reference"
		image="$2"
		shift 2
		;;
	--version)
		[ $# -ge 2 ] || die_usage "--version needs a value"
		version="$2"
		shift 2
		;;
	--platform)
		[ $# -ge 2 ] || die_usage "--platform needs a value"
		platform="$2"
		shift 2
		;;
	--resolve)
		resolve=1
		shift
		;;
	-h | --help)
		sed -n '2,/^$/{/^$/d;p}' "$0"
		exit 0
		;;
	*) die_usage "unknown argument: $1" ;;
	esac
done

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
[ -f "$pins" ] || die "missing sandbox/image.json"
[ -f "$schema" ] || die "missing sandbox/toolset.schema.json"
[ -f "$validator" ] || die "missing sandbox/validate-toolset.py"
[ -f "$dockerfile" ] || die "missing sandbox/Dockerfile"
[ -f "$requirements" ] || die "missing sandbox/requirements-semgrep.txt"
# The architectures sandbox-image.yml builds and verifies. A pin has to resolve
# on every one of them, and each gets its own generated apt list.
archs_json='["amd64","arm64"]'
architectures="$(printf '%s' "$archs_json" | jq -r '.[]')"
for arch in $architectures; do
	[ -f "$sandbox/apt-pins-$arch.txt" ] || die "missing sandbox/apt-pins-$arch.txt"
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

jq -e . "$pins" >/dev/null 2>&1 || die "sandbox/image.json is not valid JSON"

if [ -z "$version" ]; then
	version="$(jq -r .image_version "$pins")"
fi
printf '%s' "$version" | grep -Eq '^sandbox-v1\.[0-9]{4}\.[0-9]{2}\.[0-9]+$' ||
	die "the image version must look like sandbox-v1.YYYY.MM.PATCH, got: $version"

# 1. Every input carries its pin. A pin that is a tag, a range, or missing is
#    the failure mode this file exists to make impossible.
jq -e '
  (.image_version | type == "string" and test("^sandbox-v1\\.[0-9]{4}\\.[0-9]{2}\\.[0-9]+$")) and
  (.source_date_epoch | type == "number") and
  (.base.digest | test("^sha256:[0-9a-f]{64}$")) and
  (.builder.digest | test("^sha256:[0-9a-f]{64}$")) and
  (.semgrep_requirements | length > 0) and
  (.tools | length > 0) and
  (all(.tools[]; (.name | length > 0) and (.version | length > 0) and (.binary | length > 0))) and
  (all(.tools[]; if .package == null then .package_version == null else (.package | length > 0) and (.package_version | length > 0) end)) and
  (all(.supporting[]; (.package | length > 0) and (.package_version | length > 0))) and
  (all(.wordlists[]; (.name | length > 0) and (.url | startswith("https://")) and (.path | startswith("/usr/share/wordlists/styx/")) and (.sha256 | test("^[0-9a-f]{64}$")))) and
  (.data.seclists.commit | test("^[0-9a-f]{40}$")) and
  (.data.seclists.license.sha256 | test("^[0-9a-f]{64}$")) and
  (.data.nuclei_templates.tag | length > 0) and
  (.data.nuclei_templates.sha256 | test("^[0-9a-f]{64}$")) and
  (.data.semgrep_rules.commit | test("^[0-9a-f]{40}$")) and
  (.data.semgrep_rules.sha256 | test("^[0-9a-f]{64}$")) and
  (.data.trivy_db.digest | test("^sha256:[0-9a-f]{64}$")) and
  (.data.trivy_db.layer_digest | test("^sha256:[0-9a-f]{64}$")) and
  (.data.trivy_db.layer_size | type == "number") and
  (.data.trivy_java_db.digest | test("^sha256:[0-9a-f]{64}$")) and
  (.data.trivy_java_db.layer_digest | test("^sha256:[0-9a-f]{64}$")) and
  (.data.trivy_java_db.layer_size | type == "number")
' "$pins" >/dev/null ||
	die "sandbox/image.json is missing a pinned input: every tool, package, wordlist, and tool-data source needs its exact version, digest, or checksum"

# 1b. Every package resolves to one exact version on every architecture. A
#     package rebuilt as a per-arch binNMU names that architecture in
#     package_versions instead of pinning a version another architecture cannot
#     install; no package_versions means the pin is the same on all of them.
jq -e --argjson archs "$archs_json" '
  [ (.tools[], .supporting[]) | select(.package != null) | . as $p
    | (($p.package_versions // {}) | keys[]) as $k
    | select(($archs | index($k)) == null)
    | "\($p.package): package_versions names \($k), which the image is not built for"
  ] + [ (.tools[], .supporting[]) | select(.package != null) | . as $p
        | $archs[] as $a
        | ($p.package_versions[$a] // $p.package_version) as $v
        | select(($v | type) != "string" or ($v | length) == 0)
        | "\($p.package): no exact version for \($a)"
      ]
  | length == 0
' "$pins" >/dev/null ||
	die "sandbox/image.json must pin one exact version per package per architecture (amd64, arm64)"

# 2. apt-pins-<arch>.txt is generated from image.json, never hand-edited: the
#    build installs exactly that list, and drift between it and the pins fails
#    here. One file per architecture, because a Debian binNMU rebuild gives one
#    architecture a version the others do not carry.
for arch in $architectures; do
	jq -r --arg arch "$arch" '[.tools[], .supporting[]] | map(select(.package != null)) | map("\(.package)=\(.package_versions[$arch] // .package_version)") | unique | .[]' "$pins" >"$work/apt-pins-$arch.txt"
	cmp -s "$work/apt-pins-$arch.txt" "$sandbox/apt-pins-$arch.txt" ||
		die "sandbox/apt-pins-$arch.txt is out of step with sandbox/image.json; regenerate it from the pins"
done
grep -qF 'apt-pins-${TARGETARCH}.txt' "$dockerfile" ||
	die "sandbox/Dockerfile must install the pinned packages from sandbox/apt-pins-<arch>.txt"
grep -q '^ARG TARGETARCH$' "$dockerfile" ||
	die "sandbox/Dockerfile must declare ARG TARGETARCH to select the architecture's pin list"

# 3. The deterministic generation the Dockerfile performs, twice, so build info
#    can record the manifest's own hash. The toolset names no apt version, so it
#    has to be the same declaration on every architecture; build-info names them,
#    so it is generated once per architecture.
requirements_sha="$(sha256sum "$requirements" | cut -d' ' -f1)"
for arch in $architectures; do
	jq -S -f "$sandbox/manifest.jq" --arg toolset_sha "" --arg req_sha "$requirements_sha" \
		--arg image_version "$version" --arg arch "$arch" "$pins" >"$work/gen-$arch.json" ||
		die "sandbox/manifest.jq failed on sandbox/image.json"
	jq -S .toolset "$work/gen-$arch.json" >"$work/toolset-$arch.json"
done
for arch in $architectures; do
	cmp -s "$work/toolset-amd64.json" "$work/toolset-$arch.json" ||
		die "the generated toolset manifest differs between amd64 and $arch; it must not name anything architecture-specific"
done
cp "$work/toolset-amd64.json" "$work/toolset.json"
toolset_sha="$(sha256sum "$work/toolset.json" | cut -d' ' -f1)"
for arch in $architectures; do
	jq -S -f "$sandbox/manifest.jq" --arg toolset_sha "$toolset_sha" --arg req_sha "$requirements_sha" \
		--arg image_version "$version" --arg arch "$arch" "$pins" |
		jq -S .build_info >"$work/build-info-$arch.json"
done

# 3. The manifest the image will ship satisfies its own schema.
python3 "$validator" "$work/toolset.json" "$schema" ||
	die "the generated toolset manifest does not satisfy sandbox/toolset.schema.json"

# 4. Build information records every pinned input, and every apt package at its
#    architecture's pinned version, so "what produced this digest" is answerable
#    from the image alone.
for arch in $architectures; do
	jq -e --arg version "$version" --arg arch "$arch" --slurpfile pinned "$pins" '
  (.base.digest == $pinned[0].base.digest) and
  (.builder.digest == $pinned[0].builder.digest) and
  (.source_date_epoch == $pinned[0].source_date_epoch) and
  (.image_version == $version) and
  (.data.seclists.commit == $pinned[0].data.seclists.commit) and
  (.data.seclists.license.sha256 == $pinned[0].data.seclists.license.sha256) and
  (.data.nuclei_templates.tag == $pinned[0].data.nuclei_templates.tag) and
  (.data.nuclei_templates.sha256 == $pinned[0].data.nuclei_templates.sha256) and
  (.data.semgrep_rules.commit == $pinned[0].data.semgrep_rules.commit) and
  (.data.semgrep_rules.sha256 == $pinned[0].data.semgrep_rules.sha256) and
  (.data.trivy_db.digest == $pinned[0].data.trivy_db.digest) and
  (.data.trivy_java_db.digest == $pinned[0].data.trivy_java_db.digest) and
  (.upstream[0].requirements_sha256 | test("^[0-9a-f]{64}$")) and
  (.toolset_sha256 | test("^[0-9a-f]{64}$")) and
  ([.apt[] | "\(.package)=\(.version)"] | sort ==
    ([$pinned[0].tools[], $pinned[0].supporting[]] |
      map(select(.package != null) | "\(.package)=\(.package_versions[$arch] // .package_version)") | sort))
' "$work/build-info-$arch.json" >/dev/null ||
		die "build-info-$arch.json does not record every pinned input at its pinned version"
done

# 5. semgrep's lock is what the "pinned upstream release" means: one exact
#    version and a hash for every artifact pip may install.
semgrep_version="$(jq -r '.tools[] | select(.source == "pypi") | .version' "$pins")"
[ -n "$semgrep_version" ] || die "sandbox/image.json declares no pypi-installed tool"
grep -q "^semgrep==${semgrep_version} " "$requirements" ||
	die "requirements-semgrep.txt pins a semgrep other than ${semgrep_version}"
if grep -Eq '^[[:space:]]*(-e|--index-url|--extra-index-url|--trusted-host)' "$requirements"; then
	die "requirements-semgrep.txt may not point pip at another index or an editable install"
fi
grep -q -- '--hash=sha256:' "$requirements" || die "requirements-semgrep.txt carries no hashes"
if awk '/^[[:space:]]*(#|$)/ { next } /^[[:space:]]/ { next } $0 !~ /==/ { print; bad = 1 } END { exit bad }' "$requirements"; then
	:
else
	die "requirements-semgrep.txt has an unpinned requirement"
fi

# 6. The Dockerfile can only build what the pins describe, and it must never
#    drift: no upgrade, no tag-resolved base, no unpinned download.
grep -q "^# syntax=docker/dockerfile:1@$(jq -r .builder.digest "$pins")$" "$dockerfile" ||
	die "sandbox/Dockerfile's syntax directive is not pinned to image.json's builder digest"
grep -q "^ARG BASE=.*@$(jq -r .base.digest "$pins")$" "$dockerfile" ||
	die "sandbox/Dockerfile's BASE arg is not pinned to image.json's base digest"
grep -q "^ARG SOURCE_DATE_EPOCH=$(jq -r .source_date_epoch "$pins")$" "$dockerfile" ||
	die "sandbox/Dockerfile's SOURCE_DATE_EPOCH does not match image.json's build clock"
grep -q '^ARG IMAGE_VERSION=' "$dockerfile" ||
	die "sandbox/Dockerfile must take the published image version as a build arg"
grep -q -- '--arg image_version' "$dockerfile" ||
	die "sandbox/Dockerfile must pass the image version into manifest.jq, or the tag and the declaration disagree"
grep -q -- '--arg arch' "$dockerfile" ||
	die "sandbox/Dockerfile must pass the target architecture into manifest.jq, or build-info names another architecture's apt versions"
grep -q 'stat -c %s' "$dockerfile" ||
	die "sandbox/Dockerfile must verify the pinned size of every checksummed download"
grep -q 'sha256sum -c -' "$dockerfile" ||
	die "sandbox/Dockerfile must verify every checksummed download"
grep -q 'Accept: application/vnd.oci.image.manifest.v1+json' "$dockerfile" ||
	die "sandbox/Dockerfile must ask the registry for an OCI manifest explicitly: without the Accept header GHCR answers 404"
for ref in trivy_db trivy_java_db; do
	grep -q "jq -r .data.${ref}.digest" "$dockerfile" ||
		die "sandbox/Dockerfile does not read the pinned ${ref} manifest digest from image.json"
	grep -q "jq -r .data.${ref}.layer_digest" "$dockerfile" ||
		die "sandbox/Dockerfile does not read the pinned ${ref} layer digest from image.json"
done
grep -q 'apt-get install -y --no-install-recommends' "$dockerfile" ||
	die "sandbox/Dockerfile must install with --no-install-recommends"
if sed 's/^[[:space:]]*#.*//' "$dockerfile" | grep -Eq 'apt-get (dist-)?upgrade'; then
	die "sandbox/Dockerfile must never upgrade packages: drift has to fail the build"
fi
grep -q 'validate-toolset.py' "$dockerfile" ||
	die "sandbox/Dockerfile must validate the manifest it generated"

note "static checks passed: $(jq '.tools | length' "$pins") tools, $(jq '.supporting | length' "$pins") supporting packages, $(jq '.wordlists | length' "$pins") wordlists"

# 7. Every pin resolves on every architecture. Static checks cannot see this: the
#    archive moves, so a version pinned for one architecture can vanish from its
#    index while the other still carries it, and the build then fails on that
#    architecture alone. Ask the pinned base image's own apt, from the indexes
#    the build installs from: `apt-get download --print-uris` exits 100 for a
#    version that architecture's index does not carry, and fetches nothing when
#    it does. arch:all packages are indexed for every architecture but apt
#    refuses a foreign qualifier for them, so those are checked unqualified —
#    the same _all.deb is what either architecture installs.
if [ "$resolve" -eq 1 ]; then
	command -v docker >/dev/null 2>&1 || die "docker is required for --resolve"
	base="$(jq -r '.base.ref + "@" + .base.digest' "$pins")"
	note "resolving every pin on every architecture against $base"
	mounts=()
	for arch in $architectures; do
		mounts+=(-v "$sandbox/apt-pins-$arch.txt:/check/apt-pins-$arch.txt:ro")
	done
	docker run --rm "${mounts[@]}" --entrypoint bash "$base" -c '
		set -euo pipefail
		host_arch="$(dpkg --print-architecture)"
		for list in /check/apt-pins-*.txt; do
			arch="$(basename "$list" .txt)"
			arch="${arch#apt-pins-}"
			[ "$arch" = "$host_arch" ] || dpkg --add-architecture "$arch"
		done
		apt-get update -qq
		available() {
			pkg="$1"
			ver="$2"
			arch="$3"
			if apt-get download --print-uris "${pkg}:${arch}=${ver}" >/dev/null 2>&1; then
				return 0
			fi
			if [ "$(apt-cache show "$pkg" 2>/dev/null | sed -n "s/^Architecture: //p" | head -n1)" != all ]; then
				return 1
			fi
			apt-get download --print-uris "${pkg}=${ver}" >/dev/null 2>&1
		}
		missing=0
		for list in /check/apt-pins-*.txt; do
			arch="$(basename "$list" .txt)"
			arch="${arch#apt-pins-}"
			while IFS="=" read -r pkg ver; do
				[ -n "$pkg" ] || continue
				if ! available "$pkg" "$ver" "$arch"; then
					printf "no %s index entry for %s=%s\n" "$arch" "$pkg" "$ver" >&2
					missing=1
				fi
			done < "$list"
		done
		exit "$missing"
	' || die "the pins do not resolve: an architecture's index no longer carries every pinned version"
fi

if [ -z "$image" ]; then
	exit 0
fi

# 7. The built image: its declaration must be exactly the generation above, and
#    its contents must match that declaration. Run it, do not infer it.
command -v docker >/dev/null 2>&1 || die "docker is required for --image"
note "checking the built image: $image${platform:+ as $platform}"

# The pins are per architecture, so the check has to know which one it is looking
# at: the requested platform, or the image's own when none was given.
if [ -n "$platform" ]; then
	arch="${platform#linux/}"
else
	arch="$(run_image --entrypoint dpkg "$image" --print-architecture)"
fi
printf '%s\n' $architectures | grep -qx "$arch" ||
	die "sandbox/image.json pins no packages for architecture: $arch"

run_image "$image" cat /etc/styx/toolset.json >"$work/image-toolset.json" 2>/dev/null ||
	die "cannot read /etc/styx/toolset.json from $image"
run_image "$image" cat /etc/styx/build-info.json >"$work/image-build-info.json" 2>/dev/null ||
	die "cannot read /etc/styx/build-info.json from $image"

cmp -s "$work/toolset.json" "$work/image-toolset.json" ||
	die "the image's toolset manifest differs from what sandbox/image.json generates"
cmp -s "$work/build-info-$arch.json" "$work/image-build-info.json" ||
	die "the image's build-info.json differs from what sandbox/image.json generates"
python3 "$validator" "$work/image-toolset.json" "$schema" ||
	die "the image's toolset manifest does not satisfy sandbox/toolset.schema.json"

jq -r --arg arch "$arch" '.tools[] | [.name, .binary, (.package // "-"), (.package_versions[$arch] // .package_version // "-"), .version] | @tsv' "$pins" >"$work/tools.tsv"
jq -r '.wordlists[] | [.path, .sha256] | @tsv' "$pins" >"$work/wordlists.tsv"

cat >"$work/in-image.sh" <<'EOS'
set -euo pipefail
tab="$(printf '\t')"
fail() { printf 'check-sandbox-image: %s\n' "$*" >&2; exit 1; }

# Every declared tool exists, at the declared version: for a package install the
# package manager's own record is the authority; for the upstream install the
# tool's own version output is.
while IFS="$tab" read -r name binary package package_version version; do
  command -v "$binary" >/dev/null 2>&1 || fail "declared tool $name has no binary named $binary"
  if [ "$package" != "-" ]; then
    got="$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null)" || fail "declared tool $name: package $package is not installed"
    [ "$got" = "$package_version" ] || fail "declared tool $name: $package is $got, declared $package_version"
  else
    out="$("$binary" --version 2>&1 || true)"
    case "$out" in
      *"$version"*) ;;
      *) fail "declared tool $name: --version does not report $version ($out)" ;;
    esac
  fi
done < /check/tools.tsv

# The wordlists are the bytes the manifest declares.
while IFS="$tab" read -r path want; do
  got="$(sha256sum "$path" 2>/dev/null | cut -d' ' -f1)" || fail "declared wordlist $path is missing"
  [ "$got" = "$want" ] || fail "declared wordlist $path hashes to $got, declared $want"
done < /check/wordlists.tsv

# The baked tool data and the in-image help text.
[ -n "$(ls -A /root/nuclei-templates 2>/dev/null)" ] || fail "nuclei templates are missing"
[ -n "$(ls -A /opt/semgrep-rules 2>/dev/null)" ] || fail "semgrep rules are missing"
for db in /opt/trivy-cache/db/trivy.db /opt/trivy-cache/java-db/javadb/trivy-java.db; do
  [ -s "$db" ] || fail "trivy database file is missing: $db"
done
[ -s /etc/styx/README ] || fail "/etc/styx/README is missing"
[ -s /usr/share/doc/styx/SecLists-LICENSE ] || fail "the SecLists licence is missing"

# The runtimes code_exec promises, and the shell the harness execs through
# (§2.1, §5.1): the image is the contract, so it is checked, not assumed.
for cmd in bash python3 node; do
  command -v "$cmd" >/dev/null 2>&1 || fail "the promised runtime $cmd is missing"
done
python3 -V >/dev/null 2>&1 || fail "python3 does not run"
node -v >/dev/null 2>&1 || fail "node does not run"

# The offline posture is the default, not a flag a caller has to remember (§8).
[ "${TRIVY_SKIP_DB_UPDATE:-}" = "true" ] || fail "TRIVY_SKIP_DB_UPDATE is not true"
[ "${TRIVY_SKIP_JAVA_DB_UPDATE:-}" = "true" ] || fail "TRIVY_SKIP_JAVA_DB_UPDATE is not true"
[ "${TRIVY_OFFLINE_SCAN:-}" = "true" ] || fail "TRIVY_OFFLINE_SCAN is not true"
[ "${SEMGREP_SEND_METRICS:-}" = "off" ] || fail "SEMGREP_SEND_METRICS is not off"
[ -n "${STYX_WORDLISTS:-}" ] || fail "STYX_WORDLISTS is not set"
EOS

run_image -v "$work:/check:ro" --entrypoint bash "$image" /check/in-image.sh ||
	die "the built image does not match its declaration"

note "image checks passed: $image${platform:+ as $platform}"
