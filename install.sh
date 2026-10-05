#!/bin/sh
# install.sh — the blessed Linux install path for styx (§12.1).
#
#   curl -fsSL https://raw.githubusercontent.com/mobley-trent/styx-agent/main/install.sh | sh
#
# It picks the architecture, downloads the release archive, verifies it against
# the published SHA256SUMS, and installs the binary to ~/.local/bin. It does not
# verify the cosign signature: that is the documented manual path (§12.2), so
# the checksum line above is what this script trusts.
#
# Overridable via the environment:
#   STYX_VERSION      install a specific tag (e.g. v0.2.0); default: latest
#   STYX_INSTALL_DIR  install directory; default: ~/.local/bin

set -eu

REPO="mobley-trent/styx-agent"
BIN="styx"
INSTALL_DIR="${STYX_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${STYX_VERSION:-latest}"

err() {
	echo "install.sh: $*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || err "$1 is required but was not found"
}

need curl
need tar
need uname
need sed
need grep

os="$(uname -s)"
case "$os" in
Linux) os="linux" ;;
Darwin)
	err "macOS uses the blessed Homebrew tap: brew install mobley-trent/styx/styx"
	;;
*) err "unsupported operating system: $os (styx supports Linux and macOS 13+)" ;;
esac

arch="$(uname -m)"
case "$arch" in
x86_64 | amd64) arch="amd64" ;;
aarch64 | arm64) arch="arm64" ;;
*) err "unsupported architecture: $arch" ;;
esac

# Resolve "latest" to a concrete tag through the GitHub releases endpoint.
if [ "$VERSION" = "latest" ]; then
	VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
	[ -n "$VERSION" ] || err "could not determine the latest release"
fi

# goreleaser strips the leading "v" from the archive name.
num_version="${VERSION#v}"
archive="styx_${num_version}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/v${num_version}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "downloading styx $VERSION ($os/$arch)..."
curl -fsSL "$base/$archive" -o "$tmp/$archive" || err "download failed: $base/$archive"
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || err "download failed: $base/SHA256SUMS"

# Verify the archive against the published checksum before touching it.
expected="$(grep " $archive\$" "$tmp/SHA256SUMS" | awk '{print $1}')"
[ -n "$expected" ] || err "$archive is not listed in SHA256SUMS"

if command -v sha256sum >/dev/null 2>&1; then
	actual="$(sha256sum "$tmp/$archive" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
	actual="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"
else
	err "sha256sum or shasum is required to verify the download"
fi

[ "$expected" = "$actual" ] || err "checksum mismatch for $archive (expected $expected, got $actual)"

tar -xzf "$tmp/$archive" -C "$tmp" "$BIN" || err "could not extract $BIN from $archive"

mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp/$BIN" "$INSTALL_DIR/$BIN" 2>/dev/null ||
	{ cp "$tmp/$BIN" "$INSTALL_DIR/$BIN" && chmod 0755 "$INSTALL_DIR/$BIN"; }

echo "installed $BIN $VERSION to $INSTALL_DIR/$BIN"
case ":$PATH:" in
*":$INSTALL_DIR:"*) ;;
*) echo "note: add $INSTALL_DIR to your PATH (e.g. export PATH=\"$INSTALL_DIR:\$PATH\")" ;;
esac
