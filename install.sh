#!/bin/sh
# eimer installer: downloads the release archive for this machine, verifies it against the
# published checksums, and puts the binary on your PATH. POSIX sh, needs curl or wget and
# sha256sum or shasum.
#
#   curl -fsSL https://raw.githubusercontent.com/morrieinmaas/eimer/main/install.sh | sh
#
# Knobs: EIMER_VERSION (default: latest release, without the v), EIMER_INSTALL_DIR
# (default: /usr/local/bin if writable, else ~/.local/bin).
set -eu

repo="morrieinmaas/eimer"

say() { printf '%s\n' "$*" >&2; }
die() { say "install: $*"; exit 1; }

fetch() { # url [outfile]
  if command -v curl >/dev/null 2>&1; then
    if [ $# -eq 2 ]; then curl -fsSL "$1" -o "$2"; else curl -fsSL "$1"; fi
  elif command -v wget >/dev/null 2>&1; then
    if [ $# -eq 2 ]; then wget -q "$1" -O "$2"; else wget -q "$1" -O -; fi
  else
    die "need curl or wget"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else die "need sha256sum or shasum"; fi
}

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in linux|darwin) ;; *) die "unsupported OS $os: build from source with go install" ;; esac
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture $arch" ;;
esac

version="${EIMER_VERSION:-}"
if [ -z "$version" ]; then
  # GitHub redirects /releases/latest to /releases/tag/vX.Y.Z; read the tag off the redirect.
  version=$(curl -fsSI "https://github.com/$repo/releases/latest" 2>/dev/null | tr -d '\r' \
    | awk 'tolower($1)=="location:"{sub(/.*\/tag\/v?/,"",$2); print $2}')
  [ -n "$version" ] || die "could not determine the latest version; set EIMER_VERSION"
fi

base="${EIMER_DOWNLOAD_BASE:-https://github.com/$repo/releases/download/v$version}"
archive="eimer_${version}_${os}_${arch}.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say "downloading eimer $version for $os/$arch"
fetch "$base/$archive" "$tmp/$archive" || die "no release $version for $os/$arch at $base"
fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "checksums.txt missing for release $version"

want=$(awk -v f="$archive" '$2==f{print $1}' "$tmp/checksums.txt")
[ -n "$want" ] || die "$archive is not in checksums.txt"
got=$(sha256 "$tmp/$archive")
[ "$want" = "$got" ] || die "checksum mismatch for $archive: expected $want, got $got"

tar -xzf "$tmp/$archive" -C "$tmp" eimer

dir="${EIMER_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir"
install -m 0755 "$tmp/eimer" "$dir/eimer"

say "installed $("$dir/eimer" version) to $dir/eimer (sha256 verified)"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "note: $dir is not on your PATH; add it, e.g. export PATH=\"$dir:\$PATH\"" ;;
esac
