#!/bin/sh
# noscat installer: curl -fsSL https://raw.githubusercontent.com/Letdown2491/noscat/main/packaging/install.sh | sh
# Installs the latest release binary into ${NOSCAT_INSTALL_DIR:-$HOME/.local/bin}.
set -eu

REPO="Letdown2491/noscat"
INSTALL_DIR="${NOSCAT_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s)
arch=$(uname -m)
case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
# The release tarballs are named by target triple.
case "$os" in
    Linux) target="$arch-unknown-linux-musl" ;;
    Darwin) target="$arch-apple-darwin" ;;
    FreeBSD)
        [ "$arch" = x86_64 ] || { echo "FreeBSD builds are x86_64 only" >&2; exit 1; }
        target="x86_64-unknown-freebsd" ;;
    *) echo "unsupported OS: $os (see https://github.com/$REPO/releases for packages)" >&2; exit 1 ;;
esac

version=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
[ -n "$version" ] || { echo "cannot determine the latest release" >&2; exit 1; }

artifact="noscat-$version-$target.tar.gz"
url="https://github.com/$REPO/releases/download/$version/$artifact"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "# downloading $url"
curl -fsSL "$url" -o "$tmp/$artifact"

mkdir -p "$INSTALL_DIR"
tar -xzf "$tmp/$artifact" -C "$tmp"
install -m 755 "$tmp/noscat" "$INSTALL_DIR/noscat"

echo "# installed $version to $INSTALL_DIR/noscat"
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "# note: $INSTALL_DIR is not on your PATH" ;;
esac
