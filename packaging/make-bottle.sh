#!/bin/sh
# Craft a Homebrew bottle tarball from a static musl release tarball.
# Hand-assembled rather than `brew bottle`-built: the binary is static musl
# with no paths to relocate, so a receipt + the staged tree is all a bottle
# is. Lets the release job make bottles without Homebrew on the runner.
#
# Usage: make-bottle.sh <version> <formula> <musl-tarball> <tag> <outdir>
#   <tag> is the Homebrew bottle tag: x86_64_linux or arm64_linux.
# Output: <outdir>/noscat-<version>.<tag>.bottle.tar.gz (print its sha256).
set -eu

version=$1
formula=$2
tarball=$3
tag=$4
outdir=$5

case $tag in
    x86_64_linux) arch=x86_64 ;;
    arm64_linux) arch=aarch64 ;;
    *) echo "unknown bottle tag: $tag" >&2; exit 1 ;;
esac

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/src" "$stage/bottle"
tar -xzf "$tarball" -C "$stage/src"

v="$stage/bottle/noscat/$version"
mkdir -p "$v/bin" "$v/share/man/man1" "$v/etc/bash_completion.d" \
    "$v/share/zsh/site-functions" "$v/share/fish/vendor_completions.d" "$v/.brew"
install -m 755 "$stage/src/noscat" "$v/bin/noscat"
install -m 644 "$stage/src/noscat.1" "$v/share/man/man1/noscat.1"
install -m 644 "$stage/src/completions/noscat.bash" "$v/etc/bash_completion.d/noscat"
install -m 644 "$stage/src/completions/noscat.zsh" "$v/share/zsh/site-functions/_noscat"
install -m 644 "$stage/src/completions/noscat.fish" "$v/share/fish/vendor_completions.d/noscat.fish"
cp "$formula" "$v/.brew/noscat.rb"

now=$(date +%s)
cat > "$v/INSTALL_RECEIPT.json" <<EOF
{
  "homebrew_version": "5.1.0-51-g2316400",
  "used_options": [],
  "unused_options": [],
  "built_as_bottle": true,
  "poured_from_bottle": true,
  "loaded_from_api": false,
  "loaded_from_internal_api": false,
  "installed_on_request": true,
  "changed_files": [],
  "time": $now,
  "source_modified_time": $now,
  "compiler": "gcc-12",
  "aliases": [],
  "runtime_dependencies": [],
  "source": {
    "spec": "stable",
    "versions": {
      "stable": "$version",
      "head": null,
      "version_scheme": 0,
      "compatibility_version": null
    },
    "path": "/home/linuxbrew/.linuxbrew/Library/Taps/letdown2491/homebrew-tap/Formula/noscat.rb",
    "tap_git_head": null,
    "tap": "letdown2491/homebrew-tap"
  },
  "arch": "$arch",
  "built_on": {"os": "Linux", "os_version": "Ubuntu 24.04"}
}
EOF

bottle="$outdir/noscat-$version.$tag.bottle.tar.gz"
tar -czf "$bottle" -C "$stage/bottle" noscat
sha256sum "$bottle"
