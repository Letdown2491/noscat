#!/bin/sh
# Fetches the FIPS crates that do not build on the BSDs yet, applies
# packaging/bsd/patches/ to them, and prints the cargo `--config` arguments
# that use the patched copies (upstream draft: docs/upstream/01-freebsd-build.md).
# Only BSD builds use this; every other platform builds pure crates.io code.
#
# Usage, from the repo root:
#   cargo build --release $(packaging/bsd/patch-crates.sh)
#
# Each patch is named <crate>-<version>.diff, against the published crate.
# Needs curl (or fetch, on FreeBSD), tar and patch. Writes to target/bsd-crates.
set -eu

root=$(pwd)
dir="$root/target/bsd-crates"
mkdir -p "$dir"
for p in "$root"/packaging/bsd/patches/*.diff; do
  name=$(basename "$p" .diff)        # nvpn-fips-core-0.4.124
  crate=${name%-*}                   # nvpn-fips-core
  version=${name##*-}                # 0.4.124
  if [ ! -f "$dir/$name/.patched" ]; then
    rm -rf "${dir:?}/$name"
    url="https://static.crates.io/crates/$crate/$name.crate"
    if command -v curl >/dev/null 2>&1; then
      curl -sSfL "$url" -o "$dir/$name.crate"
    else
      fetch -q -o "$dir/$name.crate" "$url"
    fi
    tar -xzf "$dir/$name.crate" -C "$dir"
    rm "$dir/$name.crate"
    (cd "$dir/$name" && patch -s -p1 < "$p")
    touch "$dir/$name/.patched"
  fi
  # Exact version pins keep the patch from silently applying to a newer
  # crate the lockfile moves to.
  grep -q "^version = \"$version\"" "$dir/$name/Cargo.toml"
  printf -- '--config patch.crates-io.%s.path="%s" ' "$crate" "$dir/$name"
done
