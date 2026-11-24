#!/bin/sh
# Interop check: noscat-core against MDK's White Noise CLI (`wn`).
#
#   tests/mdk-interop/run.sh [MDK_REV]
#
# Clones marmot-protocol/mdk at MDK_REV (default below) into a cache
# volume, builds `wn` and `wnd`, builds the harness, and runs it. Everything
# runs in a noscat-dev based container (see Containerfile). Exits non-zero if any scenario fails.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
MDK_REV=${1:-08f3ebf}
IMAGE=localhost/noscat-mdk

podman build -q -t "$IMAGE" -f "$HERE/Containerfile" "$HERE" > /dev/null 2>&1 || { echo "mdk-interop: image build failed"; exit 1; }

podman volume exists noscat-mdk-src || podman volume create noscat-mdk-src > /dev/null
podman volume exists noscat-mdk-target || podman volume create noscat-mdk-target > /dev/null
TOOLCHAIN=$(podman run --rm "$IMAGE" rustup show active-toolchain | cut -d' ' -f1)

podman run --rm -v noscat-cargo-home:/usr/local/cargo:z \
  -v noscat-mdk-src:/mdk:z -v noscat-mdk-target:/target:z \
  -e CARGO_TARGET_DIR=/target -e RUSTUP_TOOLCHAIN="$TOOLCHAIN" -w /mdk "$IMAGE" sh -ec "
    [ -d /mdk/.git ] || git clone -q https://github.com/marmot-protocol/mdk.git /mdk
    git fetch -q origin && git checkout -q $MDK_REV
    [ -x /mdk/.odin/odin ] || bash scripts/install-odin.sh /mdk/.odin > /dev/null
    ODIN=/mdk/.odin/odin cargo build -q --release -p wn-cli --bins"

podman run --rm -v noscat-cargo-home:/usr/local/cargo:z \
  -v noscat-mdk-target:/mdk-target:z \
  -e CARGO_TARGET_DIR=/mdk-target/harness -e WN_BIN=/mdk-target/release/wn \
  -e RUST_LOG="${RUST_LOG:-warn}" \
  -v "$ROOT:/work:Z" -w /work/tests/mdk-interop "$IMAGE" cargo run -q --release
