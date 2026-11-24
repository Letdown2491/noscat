#!/bin/sh
# Host-side entry point for the netrig network test rig. Builds the rig
# image and the experiment node, then runs every scenario (or the one given)
# and exits non-zero if any scenario misses its expected outcome.
#
#   tests/netrig/run.sh                         # all scenarios
#   tests/netrig/run.sh cone symmetric yes connect
#   DUMP=A RUST_LOG=info tests/netrig/run.sh cone cone yes connect
#   QUIC_WAIT_DIRECT=yes tests/netrig/run.sh cone cone yes connect 60 3 16
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)

podman build -q -t localhost/noscat-netrig -f "$HERE/Containerfile" "$HERE" > /dev/null 2>&1 || { echo "netrig: image build failed"; exit 1; }
podman run --rm -v noscat-cargo-home:/usr/local/cargo:Z \
  -v noscat-netrig-target:/target:Z -e CARGO_TARGET_DIR=/target \
  -v "$HERE/node:/work:Z" -w /work localhost/noscat-netrig \
  cargo build -q --release

scenario() {
  podman run --rm --privileged \
    -e DUMP="${DUMP:-}" -e RUST_LOG="${RUST_LOG:-warn}" -e CC="${CC:-bbr}" -e FIPS_MTU="${FIPS_MTU:-1320}" \
    -e QUIC_WAIT_DIRECT="${QUIC_WAIT_DIRECT:-}" -e PROBE_SIZES="${PROBE_SIZES:-}" \
    -v noscat-netrig-target:/target:ro \
    -v "$HERE:/rig:ro,Z" localhost/noscat-netrig sh /rig/rig.sh "$@"
}

if [ $# -gt 0 ]; then
  scenario "$@"
  exit
fi

failed=0
scenario cone cone no never || failed=1
scenario cone cone yes connect || failed=1
scenario cone symmetric yes connect || failed=1
scenario symmetric symmetric yes connect || failed=1
# QUIC streams under loss (16 MiB, BBR, sha256 checked), relayed and punched
scenario symmetric symmetric yes connect 45 3 16 || failed=1
QUIC_WAIT_DIRECT=yes scenario cone cone yes connect 75 3 16 || failed=1
[ "$failed" = 0 ] && echo "netrig: all scenarios passed" || echo "netrig: FAILURES"
exit "$failed"
