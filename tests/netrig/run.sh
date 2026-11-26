#!/bin/sh
# Host-side entry point for the netrig network test rig. Builds the rig
# image and the experiment node, then runs every scenario (or the one given)
# and exits non-zero if any scenario misses its expected outcome.
#
#   tests/netrig/run.sh                         # all scenarios
#   tests/netrig/run.sh cone symmetric yes connect
#   DUMP=A RUST_LOG=info tests/netrig/run.sh cone cone yes connect
#   QUIC_WAIT_DIRECT=yes tests/netrig/run.sh cone cone yes connect 60 3 16
#   TERM_TEST=yes tests/netrig/run.sh symmetric symmetric yes connect 60 3
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

podman build -q -t localhost/noscat-netrig -f "$HERE/Containerfile" "$HERE" > /dev/null 2>&1 || { echo "netrig: image build failed"; exit 1; }
podman run --rm -v noscat-cargo-home:/usr/local/cargo:z \
  -v noscat-netrig-target:/target:Z -e CARGO_TARGET_DIR=/target \
  -v "$ROOT:/work:Z" -w /work/tests/netrig/node localhost/noscat-netrig \
  cargo build -q --release

scenario() {
  podman run --rm --privileged \
    -e DUMP="${DUMP:-}" -e RUST_LOG="${RUST_LOG:-warn}" -e QUIC_WAIT_DIRECT="${QUIC_WAIT_DIRECT:-}" \
    -e TERM_TEST="${TERM_TEST:-}" -e TERM_P95_MS="${TERM_P95_MS:-}" \
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
# A terminal relayed through the reachable member at 3% loss: keystroke
# echoes stay quick, a 4 MiB burst arrives intact, the exit status comes back
TERM_TEST=yes scenario symmetric symmetric yes connect 60 3 || failed=1
[ "$failed" = 0 ] && echo "netrig: all scenarios passed" || echo "netrig: FAILURES"
exit "$failed"
