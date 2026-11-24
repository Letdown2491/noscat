#!/bin/sh
# One netrig scenario. Runs as (namespaced) root inside a --privileged
# rootless container; run.sh is the host-side entry point.
#
# Usage: rig.sh <nat_a> <nat_b> <with_c> <expect> [duration_secs] [loss_pct] [quic_mib]
#   nat_a, nat_b: cone | symmetric
#   with_c:       yes | no      (a publicly reachable member C)
#   expect:       connect | never   (A<->B outcome this scenario must show)
#   loss_pct:     random loss on each router's WAN egress (default 0), so
#                 every A<->B direction crosses one lossy hop
#   quic_mib:     if set, A sends this many MiB to B over QUIC once pings
#                 work, and the scenario also requires a verified transfer
#
# env: FIPS_MTU (default 1320, see below), QUIC_WAIT_DIRECT=yes (hold the
#      transfer until A has a direct link to B), CC (bbr | cubic),
#      PROBE_SIZES, RUST_LOG, DUMP=<A|B|C> (print that node's log)
#
# FIPS fragments service datagrams only on a direct link; a relayed path
# carries at most (FIPS_MTU - 110) bytes. QUIC needs 1200, so the rig, like
# noscat, runs FIPS at 1320 (relayed max 1210). FIPS's own default, 1280,
# makes QUIC fail over every relayed path.
#
#   wan bridge 37.120.10.0/24 (the "internet"; FIPS ignores RFC 5737
#   documentation ranges, so this must be an ordinary global range)
#     .3  stun   coturn, STUN only
#     .10 pub    member C (public: true), when with_c=yes
#     .1  r1 --NAT, 10 ms each way-- 10.1.0.0/24 -- h1 (member A)
#     .2  r2 --NAT, 10 ms each way-- 10.2.0.0/24 -- h2 (member B)
#
# cone NAT = nft masquerade (port-preserving, punchable)
# symmetric = nft masquerade fully-random (new port per destination)
#
# `ip netns exec` and `ip -n` remount /sys, which rootless podman refuses,
# so everything enters namespaces with nsenter.
set -eu
NAT_A=$1 NAT_B=$2 WITH_C=$3 EXPECT=$4 DUR=${5:-45} LOSS=${6:-0} QUIC_MIB=${7:-}
NODE=${NODE:-/target/release/netrig-node}
ns() { n=$1; shift; nsenter --net=/run/netns/"$n" "$@"; }

ip netns add wan
ns wan ip link add br0 type bridge
ns wan ip link set br0 up
ns wan ip link set lo up

link_wan() { # ns ip
  ip netns add "$1"
  ip link add "v-$1" type veth peer name eth0 netns "$1"
  ip link set "v-$1" netns wan
  ns wan ip link set "v-$1" master br0 up
  ns "$1" ip addr add "$2/24" dev eth0
  ns "$1" ip link set eth0 up
  ns "$1" ip link set lo up
}
link_lan() { # router host subnet-prefix
  ip link add lan0 netns "$1" type veth peer name eth0 netns "$2"
  ns "$1" ip addr add "$3.1/24" dev lan0
  ns "$1" ip link set lan0 up
  ns "$2" ip addr add "$3.2/24" dev eth0
  ns "$2" ip link set eth0 up
  ns "$2" ip link set lo up
  ns "$2" ip route add default via "$3.1"
  ns "$1" sysctl -qw net.ipv4.ip_forward=1
}
nat() { # router mode
  flags=""
  [ "$2" = symmetric ] && flags="fully-random"
  ns "$1" nft add table ip nat
  ns "$1" nft add chain ip nat post '{ type nat hook postrouting priority 100 ; }'
  ns "$1" nft add rule ip nat post oifname eth0 masquerade $flags
  ns "$1" tc qdisc add dev eth0 root netem delay 10ms loss "$LOSS%"
}

link_wan stun 37.120.10.3
link_wan pub 37.120.10.10
link_wan r1 37.120.10.1
link_wan r2 37.120.10.2
ip netns add h1
ip netns add h2
link_lan r1 h1 10.1.0
link_lan r2 h2 10.2.0
nat r1 "$NAT_A"
nat r2 "$NAT_B"

mkdir -p /shared /logs && chmod 777 /shared /logs && rm -f /shared/* /logs/*
ns stun turnserver --stun-only -L 37.120.10.3 -p 3478 --no-cli -n \
  --log-file=stdout > /logs/stun.txt 2>&1 &
sleep 1
ns h1 python3 /rig/stunc.py > /dev/null || { echo "FAIL rig: STUN unreachable from behind NAT"; exit 1; }

run() { # ns name peers [public] [quic_to]
  ns "$1" setpriv --reuid 65534 --regid 65534 --clear-groups --inh-caps=-all \
    env FIPS_MTU="${FIPS_MTU:-1320}" QUIC_WAIT_DIRECT="${QUIC_WAIT_DIRECT:-no}" PROBE_SIZES="${PROBE_SIZES:-256,512,768,1000,1100,1150,1200,1250,1300,1400,2000,8000}" PUBLIC="${4:-no}" QUIC_TO="${5:-}" QUIC_MIB="${QUIC_MIB:-16}" CC="${CC:-bbr}" NAME="$2" PEERS="$3" SHARED=/shared \
        STUN=stun:37.120.10.3:3478 DURATION_SECS="$DUR" HOME=/tmp \
        RUST_LOG="${RUST_LOG:-warn}" "$NODE" > "/logs/$2.log" 2>&1 &
}
if [ "$WITH_C" = yes ]; then
  run h1 A B,C no "${QUIC_MIB:+B}"; run h2 B A,C; run pub C A,B yes
else
  run h1 A B no "${QUIC_MIB:+B}"; run h2 B A
fi
sleep $((DUR + 8))

echo "=== A behind $NAT_A NAT, B behind $NAT_B NAT, reachable member: $WITH_C, loss ${LOSS}%${QUIC_MIB:+, QUIC $QUIC_MIB MiB (${CC:-bbr}${QUIC_WAIT_DIRECT:+, wait direct})}, FIPS MTU ${FIPS_MTU:-1320} (expect A<->B: $EXPECT)"
grep -h RESULT /logs/*.log | sort
for f in /logs/A.log /logs/B.log; do
  grep -h '^t=' "$f" | awk '{k=$3; last[k]=$0} END {for (k in last) print "LAST " last[k]}'
done | sort -k3
[ -n "${DUMP:-}" ] && { echo "--- $DUMP log"; grep -v '^t=' "/logs/$DUMP.log" | cut -c1-220 | head -60; }

if [ -n "$QUIC_MIB" ] && ! grep -q "RESULT quic A->B .* ok " /logs/A.log; then
  echo "FAIL ($(grep -h 'RESULT quic' /logs/A.log || echo 'no QUIC result'))"
  exit 1
fi
ab=$(grep -h 'RESULT A->B' /logs/A.log | sed 's/.*=//')
ba=$(grep -h 'RESULT B->A' /logs/B.log | sed 's/.*=//')
if [ "$EXPECT" = never ]; then
  [ "$ab" = never ] && [ "$ba" = never ] && { echo "PASS"; exit 0; }
else
  [ "$ab" != never ] && [ "$ba" != never ] && { echo "PASS"; exit 0; }
fi
echo "FAIL (A->B $ab, B->A $ba)"
exit 1
