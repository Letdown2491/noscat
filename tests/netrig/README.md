# netrig

A fake internet in network namespaces, for testing how noscat devices find
and reach each other through NATs. Rootless: everything runs inside a
`--privileged` rootless podman container, whose privileges stay inside its
own user namespace.

```
tests/netrig/run.sh          # every scenario, non-zero exit on any miss
tests/netrig/run.sh cone symmetric yes connect
DUMP=A RUST_LOG=info tests/netrig/run.sh cone cone yes connect
QUIC_WAIT_DIRECT=yes tests/netrig/run.sh cone cone yes connect 75 3 16
```

Topology, NAT modes and the scenario arguments are documented at the top of
`rig.sh`. Each device runs `node/` (a standalone crate, not part of the
published workspace) as `nobody` with every capability dropped. Devices swap
signed FIPS adverts through a shared directory, standing in for delivery
inside the Marmot group (ADR 0006), and ping each other over FIPS. A can
also send a QUIC stream to B (`node/src/quic.rs`, the ADR 0003 prototype)
and the scenario then requires a sha256-verified transfer.

Current scenarios and what they must show (results recorded in
`docs/plan-0.5.0.md`, Phase 1):

| A | B | reachable member | A<->B |
|---|---|---|---|
| cone | cone | no | never connects |
| cone | cone | yes | connects (punched direct) |
| cone | symmetric | yes | connects (relayed via member) |
| symmetric | symmetric | yes | connects (relayed via member) |
| symmetric | symmetric | yes, 3% loss | 16 MiB over QUIC, relayed |
| cone | cone | yes, 3% loss | 16 MiB over QUIC, after the punch |

When noscat's own data plane lands, the node here should be replaced by the
real `noscat` binary so the rig tests what ships.

Gotchas already paid for:
- FIPS ignores RFC 5737 documentation addresses, so the fake internet uses
  an ordinary global range.
- Use coturn for STUN; a hand-rolled responder that satisfied a Python
  client still timed out against FIPS.
- `ip netns exec` / `ip -n` remount `/sys`, which rootless podman refuses;
  use `nsenter --net=/run/netns/<name>`.
- nftables spells the symmetric-NAT flag `fully-random`.
- FIPS fragments service datagrams only on a direct link. Through a relay
  the limit is the FIPS UDP MTU minus 110 bytes, so FIPS's default 1280
  (limit 1170) silently drops every 1200-byte QUIC packet. The rig runs
  FIPS at 1320, as noscat must.
- Loopback hides this, and loopback's 64 KB MTU also makes kernel TCP
  baselines meaningless. Measure in the rig, not on `lo`.
