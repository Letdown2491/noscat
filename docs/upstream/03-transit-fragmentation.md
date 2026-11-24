<!-- Note to you: bug report with measurements from tests/netrig. Text to send
is below the line. -->

---

**Title:** Service datagrams over a transit (relayed) path are silently dropped above UDP MTU minus 110 bytes

Service datagrams sent with `FipsEndpoint::send_datagram` are fragmented and
reassembled when the two endpoints have a direct link, but not when the
session runs through a transit node. On a relayed path anything larger than
the UDP transport MTU minus 110 bytes is dropped, and `send_datagram` still
returns `Ok(())`.

### Measurements (0.4.124)

Three nodes in network namespaces: A and B behind NAT routers, C public. A
and B list each other and C as peers; A and B behind symmetric NATs (so
A to B goes through C). A sends echo probes of increasing size on a service
port; B echoes them.

| UDP `mtu` | Largest datagram A to B (via C) | A to C (direct) |
|---|---|---|
| 1280 (default) | 1170 | 8000+ (largest probed) |
| 1472 | 1362 | 8000+ |

The threshold is exactly MTU minus 110 at both settings (probed in 2-byte
steps). Once A and B (cone NATs) punch a direct link, A to B also carries
8000-byte datagrams.

### Why it matters

QUIC requires every path to carry 1200-byte UDP payloads and pads client
Initials to at least 1200 bytes (RFC 9000, section 14), so with the default
MTU a QUIC connection over a relayed path fails: the client's Initials never
arrive and the handshake times out, with no
error anywhere. We run quinn over `send_datagram` for reliable streams; it
works on direct links and fails on every relayed one until the MTU is raised.
We now set `mtu: Some(1320)` (relayed limit 1210) as a workaround.

### What would help (any of)

1. Fragment service datagrams on transit paths too, like on direct links.
2. Or return an error from `send_datagram` when the payload exceeds what the
   current path can carry, instead of dropping it silently.
3. Or expose the current path's datagram limit for a peer, so callers can size
   packets (QUIC can then use it for its max UDP payload).

From a quick read, fragmentation looks like it lives in
`dataplane/direct_transport.rs` only, but I may have missed a transit-side
mechanism or a config switch. Happy to test patches with the same rig.
