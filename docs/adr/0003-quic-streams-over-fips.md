---
status: accepted
date: 2026-11-23
---

# Reliable streams are QUIC (quinn) over FIPS datagrams

Forwards, file transfer, chat and clipboard all need a reliable byte stream, and FIPS only carries datagrams. We run QUIC (`quinn`, with a custom socket that sends FIPS service datagrams) and address each peer by its FIPS `fd00::/8` address, giving one multiplexed connection per peer with mature loss recovery and congestion control on every platform.

## Considered Options

- **`nvpn-fips-tcp`, the stream layer shipped with the FIPS crates.** Correct under loss (sha256 matched at 3% loss with reordering) but slow by design: no window scaling caps it at about 10 Mbit/s at 50 ms RTT, and without SACK it fell to 0.6 to 1.9 Mbit/s under loss. The QUIC prototype on the same links did 2x to 3.5x better with Cubic and about 20x to 190x better with BBR (table below). Offering SACK and window scaling upstream is welcome but not something to depend on.
- **Our own reliability layer.** That is what 0.4 had for file transfer, and what we are deleting.
- **A userspace TCP/IP stack (smoltcp) over the FIPS IPv6 shim.** Interesting for a future full-VPN mode, but heavier and with weaker loss recovery than QUIC for app streams.

## Consequences

- QUIC brings its own TLS, so stream payloads are encrypted twice (FIPS session plus QUIC). Accepted as the price of not owning a transport protocol. The QUIC certificate is bound to the device's npub so the second layer authenticates the same identity.
- FIPS fragments service datagrams only on a direct link (verified up to 60 KB on loopback, 8 KB in the rig). Through a relay it does not: the limit is the FIPS UDP MTU minus 110 bytes (measured: 1170 at FIPS's default 1280, 1362 at 1472). QUIC never sends less than 1200, so at the default MTU every relayed QUIC connection silently fails. noscat therefore sets the FIPS UDP MTU to 1320 (relayed limit 1210; outer packet 1348 bytes over IPv4, 1368 over IPv6, which fits behind PPPoE and most tunnels), runs quinn at exactly 1200 with path MTU discovery off, and asks upstream for transit fragmentation or a path MTU signal.
- Congestion control is BBR. Under random loss, Cubic on 1200-byte packets is bounded by the loss rate (5.8 Mbit/s at 1%, 2.8 at 3%), while BBR held about 155 Mbit/s up to 3% loss. quinn marks BBR experimental, so the netrig loss suite must cover it, and Cubic stays one config switch away.
- FIPS drops the first datagram to a peer while it sets up the end-to-end session, which costs QUIC a 1 s Initial retransmit. The Streams module sends a warm-up datagram and waits for the session before connecting (handshake 1003 ms cold, 2 ms warm). Ask upstream whether FIPS can queue instead of drop, or expose a session-ready signal.
- The 0.4 file transfer framing, chat/clip tags and their reliability code go away; their replacements are small protocols on QUIC streams.

## Prototype measurements (2026-11-23)

quinn 0.11 over FIPS service datagrams, two in-process nodes on loopback under `tc netem`, MTU 1200 with path MTU discovery off, 16 MiB bidirectional stream, sha256 matched in every run.

| Link | nvpn-fips-tcp | QUIC, Cubic | QUIC, BBR |
|---|---|---|---|
| clean loopback | 355 Mbit/s | 707 | |
| 50 ms RTT | 8.9 | 13.1 | 166 |
| 50 ms RTT, 1% loss | 1.9 | 5.8 | 154 |
| 50 ms RTT, 3% loss | 0.8 | 2.8 | 156 |
| 50 ms RTT, 10 ms jitter, 3% loss, 10% reorder | 0.6 | 2.0 | |

Then in the netrig NAT rig (two NAT routers adding 10 ms each way, so about 40 ms RTT through the member, random loss on each router's WAN egress, FIPS MTU 1320 or 1472, BBR; the `tests/netrig/run.sh` gate repeats the 3% rows):

| Path | 0% loss | 1% loss | 3% loss |
|---|---|---|---|
| Relayed through the reachable member | 124 Mbit/s | 185 to 215 | 98 to 160 |
| Across both NATs before the punch completed (so also relayed) | 185 | 177 | 125 |
| Punched direct link between two cone NATs | | | 173 |

All 16 MiB transfers verified; handshakes 22 to 44 ms because the FIPS session was already up from pings. These are single runs, so the spread is noise, not a trend.

An earlier comparison with kernel TCP (46 to 101 Mbit/s under loss) was invalid: loopback's 64 KB MTU let kernel TCP send 64 KB segments, so it saw a fraction of the per-packet loss. Treat any loopback kernel TCP baseline as meaningless unless `lo` is set to a 1500 MTU first.
