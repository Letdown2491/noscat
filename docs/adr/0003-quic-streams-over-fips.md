---
status: accepted
date: 2026-11-23
---

# Reliable streams are QUIC (quinn) over FIPS datagrams

Forwards, file transfer, chat and clipboard all need a reliable byte stream, and FIPS only carries datagrams. We run QUIC (`quinn`, with a custom socket that sends FIPS service datagrams) and address each peer by its FIPS `fd00::/8` address, giving one multiplexed connection per peer with mature loss recovery and congestion control on every platform.

## Considered Options

- **`nvpn-fips-tcp`, the stream layer shipped with the FIPS crates.** Correct under loss (sha256 matched at 3% loss with reordering) but slow by design: no window scaling caps it at about 10 Mbit/s at 50 ms RTT, and without SACK it fell to 0.6 to 1.9 Mbit/s under loss where kernel TCP managed 46 to 101 on the same link. Offering SACK and window scaling upstream is welcome but not something to depend on.
- **Our own reliability layer.** That is what 0.4 had for file transfer, and what we are deleting.
- **A userspace TCP/IP stack (smoltcp) over the FIPS IPv6 shim.** Interesting for a future full-VPN mode, but heavier and with weaker loss recovery than QUIC for app streams.

## Consequences

- QUIC brings its own TLS, so stream payloads are encrypted twice (FIPS session plus QUIC). Accepted as the price of not owning a transport protocol. The QUIC certificate is bound to the device's npub so the second layer authenticates the same identity.
- FIPS fragments service datagrams itself (verified up to 60 KB), so QUIC's 1200-byte minimum is not a problem; quinn's max UDP payload is still capped at one unfragmented FIPS payload to avoid loss amplification.
- The 0.4 file transfer framing, chat/clip tags and their reliability code go away; their replacements are small protocols on QUIC streams.
