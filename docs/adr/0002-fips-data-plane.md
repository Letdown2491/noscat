---
status: accepted
date: 2026-11-23
---

# FIPS is the data plane, via mmalmi's nvpn-fips crates behind our own seam

noscat 0.4 ran its own data plane: Noise XK over UDP with stateful nonces, one datagram per Noise message, no retransmission. One lost or reordered datagram made every later one undecryptable, and the pump sent datagrams up to 64 KB that only survive the internet through IP fragmentation. Port forwards worked on a LAN and died on cellular. We replace it with FIPS, the Nostr-native mesh protocol (npub identities, kind 37195 adverts, gift-wrapped hole punching, transit through peers, rekeying, replay windows), consumed as mmalmi's published `nvpn-fips-*` crates and hidden behind a noscat-owned `Dataplane` seam so the implementation can be swapped.

## Considered Options

- **WireGuard (boringtun) carrying IP packets.** Mature and fast, but not Nostr-native: identities, discovery and relaying would all be ours to build. Rejected in favor of staying close to the Nostr ecosystem.
- **Upstream FIPS (jmcorgan/fips).** Independent maintainer and more transports (Tor, Nym, BLE), but daemon-shaped: apps talk to it over a Unix socket, `fips-core` is unpublished, and the native API cannot work on Windows. Fails ADR 0001.
- **mmalmi's fork as published crates (chosen).** Has a library-first `FipsEndpoint` that runs in-process without a TUN, is on crates.io, and claims wire compatibility with upstream. Costs: one publisher, exact `=` pins, fast churn (a week of releases was about 2,900 changed lines).
- **Our own fork.** Deferred. We fork only on a concrete trigger: a needed patch is refused, maintenance stops, or a security fix lags. If it happens it is a short patch stack rebased on mmalmi's work, not a divergent tree.

## Consequences

- Nothing outside the `Dataplane` module imports `fips_*` types.
- Every version bump is reviewed as a diff before it lands; exact pins stay.
- The 2026-11-23 spike confirmed: in-process as `nobody` with all capabilities dropped; `configured_only` peer admission keeps non-members out and revokes removed peers before `update_peers` returns; builds for Android arm64, Windows, musl, macOS; FreeBSD needs two small patches (see the 0.5.0 plan).
- On glibc Linux the crate needs libdbus and libclang headers at build time even with BLE unused (`bluer`, `rustables` are not feature-gated). Static musl builds avoid this; a feature-gating patch is offered upstream.
