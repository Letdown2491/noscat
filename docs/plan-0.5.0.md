# noscat 0.5.0 plan

0.5.0 rebuilds noscat on FIPS (data plane) and Marmot (control plane). It is a deliberate wire break across all three repos (noscat, noscat-desktop, noscat-android), released in lockstep, with no legacy code kept. The decisions behind it are ADRs 0001 to 0006 in `docs/adr/`.

## Target architecture

```
  app protocols: forward, file, chat, clip, presence
        |  QUIC streams (quinn), one connection per peer      ADR 0003
  Streams module
        |  FIPS service datagrams, peer = npub / fd00:: addr
  Dataplane module  (nvpn-fips-* behind our seam)            ADR 0002
        ^  roster -> peer admission                          ADR 0005
        |  signed adverts in/out (External peerfinding)      ADR 0006
  MeshGroup module  (Marmot subset on OpenMLS 0.10)          ADR 0004
        |  kind 445 / 444-in-1059 / 30443 / 10050
     Nostr relays (control plane only)
```

`noscat-core` owns the three modules. `noscat-client` composes them into the app-facing API (API.md). `noscat-ffi` wraps the client for Android. The CLI and desktop app consume the client.

## Phase 0: groundwork (parallel, mostly outward-facing)

- [ ] Open conversations with mmalmi (FIPS fork), jmcorgan (upstream FIPS) and the Marmot/MDK maintainers. Marmot already names FIPS as a future transport.
- [ ] Offer patches to mmalmi:
  - `nvpn-mdns-sd`: move off `socket-pktinfo 0.3` (uses Linux-only `IP_PKTINFO`, breaks FreeBSD). Check that 0.4.x builds on FreeBSD first.
  - `nvpn-fips-core`: non-Linux/macOS fallback for `udp::underlay::bind_socket_to_interface` (about 15 lines; spike version works).
  - `nvpn-fips-core`: put `bluer` and `rustables` behind features so glibc builds do not need libdbus and libclang.
  - Optional: SACK and window scaling for `nvpn-fips-tcp`.
- [ ] Ask MDK about publishing `cgka-engine` to crates.io, and OpenMLS about the 0.10.0 stable timeline.
- [ ] Build the network test rig: two or more network namespaces behind nftables NAT (full cone, symmetric) with `tc netem` loss, delay and reordering. It gates every later phase; 0.4's loss bug got past green container tests.
- [ ] Add a FreeBSD cross build to CI (FreeBSD sysroot plus clang/lld, as in the spike), using a CI-only `[patch]` until upstream ships the fixes.

## Phase 1: first-contact experiment (blocks the Dataplane design)

The one unanswered spike question. With `peerfinding_source: External`, hole punching is coordinated over existing FIPS sessions, not relays.

- [ ] Two devices behind separate NATs, no reachable member: can they connect from adverts delivered out of band?
- [ ] Same, with a third, publicly reachable member (home server): does transit plus punching work, and does traffic move to the direct path afterwards?
- [ ] Symmetric NAT on one side: does it fall back to transit through a member?

Outcome decides whether 0.5 keeps relay-based traversal signaling (kind 21059) as a fallback, requires one reachable member, or both.

## Phase 2: noscat-core rewrite

- [ ] **Dataplane**: FIPS endpoint lifecycle from the device identity; `configured_only` admission; advert export and ingest; network-change handling (`rebind_network_transports`, `refresh_peer_paths`); no other module imports `fips_*`.
- [ ] **Streams**: quinn over a custom socket on one FIPS service port; npub-bound certificates; max UDP payload capped to one unfragmented FIPS payload.
- [ ] **MeshGroup**: Marmot subset on OpenMLS 0.10 (develop on 0.10.0-rc.1, switch to stable on release). Key packages (30443), Welcomes (444 in 1059 to 10050 inbox relays), group events (445 under the exporter key), routing component, admin policy with every device an admin, and a noscat app component for adverts and device names. Reliable commit delivery (relay ACK checks, resend) carries over from 0.4.
- [ ] **MDK interop suite** in CI via a git dev-dependency: MDK creates and we join, we commit and MDK merges, and the reverse. Confirm `cargo publish --dry-run` passes with it.
- [ ] **App protocols over QUIC**: port forward, file transfer (resumable, sha256-verified), chat and clipboard with a delivery acknowledgement, presence from adverts.
- [ ] **Delete**: `tunnel.rs`, `noise.rs`, `stun.rs`, `traversal.rs`, `advert.rs`, and the 0.4 parts of `mesh.rs`.
- [ ] `cargo audit` clean (or each remaining finding explained); `openmls_rust_crypto`'s `test-utils` feature off in production.

## Phase 3: client, API and spec

- [ ] `noscat-client` surface for the new model; API.md rewritten in the same commits (stamp 0.5.0).
- [ ] `docs/nip-noscat.md` rewritten to cover only what is ours: the Marmot mesh profile (our app component, roster-to-admission rule, adverts in the group) and the app stream protocols. FIPS and Marmot are referenced, not restated.
- [ ] AGENTS.md layout sections updated in all three repos.

## Phase 4: clients

- [ ] `noscat-ffi` surface and Kotlin bindings; Android app moved to the new events. Android needs no root for the optional full-VPN mode (`VpnService`), which becomes cheap once mesh addresses exist; still out of scope for 0.5.
- [ ] noscat-desktop moved to the new client; its `src/mesh.rs` glue shrinks or disappears.
- [ ] CLI commands mapped onto the new model (`up`, `forward`, `expose`, `send`, `mesh ...`).

## Phase 5: release

- [ ] All five platforms green in CI, plus the netns NAT and loss suite.
- [ ] Binary size checked after strip and LTO (spike binaries were 20 to 29 MB unstripped, 0.4 is about 10 MB).
- [ ] Lockstep 0.5.0 across noscat, noscat-desktop, noscat-android.

## Open questions

- First contact between NATed devices in External mode (Phase 1).
- `nostr` version skew: the FIPS crates use 0.44, we use 0.45. Two copies get compiled, and events passed to FIPS must be its version's type.
- Key storage at rest: Android Keystore and the desktop keyring are cheap upgrades over today's 0600 hex file. In 0.5 or later?
- Whether to offer an opt-in public mode (relay adverts, dial any npub) in 0.5 or later.

## Spike evidence (2026-11-23)

Throwaway crate, not kept in the repo. Ran as `nobody` with all capabilities dropped:

| Check | Result |
|---|---|
| Adjacency A to B, loopback | 51 ms |
| Non-allowlisted node | kept out, both directions |
| Revocation via `update_peers` | effective before return (0.3 ms) |
| 32 MiB stream over `nvpn-fips-tcp`, clean link | sha256 match, 355 Mbit/s |
| Same, 50 ms RTT, no loss | 8.9 Mbit/s (64 KB window cap) |
| Same, 1% / 3% loss | 1.9 / 0.8 Mbit/s (kernel TCP: 46 / 49) |
| Same, 3% loss, jitter, 10% reorder | 0.6 Mbit/s, sha256 match (kernel TCP: 101) |
| Largest FIPS service datagram delivered | at least 60 KB (FIPS fragments) |
| Builds: Android arm64, Windows, musl, macOS arm64 | pass |
| Build: FreeBSD | pass with the two patches above |
| `nvpn-fips-core` churn | 99 lines (0.4.123 to 0.4.124); about 2,900 lines over a week |
