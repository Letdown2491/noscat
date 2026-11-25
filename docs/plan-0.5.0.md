# noscat 0.5.0 plan

0.5.0 rebuilds noscat on FIPS (data plane) and Marmot (control plane). It is a deliberate wire break across all three repos (noscat, noscat-desktop, noscat-android), released in lockstep, with no legacy code kept. The decisions behind it are ADRs 0001 to 0007 in `docs/adr/`.

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
- [ ] Ask mmalmi (issues, not patches yet):
  - Fragment service datagrams on transit paths too, or expose the path's datagram limit. Today a relayed path silently drops anything over the UDP MTU minus 110 bytes.
  - Queue the first datagram to a peer while the end-to-end session forms, or expose a session-ready signal (today it is dropped, costing QUIC a 1 s retransmit).
  - An External signaling hook so traversal offers and answers can travel inside the Marmot group, like adverts (Phase 1).
- [ ] Ask MDK about publishing `cgka-engine` to crates.io, and OpenMLS about the 0.10.0 stable timeline.
- [x] Build the network test rig (`tests/netrig/`; NAT scenarios plus QUIC under 3% loss, relayed and punched): two or more network namespaces behind nftables NAT (full cone, symmetric) with `tc netem` loss, delay and reordering. It gates every later phase; 0.4's loss bug got past green container tests.
- [ ] Add a FreeBSD cross build to CI (FreeBSD sysroot plus clang/lld, as in the spike), using a CI-only `[patch]` until upstream ships the fixes.

## Phase 1: first-contact experiment (blocks the Dataplane design)

The one unanswered spike question. With `peerfinding_source: External`, hole punching is coordinated over existing FIPS sessions, not relays.

- [x] Two devices behind separate NATs, no reachable member: can they connect from adverts delivered out of band? **No.** A NATed device advertises `{"addr":"nat"}` (its public address goes into a traversal offer, not the advert), and in External mode offers travel only over existing FIPS sessions, so there is no path for the first offer.
- [x] Same, with a third, publicly reachable member: **yes**, and the two NATed devices punch a direct link (route `direct`, link to the other NAT's public address).
- [x] Symmetric NAT on one or both sides: **yes**, traffic falls back to transit through the reachable member automatically (no direct link; RTT equals the two legs through it).

Results (2026-11-23, rig in network namespaces: two NAT routers with 10 ms each way, a public member, coturn as STUN; first ping at 12 to 14 s, most of which is the experiment registering peers before adverts arrived, so the first dial waits for FIPS's retry timer):

| Scenario | A to B | Path |
|---|---|---|
| cone + cone, no reachable member | never | none |
| cone + cone, reachable member | 14 s | direct (punched) |
| cone + symmetric, reachable member | 14 s | transit via member |
| symmetric + symmetric, reachable member | 14 s | transit via member |

Decision needed for 0.5:
- **Option A: require one reachable member** (a home server, VPS, or any device with public IPv6 or a UPnP/PCP mapping). Fully private and works today. Matches the "your own devices are your relays" model, but a mesh of only phones and laptops behind NAT cannot start.
- **Option B: propose an External signaling hook upstream** (export and ingest traversal offers and answers like adverts do), and carry offers inside the Marmot group. Cone NATs then punch with no reachable member, privately; symmetric NATs still need a member to relay.
- **Option C: allow FIPS's relay peerfinding as an opt-in fallback.** Works without a reachable member, but publishes adverts to public relays, which ADR 0006 rejects by default.

Recommended: A for 0.5.0, B offered upstream in parallel, C never on by default.

Implementation notes from the rig:
- Members are registered before their adverts arrive, so FIPS's first dial fails with "no transport" and waits about 10 s for a retry. The Dataplane now calls `refresh_peer_paths` when a member's advert is new or changed (first contact 0.6 s in the rig).
- A reachable member must set `public: true`; FIPS learns the address by STUN (or `external_addr`). FIPS ignores documentation-range addresses (RFC 5737), so test rigs must use ordinary global ranges.
- The rig lives in `tests/netrig/` (`tests/netrig/run.sh` runs every scenario and fails on any miss). It is the network test gate from Phase 0 on; swap its experiment node for the real `noscat` binary once the data plane lands.

## Phase 2: noscat-core rewrite

- [x] **Dataplane** (`crates/noscat-core/src/dataplane.rs`): FIPS endpoint lifecycle from the device identity; `configured_only` admission; advert export and ingest; network-change handling (`rebind_network_transports`, `refresh_peer_paths`); no other module imports `fips_*`. Also: LAN discovery on by default (FIPS drops private addresses from adverts), optional static addresses per member, adverts accepted only from members, a reachable device must use a fixed port.
- [x] **Streams** (`crates/noscat-core/src/streams.rs`): quinn over a custom socket on one FIPS service port (prototype in ADR 0003 works: sync `try_send` via `send_datagram(..).now_or_never()`, receive pump into a channel); BBR; a probe port so `connect` waits for a real round trip instead of a warm-up guess; identity from FIPS with a certificate name check against mis-routing (ADR 0003); `retain_members` closes removed members' connections, including handshakes in flight, before the data plane drops them; quinn at 1200 with PMTUD off; FIPS UDP MTU set to 1320 (relayed paths carry at most MTU minus 110 bytes, and FIPS's default 1280 breaks relayed QUIC; see ADR 0003).
- [x] **MeshGroup** (`crates/noscat-core/src/marmot/`): Marmot subset on OpenMLS 0.10.0-rc.1 (switch to stable on release). Key packages (30443, last resort, 30 days), Welcomes (444 in 1059 to 10050 inbox relays, sent only after the commit is acknowledged), group events (445 under the exporter key, fresh outer key per event), identity proofs (0x8009), routing (0x8004), lifecycle (0x800c), admin policy with every device an admin, and the non-required `noscat.mesh.v1` component (0xf3a0) for the mesh name. Adverts and device names travel as app events (kind 21195). Leaving: an admin steps down, then sends SelfRemove for another member to commit. Concurrent commits converge by Marmot branch order with snapshot rollback inside a 5-commit horizon (ADR 0007). A pure state machine; `device.rs` does the relay I/O.
- [x] **MDK interop suite** (`tests/mdk-interop/run.sh`): a standalone harness, not a dev-dependency, so the published crates never see MDK. It builds MDK's `wn` CLI at a pinned commit and runs White Noise invites noscat and noscat invites White Noise over one relay, with kind 9 messages both ways. Both scenarios pass. What it found: the key package `app_components` tag must list only ids from 0x8000 (MDK compares it exactly against the leaf), the leaf must not list 0x0002, and White Noise requires encrypted media v2 (0x800b) in every new group, so noscat advertises it (it never sends media and leaves the policy alone).
- [x] **App protocols over QUIC** (`apps.rs`): port forward, file transfer (resumable, sha256-verified), chat and clipboard with a delivery acknowledgement. Presence comes from in-group adverts (`Device::members`).
- [x] **Device runtime** (`device.rs`): relays, group, data plane and streams kept in step; publish before apply; roster to `retain_members` then `set_members`; adverts every 2 minutes and on every roster change; group subscription resumes from the last processed event after a restart. End-to-end tests against an in-process relay (`tests/device.rs`).
- [x] Switch `tests/netrig` from its experiment node to a node built on Dataplane and Streams. All six scenarios pass on the shipping modules; first contact 0.6 to 0.7 s (was 11 to 14 s) because the Dataplane dials a member as soon as its first or changed advert arrives. Only on change: adverts are re-signed on every export, and refreshing paths on each one rekeyed live sessions often enough to stall QUIC.
- [x] **Delete**: `tunnel.rs`, `noise.rs`, `stun.rs`, `traversal.rs`, `advert.rs`, `mesh.rs`; snow, curve25519-dalek, rusqlite and the OpenMLS sqlite storage are gone from the workspace.
- [x] `cargo audit`: no vulnerabilities. Remaining warnings are upstream: heapless 0.8 (unsound) via nostr's faster-hex; lru 0.16 (unsound) and nostr-relay-pool 0.44 (unmaintained) via nvpn-fips-core's nostr-sdk 0.44; nostr-relay-builder 0.44 is a dev-dependency only. `openmls_rust_crypto`'s `test-utils` feature is off.

## Phase 3: client, API and spec

- [x] `noscat-client` surface for the new model; API.md rewritten in the same commits (stamp 0.5.0). One `Client` per device on the device runtime; mesh operations (`create_mesh`, `invite`, `join`, `remove`, `leave`, `members`) next to the 0.4 app operations; the 0.4 events kept (minus `Incoming`) plus mesh events. `tests/client.rs` runs two clients end to end. The FFI section of API.md follows in phase 4.
- [x] `docs/nip-noscat.md` rewritten to cover only what is ours: the Marmot mesh profile (our app component, roster-to-admission rule, adverts in the group) and the app stream protocols. FIPS and Marmot are referenced, not restated.
- [x] AGENTS.md layout sections updated in all three repos. Done here (and CONTEXT.md gained Reachable device and Default service); the app repos' AGENTS.md were rewritten with their 0.5 glue in phase 4.

## Phase 4: clients

- [x] `noscat-ffi` surface and Kotlin bindings; Android app moved to the new events (debug APK builds and runs on a Pixel 9a; device dir `filesDir/device`, `members.json`; ten minute presence; `JoinRequest` only logged, inviting from the phone needs UI). FFI done (same function names; `mesh_*` use the running client; `MeshMember.admin/online/this_device` replace `is_owner`; new mesh events and `JoinRequest`). Android needs no root for the optional full-VPN mode (`VpnService`), which becomes cheap once mesh addresses exist; still out of scope for 0.5.
- [x] `noscat up --accept-joins` invites every device that sends a join request (the 0.4 `--auto-accept-joins` workflow); off by default, and the banner says anyone who knows the npub can ask.
- [x] noscat-desktop moved to the new client; its `src/mesh.rs` glue shrinks or disappears (`mesh.rs` is a thin layer over `Client`; `[patch.crates-io]` points at this repo's `main` until release; device dir `device/`, `members.json`; dev image gains dbus-devel, clang-devel and the Vulkan/Wayland runtime, and `scripts/run.sh` runs the app in it, since the host is immutable). Neither app can create a mesh or approve a join request yet: both need new UI, which the user chose to keep unchanged for now, so a CLI device creates the mesh and invites.
- [x] CLI commands mapped onto the new model: `id`, `up`, `expose`, `serve`, `pipe`, `send`, `chat`, `clip`, `forward`, `mesh create|invite|join|remove|leave|members|qr`. One process runs a device (directory lock); other commands go through its loopback control channel or start the device themselves. State moved to the platform data directory. `tests/cli.rs` drives the binary end to end.
- [x] Join requests (kind 21196 gift wrap to the scanned device) so the inviting side gets a prompt instead of typing an npub; restores 0.4's approve-on-request flow without an owner.
- [x] Devices send their advert at start and answer a returning member's advert, so a just-started device (a one-shot CLI command) reaches members in seconds.
- [x] Dropping the last `Client` stops the device and frees its directory. Background tasks held the shared state, which owned their runtime, so no client ever dropped; the apps' join helper then kept the directory and the app's own client failed with `Busy`. Found on the phone; `tests/client.rs` covers it.
- [x] First real-device test (2026-11-24): CLI on Linux plus the Android app joined one mesh over the LAN; chat from the CLI delivered to the phone.
- [x] Both apps split Disconnect (go offline, stay a member; Android remembers it across restarts) from Forget mesh (leave, then delete the device dir and cached roster; nothing is deleted if leaving fails). Before, Android's disconnect only dropped its pointer to the device, which stayed a member. Android now closes clients with `close()` instead of leaving them to the garbage collector, so a restart (rename) no longer depends on the old client being collected first. Disconnect, restart and reconnect verified on the Pixel 9a; Forget left for the user to try.
- [x] Fixes from the user's testing (2026-11-24): the desktop's default build is Wayland only, as its `x11` feature comment always intended (X11 needs libxkbcommon-x11, which the immutable host lacks), so `target/release/noscat-desktop` runs on the host; `noscat up` hides routine startup logs unless `--verbose` (openmls errors for stale backlog adverts, the kernel-capped UDP buffer, a member with no address yet and its retries); the CLI tests no longer share temp directories when run in parallel. Joining failed about half the time with "no relay accepted the event: ... have newer event": a device not in a mesh publishes a key package at start and `join` publishes another at once, both stamped the same second, and relays keep one per slot. Key packages are now stamped strictly later than the device's previous one (kept in the mesh state); a unit test covers it. `noscat up` then took two minutes to show its QR: the only default relay (relay.primal.net) acknowledged events 25 to 35 seconds late, and every start blocked on three timed-out, re-sent publishes per event. Relays reworked: three defaults (relay.snort.social, relay.ditto.pub, nostr.mom; 14 candidates tested for every noscat kind, a real join each, and reachability from the phone on cellular), each relay gets nostr-sdk's lasting connection task (a relay down at start was never retried before), publishes go to every relay at once and return on the first acceptance without re-sending to slow relays, the start publishes in the background, and relay lists are republished only on change or weekly. Banner in 0.3 s, a join in 2 s over the defaults; two client tests cover a dead relay and a relay that comes up late (both fail on the old code). Existing meshes keep relay.primal.net as a group relay, used alongside the defaults.
- [x] Transfers carry an id from a new `TransferStarted` to their outcome, and receives report progress like sends, so both apps show a progress bar either way and keep a Received / Sent history (the last 100 sends; Forget mesh clears it).
- [x] Renames reach members within seconds: `Device::set_name` / `Client::set_device_name` send an advert with the new name at once (before, a running device kept its old name until restarted). The CLI gains `noscat name [new name]` (saved in the device dir) and a `name` command in the `up` chat that saves it the same way; both apps call it from Settings.
- [x] Routine FIPS path warnings (a failed direct-path upgrade, a stale direct path, congestion marks) are hidden by default like the startup ones; `--verbose` shows them.
- [x] Adverts carry `["reachable", "1"]` from a device run reachable, members expose `reachable`, and `mesh members` marks them and notes when none is. The apps show no banner for it: the presence dot is three-state (green connected, from `Member.connected`, a direct link or live connection that `up` keeps to every online member; amber online but unreachable; grey or red offline). `noscat service install|uninstall|status` runs `up` in the background (systemd user unit with lingering on Linux, launchd agent on macOS), and the packages ship a plain user unit, `/usr/lib/systemd/user/noscat.service`.
- [x] Both apps approve join requests (before, only the CLI could invite), notify (chat, files in the background, join requests), keep chat history across restarts, and name devices instead of npubs in pop-ups.
- [x] Secret files sealed at rest: `set_storage_key` (core, client, FFI) seals `identity.nsec` and `mesh-state.json` with XChaCha20-Poly1305 under a key the apps keep in the Android Keystore or the desktop keyring; plain files migrate; a sealed file without the key refuses to start instead of being replaced. The CLI stays plain. Android backup and device transfer are off.

## Phase 5: release

- [ ] All five platforms green in CI, plus the netns NAT and loss suite. **FreeBSD blocks on upstream draft 01** (`nvpn-mdns-sd` still uses `socket-pktinfo` 0.3): a workspace `[patch]` would fix CI but not `cargo install noscat`, so the release needs the upstream fix published. glibc CI runners also need libdbus and libclang until draft 02 lands.
- [ ] Binary size checked after strip and LTO (spike binaries were 20 to 29 MB unstripped, 0.4 is about 10 MB).
- [ ] Lockstep 0.5.0 across noscat, noscat-desktop, noscat-android: publish the crates, drop the desktop's `[patch.crates-io]`, point `scripts/build-native.sh` at the published 0.5.0.
- [ ] Android release build: `scripts/build-native.sh` builds the Rust library unoptimized (stripped debug profile), and the Gradle project has no release signing.
- [ ] Packaging refresh: `packaging/PKGBUILD` and `.SRCINFO` are still at 0.1.1 (and need `dbus` plus build-time `clang`), the winget manifests are the 0.1.1 submission. The man page, nfpm, Homebrew and flake descriptions are already 0.5.
- [ ] Desktop release ships two Linux binaries: `noscat-desktop` (Wayland only, the default build) and `noscat-desktop-x11` (`--features x11`, needs libxkbcommon-x11 at run time, which a Wayland-only machine may lack).
- [ ] Remove the "not released yet" notes from README.md, INSTALL.md and AGENTS.md.

## Decisions (2026-11-24)

- **Every mesh needs one reachable member** in 0.5.0 (home server, VPS, port forward, or public IPv6). Setup flows say so when no member is reachable. The upstream signaling hook (draft 05) may lift this for cone NATs later.
- **MeshGroup builds on OpenMLS 0.10.0-rc.1**; switch to 0.10 stable when released.
- **Fresh start from 0.4**: no 0.4 state is read, including identities. 0.5 keeps its state in a new location so 0.4 files are left alone.
- **Git**: work happened on `v0.5.0` branches and moved to each repo's default branch (`main`, `master` for noscat-android) on 2026-11-24; all work continues there. No crates.io publishing and no tags until release. The apps build against noscat `main` until then.

## Open questions

- `nostr` version skew: the FIPS crates use 0.44, we use 0.45. Two copies get compiled; adverts cross the Dataplane seam as JSON.
- Whether to offer an opt-in public mode (relay adverts, dial any npub): not in 0.5.0.

## Spike evidence (2026-11-23)

Throwaway crate, not kept in the repo. (The kernel TCP baselines first recorded here were invalid, see ADR 0003, and have been removed.) Ran as `nobody` with all capabilities dropped:

| Check | Result |
|---|---|
| Adjacency A to B, loopback | 51 ms |
| Non-allowlisted node | kept out, both directions |
| Revocation via `update_peers` | effective before return (0.3 ms) |
| 32 MiB stream over `nvpn-fips-tcp`, clean link | sha256 match, 355 Mbit/s |
| Same, 50 ms RTT, no loss | 8.9 Mbit/s (64 KB window cap) |
| Same, 1% / 3% loss | 1.9 / 0.8 Mbit/s |
| Same, 3% loss, jitter, 10% reorder | 0.6 Mbit/s, sha256 match |
| QUIC (quinn, BBR) over FIPS datagrams: 50 ms RTT, 0 / 1 / 3% loss | 166 / 154 / 156 Mbit/s, sha256 match (full table in ADR 0003) |
| Largest relayed FIPS service datagram | FIPS UDP MTU minus 110 (1170 at the default 1280); direct links fragment |
| QUIC (BBR) in the NAT rig, relayed, 3% loss | 98 to 160 Mbit/s, sha256 match |
| QUIC handshake, cold / after a warm-up datagram | 1003 ms / 2 ms (FIPS drops the first datagram while the session forms) |
| Largest FIPS service datagram delivered | at least 60 KB (FIPS fragments) |
| Builds: Android arm64, Windows, musl, macOS arm64 | pass |
| Build: FreeBSD | pass with the two patches above |
| `nvpn-fips-core` churn | 99 lines (0.4.123 to 0.4.124); about 2,900 lines over a week |
