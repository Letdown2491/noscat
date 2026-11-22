# FIPS (Free Internetworking Peering System) — Research Notes

Repo: https://github.com/jmcorgan/fips (branch `master`, state: `v0.6.0-dev`).
All citations are to files on `raw.githubusercontent.com/jmcorgan/fips/master/...` unless otherwise noted. Research date: 2026-11-21.

---

## 1. Architecture

### Three protocol layers, clean boundaries

- Claim: FIPS is organized in three protocol layers with "clean service boundaries"; no layer depends on the specifics of the layers above or below it — transports know nothing about sessions, routing knows nothing about application addressing, applications know nothing about which media carry their traffic.
  Source: `docs/design/fips-architecture.md` (https://raw.githubusercontent.com/jmcorgan/fips/master/docs/design/fips-architecture.md)
- Layers:
  - **Transport layer** — datagram delivery + MTU reporting over UDP, TCP, raw Ethernet, Tor, Nym, BLE; "knows nothing about FIPS identities, routing, or encryption." Spec: `docs/design/fips-transport-layer.md`.
  - **FIPS Mesh Protocol (FMP)** — peer connections, Noise IK authentication, hop-by-hop link encryption, and mesh self-organization (spanning-tree announcements, bloom filters, forwarding of transit traffic).
  - **FIPS Session Protocol (FSP)** — end-to-end Noise XK authenticated encryption between endpoints, session lifecycle, coordinate caching, WireGuard-style index-based session dispatch for O(1) demux.
  - Sources: `docs/design/fips-architecture.md`; layer specs `docs/design/fips-mesh-layer.md`, `docs/design/fips-session-layer.md`.
- Claim: Above FSP sit application services dispatched by FSP **port number**: the IPv6 TUN adapter is itself just a service on **port 256**; the native datagram API is the other top service, addressing peers directly by npub.
  Source: `docs/design/fips-architecture.md` ("Node Architecture").

### Mesh routing: spanning tree + bloom filters

- Claim: A spanning tree forms through distributed parent selection, giving every node a coordinate without global topology knowledge; bloom filters propagate through gossip so each node learns which peers can reach which destinations; routing decisions are made locally per hop using immediate peers and cached coordinates.
  Source: `docs/design/fips-concepts.md` (https://raw.githubusercontent.com/jmcorgan/fips/master/docs/design/fips-concepts.md)
- Claim: Forwarding combines spanning-tree coordinates with peer bloom filters to pick a next hop, falling back to greedy tree routing when bloom filters have not converged; three explicit error signals (`CoordsRequired`, `PathBroken`, `MtuExceeded`) drive recovery.
  Source: `docs/design/fips-architecture.md` ("Routing and Mesh Operation"); details in `docs/design/fips-mesh-operation.md`, `docs/design/fips-spanning-tree.md`, `docs/design/fips-bloom-filters.md`.

### Two-layer encryption

- Claim: Independent encryption at two layers — Noise **IK** hop-by-hop (FMP link, because the outbound side knows the peer's npub from config and the inbound side learns the initiator from msg1) and Noise **XK** end-to-end (FSP session; XK delays initiator identity disclosure until msg3 for traffic crossing untrusted intermediates). Both layers always apply, even between adjacent nodes; a packet is encrypted twice end to end. Cipher suite: `Noise_IK_secp256k1_ChaChaPoly_SHA256` and `Noise_XK_secp256k1_ChaChaPoly_SHA256`, both with a documented deviation (empty associated data in the handshake AEAD instead of the handshake hash — transcript binding is deliberately not a property).
  Sources: `docs/design/fips-architecture.md` ("Two-Layer Encryption"); `docs/reference/security.md` ("Cryptographic Primitives", "Deviation: Empty Associated Data").
- Claim: Periodic hitless rekey at both layers (defaults: every 120 s or 65,536 messages; old keys retained 10 s link drain / up to 120 s session drain); 8192-entry sliding replay window at both layers.
  Sources: `docs/reference/security.md` ("Rekey Defaults", "Replay Window").

### Composability of transports

- Claim: Transports implement one small datagram interface (send, receive, report MTU) and all feed into a single FMP layer; multi-transport nodes bridge between networks transparently; a packet may traverse WiFi→UDP/IP→Tor on one path.
  Source: `docs/design/fips-architecture.md` ("Transport Abstraction").

### Could an external tool use FIPS purely as a data plane / library?

- **Partially, yes — but as a daemon client, not an embeddable mesh engine.**
  - Claim: The native datagram API exists precisely so applications skip IP emulation and address peers by public key; the client is a module of the `fips` library (`fips::native::client`), blocking and std-only, and a program links the crate (`fips = { package = "fips-mesh", git = "..." }`).
    Source: `docs/how-to/use-the-native-datagram-api.md` (https://raw.githubusercontent.com/jmcorgan/fips/master/docs/how-to/use-the-native-datagram-api.md)
  - Claim: But the client is a **local Unix-socket client of a running `fips` daemon** — you talk to `/run/fips/api.sock` and get handed file descriptors; the mesh routing, Noise layers, discovery, and transports all live in the daemon process. There is no documented "run the mesh inside your own process" library API on desktop platforms (the Android embedding — a compile-gated library surface where the host app owns the TUN — is the one in-process mode, and it is daemon-shaped too).
    Sources: `docs/reference/native-api.md`; README "Building from source" (Android paragraph).
  - Claim: The workspace is two crates: root `fips-mesh` (lib name `fips`, plus 4 binaries) and `fips-core` (path dependency, `publish = false`), the latter holding the noise/proto/path/cache machinery and buildable bare-metal (`no_std`/alloc, tested via `testing/build-core-baremetal.sh`). `fips-core` is unpublished and its API is internal, not a public embedding contract.
    Sources: `Cargo.toml` ([lib], [workspace], [dependencies]); `core/Cargo.toml` (https://raw.githubusercontent.com/jmcorgan/fips/master/core/Cargo.toml).

---

## 2. Native datagram API

### Surface

- Claim: A local program sends/receives datagrams addressed by **x-only secp256k1 public key + FSP port** (`npub:port`), no IPv6 emulation, no TUN in the path. Types: `FipsAddr`, `FipsStream`, `FipsListener`, `ToFipsAddr`, in `fips::native::client` — a Berkeley-socket-shaped mapping where `connect`/`bind` each return a real file descriptor (Unix `SOCK_SEQPACKET` on Linux/FreeBSD, `SOCK_DGRAM` on macOS) handed over `SCM_RIGHTS` from the daemon; afterwards it is ordinary `send`/`recv`/`poll`/`epoll`/`set_nonblocking`/`setsockopt` on that fd.
  Source: `docs/reference/native-api.md` (https://raw.githubusercontent.com/jmcorgan/fips/master/docs/reference/native-api.md)
- Claim: The wire-level surface is a JSON line protocol on a Unix stream socket (`{"command":"connect","params":{...}}` → `{"status":"ok"|"error","data":{"errno":...}}`), documented for writing clients in other languages (`docs/how-to/write-a-native-api-client.md`); every command returns `io::Result` (no bespoke error type), errnos matched via `raw_os_error()` against `libc` constants.
  Sources: `docs/reference/native-api.md` ("The line protocol", "Errors").
- Claim: Port tiers — 0–255 protocol (refused), 256–1023 FIPS standard services (refused; 256 = IPv6 shim), 1024–65535 application; port 0 = ephemeral (RFC 6056 Algorithm 1 random start).
  Source: `docs/reference/native-api.md` ("Ports").

### Stability and platform support

- Claim: **Experimental, off by default** (`node.native_api.enabled: false`), "not a stable API surface, not a reliability layer, and not the v2 external process API. No compatibility promise is made… may change or be withdrawn in any release." Built on **Linux, FreeBSD and macOS only**; Windows cannot carry it (no `SCM_RIGHTS`).
  Sources: `docs/reference/native-api.md`; `docs/reference/security.md` ("Native Datagram API"); `docs/how-to/use-the-native-datagram-api.md`; README feature table.
- Claim: macOS is exercised by unit tests only — no end-to-end suite runs a daemon + client pair there ("a gap in testing, not a known defect," per the how-to).
  Source: `docs/how-to/use-the-native-datagram-api.md` ("The macOS build is exercised less…").

### How a netcat-style tool (no TUN, no root, port forwarding, stdio piping) would be built

- Claim: The intended shape is exactly this: a userspace program links the `fips` crate (or speaks the line protocol from any language), calls `FipsStream::connect(("npub1…", port))` / `FipsListener::bind(port)`, gets real fds, and pipes stdio to them; no TUN, no root, no IPv6. The `examples/native-echo.rs` worked example does precisely this. A port-forwarding tool could `bind` a FIPS port and bridge accepted flows to local TCP sockets, or vice versa, using `poll`/`epoll` over the fds.
  Sources: `docs/how-to/use-the-native-datagram-api.md` (Steps 2–5, examples); `docs/reference/native-api.md`.
- Caveats a such a tool inherits (all from `docs/reference/native-api.md` / the how-to):
  - Needs the **daemon running** with the API enabled, and the invoking user in group `fips` (mode 0770 socket) — group membership is "equivalent to possession of the node's identity" (any member can send as the node). So "no root" holds, but `fips` group access is key-level trust.
  - Datagram-unreliable: no ack, no retransmission, no ordering, no flow control; five silent drop paths; no framing (1 send = 1 datagram).
  - No half-close: nothing peer-driven ends a flow; `Ok(0)` is an empty datagram, not EOF; the tool must impose its own deadlines and message semantics.
  - Payload ceiling = transport MTU minus FIPS encapsulation (`max_payload()` snapshot per flow).
  - Node-wide caps: `max_flows` 256 (peer share = ¼), `pending_per_flow` 16, `backlog` 16; all flows die with a daemon restart.
- Claim: There is no stream/TCP-like reliable mode on this API — reliable delivery is a documented non-goal of the mesh layer ("retransmission and ordering are left to applications or higher-layer protocols").
  Source: `docs/design/fips-concepts.md` ("Non-goals").

### How immature is it really?

- Very, by its own account: disabled by default, "may be withdrawn in any release," no compat promise, Windows/macos-E2E untested, subtle platform differences (Linux `EPIPE` shadowing a trailing zero-length datagram; macOS kernel descriptor-collection workaround where the daemon keeps a copy until first send). But the *documentation* of it is unusually deep and precise (an errno table, drop-cause counter taxonomy, line-protocol spec for foreign-language clients) — the immaturity is in the stability contract, not the spec coverage.
  Sources: `docs/reference/native-api.md`, `docs/how-to/use-the-native-datagram-api.md`, `docs/reference/security.md` ("Native Datagram API").

---

## 3. Nostr integration

There is a dedicated events catalog: **`docs/reference/nostr-events.md`** (https://raw.githubusercontent.com/jmcorgan/fips/master/docs/reference/nostr-events.md).

- Claim: FIPS uses exactly three Nostr event kinds:
  | Kind | Name | Encryption | Storage | Purpose |
  |---|---|---|---|---|
  | **37195** | Overlay advert | None (signed only) | Parameterized replaceable (30000–39999 range; `d` tag fixed `fips-overlay-v1`) | Publish reachable transport endpoints (JSON `OverlayAdvert`: `endpoints[]` of `{transport: udp|tcp|tor, addr}`, optional `signalRelays[]`, `stunServers[]`) with NIP-40 `expiration` (default TTL 3600 s) |
  | **21059** | Traversal signaling | **NIP-44 inside NIP-59 gift wrap** | Ephemeral | Carry `TraversalOffer`/`TraversalAnswer` for STUN-assisted UDP hole punching |
  | **10050** | NIP-17 inbox relay list | None (signed only) | Replaceable | Tell dialers where to publish gift-wrapped offers (emitted with nonstandard `r` tags, published on startup + every 24 h) |
  Source: `docs/reference/nostr-events.md`; design rationale in `docs/design/fips-nostr-discovery.md` (https://raw.githubusercontent.com/jmcorgan/fips/master/docs/design/fips-nostr-discovery.md).
- Gift wrapping: yes. Claim: kind 21059 is the standard NIP-59 envelope — rumor (JSON offer/answer) → kind-13 seal NIP-44-encrypted to the recipient and signed by the sender's FIPS identity key → gift wrap NIP-44-encrypted to the recipient under an **ephemeral one-time key**, so relays do not see the sender. Adverts (37195) and inbox lists (10050) are public, signed-only.
  Source: `docs/reference/nostr-events.md` ("Encryption envelope").
- Traversal payloads: `TraversalOffer` carries `sessionId`, `nonce`, `senderNpub`/`recipientNpub`, `issuedAt`/`expiresAt` (TTL default 120 s), `reflexiveAddress` (STUN), optional `localAddresses` (opt-in `share_local_candidates`), `stunServer`; `TraversalAnswer` echoes and adds `accepted`, `inReplyTo`, `PunchHint {startAtMs, intervalMs, durationMs}`, `reason`. Probes: 24-byte `NPTC`/`NPTA` magic + sequence + first 16 bytes of `SHA256(sessionId)`; candidate priority reflexive↔reflexive, LAN↔LAN, mixed; the punched socket becomes a normal FMP UDP transport (`adopt_established_traversal()`).
  Sources: `docs/reference/nostr-events.md`; `docs/design/fips-nostr-discovery.md` (Phases 3–5).
- Relays: none hardcoded in the protocol — Claim: relay lists are operator config (`node.rendezvous.nostr.advert_relays`, `dm_relays`); "Default relay and STUN-server lists ship in the config; both are optional overrides." Docs' worked examples use `wss://relay.damus.io` and `wss://nos.lol`; the advert's `signalRelays` and the peer's kind 10050 list are merged into signaling targets. STUN default example: `stun:stun.l.google.com:19302`.
  Sources: `docs/design/fips-nostr-discovery.md`; `docs/reference/nostr-events.md`.
- Claim: The whole feature is runtime-opt-in and disabled by default (`node.rendezvous.nostr.enabled: false`; also LAN mDNS discovery `node.rendezvous.lan.enabled: false`, service `_fips._udp.local.`, unauthenticated TXT hint, identity proven only by the FMP Noise IK handshake).
  Sources: `docs/design/fips-nostr-discovery.md`; `docs/reference/security.md` ("Default Network Exposures by Transport").

---

## 4. Identity

- Claim: Node identity is a Nostr keypair (secp256k1; Schnorr signatures, x-only ECDH). The public key / npub is the application-facing address. Three derived forms, all deterministic from the keypair: (1) `node_addr` = SHA-256 of pubkey truncated to 16 bytes, used in packet headers and bloom filters so intermediate routers never see npubs; (2) an IPv6 `fd00::/8` address (`fd` prepended to the first 15 bytes of node_addr) for the TUN adapter; (3) the npub itself.
  Sources: `docs/design/fips-architecture.md` ("Identity System"); `docs/how-to/persistent-identity.md` (https://raw.githubusercontent.com/jmcorgan/fips/master/docs/how-to/persistent-identity.md).
- Claim: The same keypair signs Nostr events, Noise IK link handshakes, and Noise XK session handshakes — "there is no separate Nostr key." The pubkey "is never exposed beyond the endpoints of an encrypted channel" at the mesh layer.
  Sources: `docs/reference/nostr-events.md`; `docs/reference/security.md`; `docs/design/fips-architecture.md`.
- Session keys: Claim: session keys come from the Noise key schedule (HKDF-SHA256 over secp256k1 x-only DH), not from a separate KDF off the identity key; there is no documented bespoke "mesh identity → session key" derivation beyond Noise.
  Source: `docs/reference/security.md` ("Cryptographic Primitives" table: key derivation = HKDF-SHA256, Noise key schedule).
- Persistence: Claim: three modes — ephemeral by default (fresh keypair per start, `node.identity.persistent: false`); persistent (key generated on first start to `/etc/fips/fips.key`, bech32 `nsec`, mode 0600, npub in `fips.pub` 0644); or provisioning from an existing nsec (migrate any Nostr identity into a node). `fipsctl keygen` mints keypairs; an existing nsec from any nostr tool works.
  Source: `docs/how-to/persistent-identity.md`.
- Rotation: Claim: rotation is destructive and manual — stop daemon, delete key files, restart (new keypair), then update every peer config/ACL/advert by hand; "no in-protocol 'key change' message"; "no recovery from a lost `fips.key`." Successor-key migration is "a future consideration." Rekey (session/link symmetric keys) is separate and automatic (see §1).
  Sources: `docs/how-to/persistent-identity.md` ("Rotating"); `docs/design/fips-architecture.md` ("Key rotation changes the node's identity…").
- Memory hygiene: Claim: `zeroize` on drops for handshake secrets, HMAC/SHA-256 states, config text carrying `nsec`, with an honest list of what erasure does *not* reach (move copies, registers, `ring` internals).
  Source: `docs/reference/security.md` ("Key Material in Memory").

---

## 5. Maturity

- Claim: Status **v0.6.0-dev** on `master`; latest release **v0.5.2** (maintenance release on the v0.5.x line); v0.5.0 was the last feature release. "The core protocol works end-to-end over UDP, TCP, Ethernet, Tor, Nym, and Bluetooth on a global, public test mesh of thousands of nodes."
  Source: README "Status & roadmap" (https://raw.githubusercontent.com/jmcorgan/fips/master/README.md).
- Claim: The README states up front: "FIPS is under active development. The protocol and APIs are not yet stable." Longer-term roadmap items include "Protocol stability and a versioned wire format"; new wire-format work is staged on a `next` branch.
  Sources: README; `docs/design/fips-nostr-discovery.md` (`fips-overlay-v1-next` on `next` branch).
- Claim: Security audit has **not** happened — "Security audit of the cryptographic protocols" is listed as a near-term priority.
  Source: README ("Near-term priorities").
- Claim: crates.io — **the crate is published as `fips-mesh`** (version 0.5.3, published 2026-10-16, MIT, 1 version, 14 downloads at time of check). `core/Cargo.toml` is `publish = false`, so only the root crate is on crates.io. Note the tension: the README's longer-term roadmap still lists "Published crate" (likely stale), while `Cargo.toml`'s comment and crates.io confirm publication of 0.5.3. The how-to still recommends the **git dependency** for the native API client.
  Sources: crates.io API https://crates.io/api/v1/crates/fips-mesh; `Cargo.toml` header comment; `docs/how-to/use-the-native-datagram-api.md` (Step 2); `core/Cargo.toml`.
- Claim: Build/test rigor is high for a v0.x: Docker-based integration + chaos testing, reproducible builds (pinned toolchain, `SOURCE_DATE_EPOCH`), tiered test suites including state-machine explorers, but only the Debian `.deb` path is exercised by install tests, and "no workflow installs a published artifact, so the released packages are checked by hand."
  Sources: README; `Cargo.toml` (features/profiles); `testing/README.md` per README.

---

## 6. License & dependency hygiene

- Claim: License is **MIT** — README badge, `LICENSE` file, `Cargo.toml` `license = "MIT"`, and `core/Cargo.toml` `license = "MIT"`. MIT embedding/linking is clean for proprietary or copyleft consumers alike.
  Sources: README "License"; https://raw.githubusercontent.com/jmcorgan/fips/master/LICENSE; `Cargo.toml`; `core/Cargo.toml`.
- Claim: Dependency tree contains **no AGPL components**. The dependency set (from `Cargo.toml` / `core/Cargo.toml`) is permissively licensed: `tokio`, `serde`, `clap`, `ratatui`, `tracing`, `crossbeam-channel` (MIT/Apache-2.0); `nostr`/`nostr-sdk` 0.44 with `nip59` feature (MIT); `secp256k1` (rust-secp256k1, CC0; underlying C libsecp256k1 MIT); `ring` 0.17 (ISC-style, with an OpenSSL-derived subset exception); RustCrypto `sha2`/`hmac`/`hkdf`/`chacha20poly1305` (MIT/Apache-2.0); `zeroize`; `mdns-sd` (MIT); `tun`, `rtnetlink`, `rustables`, `bluer`, `socket2`, `if-addrs` (MIT/Apache-2.0 or BSD). `fips-core` is an in-repo path dependency (MIT).
  Sources: `Cargo.toml` ([dependencies] and target tables); `core/Cargo.toml`.
- Claim: The only AGPL-adjacent artifact is **external, not a dependency**: `examples/sidecar-nostr-relay/` runs a *strfry* Nostr relay in a container as a deployment example; nothing in the FIPS crate links it.
  Source: README ("Examples").
- One build-time footnote: building from source on Linux needs `libclang` (bindgen for nftables bindings via `rustables`) and `libdbus` dev headers for BLE; these are not runtime dependencies and the prebuilt `.deb`s don't need them.
  Source: README ("Building from source").

---

## 7. Suitability concerns for a "tailcat-style" tool

Assessment of possible blockers (a tailcat-style tool = user-friendly point-to-point encrypted tunnels, Tailscale-like UX, ideally no root, minimal moving parts):

1. **TUN/root is never required for the native path — good.** The native datagram API needs no TUN and no root (just `fips` group membership on the daemon's socket). Sources: `docs/how-to/use-the-native-datagram-api.md`, `docs/reference/security.md` ("Native Datagram API").
2. **But it does require a full mesh daemon.** A tailcat on FIPS ships/starts the whole `fips` daemon (routing, spanning tree, bloom gossip, all transports, optional TUN adapter, gateway, DNS). There is no "link two nodes, nothing else" mode. Sources: `docs/design/fips-architecture.md`; README project structure.
3. **Mesh overhead for 2-node tunnels.** For a two-node tunnel you pay for spanning-tree construction, bloom-filter gossip, MMP metric measurement, ECN relay, and double encryption (IK + XK on every packet, even adjacent) — a documented uniform design choice. Sources: `docs/design/fips-architecture.md` ("Both layers always apply, even between adjacent peers"); `docs/design/fips-concepts.md`.
4. **No direct-path optimization guaranteed.** Traffic routes via spanning-tree coordinates; a direct LAN peer still gets double-wrapped; discovery warms caches but there is no documented "always prefer the direct path / shortcut" mechanism beyond the NAT-punch socket adoption. Sources: `docs/design/fips-architecture.md`, `docs/design/fips-nostr-discovery.md` (Phase 5).
5. **Unreliable datagrams only.** No stream mode, no ack/retransmit/ordering/flow control; five silent drop paths; no half-close. A tailcat wanting to proxy TCP would have to build reliability itself (the mesh's own non-goals explicitly push this to applications). Sources: `docs/reference/native-api.md` ("Where data disappears"), `docs/design/fips-concepts.md` ("Non-goals").
6. **API instability.** The native API "may change or be withdrawn in any release"; no compat promise; Unix-only (Windows excluded); macOS E2E untested. Anything built on it today is on shifting ground. Source: `docs/how-to/use-the-native-datagram-api.md`.
7. **Trust model is node-shaped, not app-shaped.** `fips` group membership = the node's identity; any local program in the group can impersonate the node to the whole mesh and hold any port; descriptors are revocable only by daemon restart. Fine for a single-user tunnel tool; coarse for multi-user hosts. Source: `docs/reference/security.md` ("Native Datagram API").
8. **Identity rotation is manual and destructive** — no successor-key announcement; losing the key file loses the identity. A consumer tool wanting friendly "rotate my node key" UX would have to build it. Sources: `docs/how-to/persistent-identity.md`; `docs/design/fips-architecture.md`.
9. **Not anonymity.** Direct peers learn your identity; relays see metadata; FIPS explicitly disclaims being Tor. (For a tailcat this is usually fine — Tailscale makes the same trade.) Source: `docs/design/fips-concepts.md` ("Non-goals").

Counterweights: Nostr-native discovery + NIP-59/NIP-44 hole-punch signaling is exactly the bootstrap a tailcat-style tool needs, and it is optional and off by default; multi-transport (including Tor and BLE) comes free; docs and wire-format specs are excellent; MIT with a clean permissive dep tree; a live multi-thousand-node test mesh proves the core protocol works.

---

## Verdict for noscat

FIPS is the closest existing open implementation of "Tailscale over Nostr identities": npub-addressed nodes, self-organizing routing, STUN/NAT punching advertised through Nostr events, and a pubkey+port datagram surface that a netcat-style tool could be built on *today* (Linux/macOS/FreeBSD, no TUN, no root beyond `fips` group). It is **not** a drop-in library substrate, though: the embeddable surface is a Unix-socket client of a heavyweight, always-on mesh daemon; the native API is explicitly experimental and unversioned; the data path is unreliable datagrams with double encryption and mesh-routing machinery you pay for even in a 2-node tunnel; there has been no security audit; and key rotation is manual. It is best treated as (a) a design and wire-format reference of unusually high quality, and (b) a deployable daemon to interoperate with — not as a crate to embed in noscat. If noscat needs in-process, minimal-surface point-to-point tunnels, building directly on `fips-core`-style Noise XK over a thin Nostr signaling layer (mirroring kinds 37195/21059/10050) would be lighter than depending on the whole FIPS node.
