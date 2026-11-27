# noscat plan: a private mesh with no DNS, no certificates, no URLs

Goal: a private mesh works end to end without DNS, without a certificate
authority, and without anyone typing or reading a URL. Devices are found by
npub; the only thing passed out of band is the pairing QR, which carries
npubs and raw addresses. It builds on 0.6.0 (STUN from the mesh's own
relay, invite codes in the apps). Phases 2 to 4 are phase 0 of 0.7.0
(decided 2026-11-26, in place of pinned relay certificates in 0.6.1: the
FIPS path gives the same protection with no certificate); phases 5 and 6
are not yet slotted.

Decided 2026-11-25:

- **noscat-relay stays** the mesh's relay, a separate service on the
  reachable member. noscat does not grow an embedded relay for now.
- **The relay is reached over FIPS** once a device is in the mesh, at the
  npub of the member that hosts it, so members never need its hostname or
  a TLS certificate.
- **Shared meshes and public relays are out of scope.** They keep using
  URLs; this plan is about private meshes.

What the nvpn-fips crates (0.4.124) already give us, checked 2026-11-25:

- A peer can be configured as an npub plus addresses (`PeerConfig`), and a
  numeric IP skips DNS (`transport/resolve.rs` fast path). A joining device
  can link to the reachable member from the QR alone, before any advert.
- STUN is client only (no server side). The server list takes IP
  literals, and `external_addr` lets a member with a known public IP skip
  STUN. The server is noscat-relay's job (0.6.0 phase 1).
- A Tor transport exists (outbound by SOCKS5; inbound by onion service
  through the control port or a `HiddenServiceDir`), but needs a Tor daemon
  on the device. No embedded Arti.
- A BLE transport exists behind `host-ble-transport` (note for 0.7.0).

What does not change: reachability. A device behind carrier-grade NAT
(this desktop, `100.64.55.93`) still cannot be the meeting point; the
reachable member still needs a public address. The plan changes how devices
find that member, not who can be reached. Onion (phase 5) is the only piece
that touches this.

## Phase 1: STUN from the mesh's own relay (0.6.0 phase 1)

Already planned in `plan-0.6.0.md`. STUN servers in the group state and the
QR are written as `ip:port`, never a hostname.

## Phase 2: the QR carries the meeting point, not a URL

- [ ] The pairing QR names the reachable member by npub and raw address:
      `noscat:<npub>?peer=<member npub>@<ip:port>` (several `peer` entries
      allowed, IPv4 and IPv6). Spec change in `docs/nip-noscat.md`. The
      joiner's own code goes the other way (phase 4).
- [ ] At join, the device configures that member as a FIPS peer with those
      addresses, so its first link needs no relay, advert or DNS.
- [ ] The group state of a private mesh carries the same entries, so a
      member whose cached address goes stale learns the new one from any
      peer it still reaches.
- [ ] `noscat mesh peer add|remove <npub> <ip:port>`; `noscat up
      --reachable --external <ip:port>` publishes its address there instead
      of relying on STUN (maps to FIPS `external_addr`).

## Phase 3: the relay over FIPS

- [ ] noscat on the relay's host exposes the relay as a mesh service (the
      existing expose path, members only), e.g. `noscat up --serve-relay
      127.0.0.1:<port>`.
- [ ] The group state names the relay as `<host npub>` plus the service,
      not a URL. A member's noscat opens a loopback forward to it and points
      its nostr client at that local address.
- [ ] Apps list the mesh's relays by member name; no URL field in the
      normal flow.
- [ ] Netrig scenario: relay reached only over FIPS, DNS blocked
      (`unshare -n` with a resolver that fails every query).

## Phase 4: joining without DNS or a certificate

A joining device is not a member yet, so it cannot use the FIPS path of
phase 3 (the reachable member's FIPS allowlist only admits members).
Decided 2026-11-26 ([ADR 0010](adr/0010-two-way-pairing.md)): pairing is
two-way, so the mesh knows the joiner's npub before it connects, and the
join never leaves FIPS.

- [ ] A member takes in the joiner's code (scanned or pasted) and records
      the approval in the group; the relay host admits that npub in FIPS
      as a pending joiner, confined to the relay's service port, for one
      join or 15 minutes. The joiner publishes its key package and gets
      its Welcome over that session (0.7.0 phase 0 has the details).
- [ ] No plain socket: noscat-relay listens on loopback only. The domain,
      Caddy and the certificate become optional on the relay host (kept
      for shared use and for anyone who prefers TLS).
- [ ] Not taken: a plain `ws://` listener for the join (path metadata, a
      relay facing the internet) and a one-time guest key in the QR (a
      secret in the code, a second identity on the joiner).

## Phase 5: onion, opt in

- [ ] `noscat up --tor` uses FIPS's Tor transport through a local Tor
      daemon (Orbot on Android): outbound always, inbound with an onion
      service when the daemon allows it.
- [ ] The QR and group state may carry an `onion` address for a member. It
      survives IP changes and makes a member behind carrier-grade NAT
      reachable (slowly: Tor latency, TCP only, so a fallback path).
- [ ] Docs: which mode suits which platform; noscat never starts or
      bundles Tor itself.

## Phase 6: no third parties left

- [ ] A private mesh never contacts the public default relays (this also
      covers the deferred item: a device outside any mesh publishing its key
      package to public relays at start; with phase 4 it publishes only to
      the mesh it is joining).
- [ ] A packet capture of a full join plus a day of use on a private mesh
      shows no DNS query and no TLS handshake. Recorded in the netrig suite.

## Open questions

- When the reachable member's IP changes and no member saw it happen,
  devices fall back to onion if configured, else to a fresh QR. Is a
  last-resort public rendezvous (opt in) worth keeping?
- Phase 3's loopback forward versus a custom transport inside the nostr
  client (fewer moving parts, more code).
