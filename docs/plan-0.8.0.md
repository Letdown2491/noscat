# noscat 0.8.0 plan: Bluetooth

0.8.0 lets a device with no working network (no Wi-Fi, no mobile data)
stay in the mesh through a nearby member over Bluetooth LE. It ships in
lockstep in noscat (Linux CLI), noscat-desktop (Linux) and
noscat-android. macOS follows in 0.9.0 (`docs/plan-0.9.0.md`). Windows
is out: it has no Bluetooth LE L2CAP channels for apps, and the
alternative needs upstream FIPS work we are not taking on.

Decided 2026-11-25 (moved from 0.6.0 the same day, when 0.6.0 became
access and privacy: `docs/plan-0.6.0.md`):

- **Opt-in**, per device: a toggle in Settings (desktop and Android) and
  a saved CLI setting (`--bluetooth`). A device with it on advertises,
  accepts and relays for members nearby.
- **Every Linux build has it**, glibc and musl alike: one static binary,
  no new package dependencies. See [ADR 0008](adr/0008-bluetooth-through-the-host-bridge.md).
- **Relays through the mesh in the same release**: without it, a
  Bluetooth-only device would miss membership changes, invites and names
  until it was back online.
- STUN for private meshes, once planned here, ships earlier in 0.6.0; the
  BSD binaries in 0.7.0.

## How it fits

FIPS already routes through members: a device whose only link is
Bluetooth to a laptop reaches every other member through that laptop,
end to end encrypted (the laptop forwards what it cannot read). FIPS's
Bluetooth transport uses LE L2CAP connection-oriented channels and a
small advertised record naming the channel. Its host bridge
(`host-ble-transport`) hands the platform calls to the application as
commands (listen, advertise, scan, connect) and events (stream data,
discoveries); noscat answers them per platform.

```
  noscat-core dataplane ── FIPS node ── UDP transport (as today)
                               └─────── BLE transport (host bridge)
                                            │ commands / events
            ┌───────────────────────────────┼──────────────────────┐
     Linux: zbus (BlueZ D-Bus)       Android: Kotlin via      macOS (0.9):
     + kernel L2CAP sockets          noscat-ffi               CoreBluetooth
     (CLI and desktop app)                                    (CLI and app)
```

Admission is unchanged: links of any kind are members only (ADR 0005).

## Phase 0: two-way pairing, and a private mesh without DNS

Decided 2026-11-26. Joining becomes a two-way exchange of pairing codes,
on every mesh, and a private mesh needs no DNS, no certificate and no
plain socket: phases 2 to 4 of `docs/plan-no-dns.md`, in place of the
certificate pins once planned for 0.7.0. See
[ADR 0010](adr/0010-two-way-pairing.md). The relay over FIPS is also what
phase 4 below builds on, so the two are one piece of work.

Pairing (every mesh, private or on public relays):

- [ ] The joiner scans or pastes any member's pairing code; that member's
      npub is the joiner's trust anchor. A member scans or pastes the
      joiner's code (its npub and name), and that act is the approval.
      Any member may approve, not only the one whose code was scanned
      (every device is an admin, ADR 0007).
- [ ] A pasted code (remote, or a headless machine over SSH) shows a short
      check code derived from the joiner's npub on both screens, to
      compare before approving; a scanned code skips it.
- [ ] The approving member records the approval in the group (the joiner's
      npub, an expiry of 15 minutes, single use). Any online member then
      commits the Add once the joiner's key package is in hand, so a phone
      that goes to sleep does not stall the join.
- [ ] `join` accepts a Welcome for a mesh in which the scanned member is a
      member (checked after staging), not only a Welcome from that exact
      device.
- [ ] Members see who added whom (an event in the client, a line in the
      CLI, a notice in both apps).
- [ ] Join requests go: no gift-wrapped request, no prompt anyone who
      knows your npub can trigger, no `mesh requests`. The CLI's
      `noscat join` prints this device's pairing code (and a terminal QR)
      and waits; `noscat mesh add <code>` approves.
- [ ] On a mesh on public relays, the approving member fetches the
      joiner's key package from the relays as `invite` does today.

A private mesh without DNS:

- [ ] Pairing codes carry the meeting point (`<host npub>@<ip:port>`)
      instead of a relay URL, and the group state keeps it current
      (no-dns phase 2).
- [ ] Members reach the mesh relay over FIPS at its host's npub, through a
      loopback forward; no hostname, no certificate (no-dns phase 3).
      noscat-relay listens on loopback only: nothing of it faces the
      internet.
- [ ] An approval tells the relay host to admit the joiner's npub in FIPS
      as a pending joiner: confined to the relay's service port (no
      streams, no access rules, no other service), dropped after one join
      or 15 minutes, a few at a time at most. Today FIPS admission means
      membership (`dataplane.rs`, `streams.rs`, ADR 0005); the pending
      joiner is the one exception and must stay that narrow. The joiner
      publishes its key package and gets its Welcome over that session.
- [ ] Netrig: a private mesh joined and used with DNS blocked and no relay
      port reachable from outside.

Not taken (ADR 0010): plain `ws://` for the join, a one-time guest key in
the QR, a key the inviter makes for the joiner, pinned certificates.

## Phase 1: spike (Linux)

- [ ] Linux bridge: BlueZ over zbus (advertising via LEAdvertisingManager1,
      the bootstrap record via GattManager1, scanning via Adapter1 and
      ObjectManager signals) plus kernel L2CAP sockets (AF_BLUETOOTH,
      SOCK_SEQPACKET) through libc. Builds static on musl.
- [ ] Two Linux machines, one with networking off: chat and a file
      reach a third member through the other, over Bluetooth.
- [ ] Measure throughput and latency over one Bluetooth hop; check what
      a user needs to advertise without root (group or polkit) on Fedora,
      Debian, Arch and Alpine.
- [ ] Check whether dropping FIPS's own glibc Bluetooth code (`bluer`)
      also drops the libdbus build dependency.

## Phase 2: Linux CLI and desktop app

- [ ] `Dataplane` config gains Bluetooth (off by default); the client
      exposes it (`ClientConfig.bluetooth`, `set_bluetooth`).
- [ ] CLI: `--bluetooth`, saved like the device name; `noscat status`
      shows Bluetooth state (off, on, unavailable: no BlueZ, no adapter,
      not permitted) and Bluetooth links.
- [ ] Desktop: a Settings toggle with the same states and a hint when
      advertising is not permitted.
- [ ] Member list shows which links run over Bluetooth (CLI, desktop).

## Phase 3: Android

- [ ] noscat-ffi exposes the bridge (commands out, events in).
- [ ] Kotlin side: L2CAP channels (Android 10+), advertising and
      scanning, Bluetooth permissions, runs in the existing foreground
      service.
- [ ] Settings toggle; the member list marks Bluetooth links.
- [ ] Test on the Pixel against a Linux desktop: phone in airplane mode
      with Bluetooth on stays in the mesh through the desktop.

## Phase 4: relays through the mesh

- [ ] A device with no route to its mesh relays reaches them through a
      member that has one: the member proxies the relay connection over
      a stream (members only, the relays the mesh lists only).
- [ ] Private meshes: login (NIP-42) still uses the device's own key,
      end to end through the proxy.
- [ ] Invites, removals, names and presence arrive on a Bluetooth-only
      device; it catches up when its relay route comes back.
- [ ] A private mesh's relay is already reached over FIPS (phase 0), and
      FIPS routes that through any member, Bluetooth included, which
      forwards what it cannot read. The proxy is for relays outside the
      mesh (public relays of a shared mesh): it carries the connection's
      raw bytes (TCP, with TLS end to end), not WebSocket frames, so the
      member that forwards sees neither queries nor events. (Marmot's
      accumulation relay idea, marmot#431, lets its buffer see the
      queries it serves; we have no need to.)

## Splits and healing

Decided 2026-11-25: no relay or event sync on each device. Relays carry
only the control plane (membership, invites, names, presence), and a
membership change happens only once a relay has accepted it (`commit`
publishes first and drops the change otherwise). So a group of devices
cut off from every relay (an island) keeps its data plane (chat, files,
forwards among its members, over any link including Bluetooth) but
cannot change membership; when a route to a relay comes back, its
devices catch up in order. History stays linear: nothing to reconcile.

- [ ] Relays through the mesh work in either direction: whichever member
      regains a relay route serves the others (phase 4).
- [ ] An island device that tries to invite or remove gets a clear error
      (no relay reachable), in the CLI and both apps.
- [ ] Test in the netns rig: four devices, split into two islands, the
      online island adds a device and removes one; on heal the offline
      island converges on the same members.
- [ ] Document the two edge cases: a removal made during a split takes
      effect for the other island only once it catches up; two islands
      that each reach a different relay could both commit, which the
      convergence rule (ADR 0007) resolves within 5 commits per side, and
      past that the losing side's devices rejoin (below).
- [ ] A device that fell behind rejoins on its own
      ([ADR 0009](adr/0009-rejoin-by-readmission.md)). It fell behind by
      missing commits the relays no longer keep (noscat-relay prunes group
      messages after 30 days) or more than the 5 a member can rewind (the
      other island made more). It notices: its group's events keep
      arriving but none decrypt, and its epoch stays put after catch-up.
      It publishes a fresh key package and sends a rejoin request; any
      member commits a re-admission (remove its old leaf, add the fresh
      package in one commit) with no prompt, since the requester is in
      the current roster.
- [ ] The same re-admission replaces a member that never opened its
      Welcome (0.7.0 marks it never joined): it is in the roster, so once
      its Welcome deadline has passed it sends a rejoin request like any
      device that fell behind.
- [ ] Wire: the rejoin request in `docs/nip-noscat.md`; `join` accepts a
      Welcome for the mesh this device is already in, from a member of
      it, and replaces its state.
- [ ] netns rig: the island test above with one island making 6 commits;
      the other island's devices rejoin on heal and converge on the same
      members.

## Catching up with NIP-77

Decided 2026-11-26: catch-up after a split or a long absence is where it
pays, and it needs a relay change in the same lockstep release. Today
`page_relay` walks back by time, 500 events a page (up to 200 pages), and
misses events when one second holds more than a page.

- [ ] noscat-relay: `relay.Negentropy = true` and 77 in `SupportedNIPs`.
      khatru (v0.19.1) runs NEG-OPEN through `RejectFilter`, so the
      member, login and `#h` checks apply unchanged.
- [ ] noscat-core: record the id and time of each group event received
      (bounded, in `relay-sync.json`; `seen` holds MLS digests, not event
      ids). Catch-up first tries nostr-sdk's `Relay::sync` with those
      items on a relay that supports NIP-77 (its NIP-11 document, or what
      it answered last time, cached), then fetches the missing ids in
      batches.
- [ ] Fall back to paging, per relay, on a refusal (NEG-ERR or a NOTICE),
      silence past a short initial timeout, or `auth-required:` (retried
      after login). We never hold live events back behind history, so a
      relay that ignores NIP-77 costs one timeout, not the 15 minute
      stall MDK has (mdk#3643).
- [ ] Tests on the mock relay (nostr-relay-builder speaks negentropy): a
      gap holding more than a page of events in one second is filled; a
      relay without NIP-77 falls back to paging.

## Phase 5: release

- [ ] Docs in all three repos (README, API, man page, nip-noscat for any
      wire addition, CONTEXT terms), CI green, netns suite, a two-machine
      Bluetooth test written down as a manual check.
- [ ] Lockstep 0.8.0 per `docs/releasing.md`.
