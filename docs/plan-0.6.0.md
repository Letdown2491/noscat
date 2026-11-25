# noscat 0.6.0 plan: Bluetooth and a fully private mesh

0.6.0 lets a device with no working network (no Wi-Fi, no mobile data)
stay in the mesh through a nearby member over Bluetooth LE. It ships in
lockstep in noscat (Linux CLI), noscat-desktop (Linux) and
noscat-android. macOS follows in 0.7.0 (below). Windows is out: it has
no Bluetooth LE L2CAP channels for apps, and the alternative needs
upstream FIPS work we are not taking on.

Decided 2026-11-25:

- **Opt-in**, per device: a toggle in Settings (desktop and Android) and
  a saved CLI setting (`--bluetooth`). A device with it on advertises,
  accepts and relays for members nearby.
- **Every Linux build has it**, glibc and musl alike: one static binary,
  no new package dependencies. See [ADR 0008](adr/0008-bluetooth-through-the-host-bridge.md).
- **Relays through the mesh in the same release**: without it, a
  Bluetooth-only device would miss membership changes, invites and names
  until it was back online.
- **STUN from the mesh's own relay** ([#1](https://github.com/Letdown2491/noscat/issues/1)):
  a private mesh then reaches no third party at all. Its protocol change
  ships with the relay-proxy one, so the protocol moves once.
- **BSD binaries** ([#19](https://github.com/Letdown2491/noscat/issues/19)):
  FreeBSD built with our two small patches in its own CI job, not waiting
  on upstream; OpenBSD and NetBSD tried in the same pass.

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
     Linux: zbus (BlueZ D-Bus)       Android: Kotlin via      macOS (0.7):
     + kernel L2CAP sockets          noscat-ffi               CoreBluetooth
     (CLI and desktop app)                                    (CLI and app)
```

Admission is unchanged: links of any kind are members only (ADR 0005).

## Phase 0: STUN for private meshes (#1)

Independent of Bluetooth; first, while the spike answers its questions.

- [ ] noscat-relay serves STUN on UDP (`STUN_PORT`, off by default), with
      pion/stun next to the relay: same box and operator as the relay, so
      no new exposure. Its own release, before noscat 0.6.0.
- [ ] The mesh carries its STUN servers like its relays: in the group
      state of a private mesh and in the pairing QR
      (`noscat:<npub>?relay=...&stun=...`), so a joining device uses them
      from its first moment. Spec change in `docs/nip-noscat.md`.
- [ ] A private mesh never falls back to the public defaults: with no
      STUN of its own, its devices advertise no NAT address and connect
      through the reachable member.
- [ ] CLI: `--stun` shown in `--help` and the man page; `noscat mesh stun
      add|remove`. Apps show the mesh's STUN servers next to its relays.
- [ ] Deployment note: Caddy proxies TCP only, so STUN needs UDP 3478
      open on the relay's host (on vm-2252, ask before changing it).

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

## Phase 4b: BSDs (#19)

Decided 2026-11-25 (option A): ship BSD binaries built with our patches
instead of waiting for upstream. Independent of everything else.

- [ ] The two patches from `docs/upstream/01-freebsd-build.md` live in the
      repo (`packaging/bsd/patches/`): `nvpn-mdns-sd` on `socket-pktinfo`
      0.4, and the `bind_socket_to_interface` fallback in
      `nvpn-fips-core`. Only the BSD CI job adds the `[patch]` section, so
      every other platform keeps building pure crates.io code.
- [ ] CI: FreeBSD build and tests (a FreeBSD VM action, or cross with a
      sysroot as in the spike); the release attaches
      `noscat-<tag>-x86_64-unknown-freebsd.tar.gz`.
- [ ] OpenBSD and NetBSD: try the same; ship binaries for those that
      build and pass, and record what fails for the others.
- [ ] Docs: INSTALL's BSD section points at the binaries (`cargo install
      noscat` keeps failing on the BSDs until upstream fixes it). A
      FreeBSD port (with the patches) and pkgsrc-wip later, on demand.
- [ ] When upstream ships the fixes, drop the patches; the upstream
      draft stays unposted unless approved.

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
      convergence rule (ADR 0007) resolves within 5 commits per side.

## Phase 5: release

- [ ] Docs in all three repos (README, API, man page, nip-noscat for any
      wire addition, CONTEXT terms), CI green, netns suite, a two-machine
      Bluetooth test written down as a manual check.
- [ ] Lockstep 0.6.0 per `docs/releasing.md`.

# noscat 0.7.0: macOS

- [ ] noscat-desktop on macOS: tray, Keychain for the storage key, an
      app bundle, signing and notarization (needs an Apple developer
      account).
- [ ] Bluetooth on macOS through CoreBluetooth in noscat-core (shared by
      the CLI and the app). The app asks for Bluetooth permission once.
      The CLI gets it when run from a terminal that has the permission;
      a background service (`brew services`) cannot ask, so the docs
      point background use with Bluetooth at the desktop app.
