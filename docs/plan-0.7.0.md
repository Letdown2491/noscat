# noscat 0.7.0 plan: Bluetooth

0.7.0 lets a device with no working network (no Wi-Fi, no mobile data)
stay in the mesh through a nearby member over Bluetooth LE. It ships in
lockstep in noscat (Linux CLI), noscat-desktop (Linux) and
noscat-android. macOS follows in 0.8.0 (`docs/plan-0.8.0.md`). Windows
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
- STUN for private meshes and the BSD binaries, once planned here, ship
  earlier in 0.6.0.

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
     Linux: zbus (BlueZ D-Bus)       Android: Kotlin via      macOS (0.8):
     + kernel L2CAP sockets          noscat-ffi               CoreBluetooth
     (CLI and desktop app)                                    (CLI and app)
```

Admission is unchanged: links of any kind are members only (ADR 0005).

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
- [ ] Lockstep 0.7.0 per `docs/releasing.md`.
