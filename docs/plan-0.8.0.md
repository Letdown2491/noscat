# noscat 0.8.0 plan: services, rejoin and catch-up

0.8.0 ships in lockstep in noscat, noscat-desktop and noscat-android, with
noscat-relay for NIP-77.

Re-cut 2026-11-27: the 0.8.0 planned until then (pairing, a private mesh
without DNS, Bluetooth, services, healing, NIP-77) was too big for one
release and became three. The pieces that need neither new pairing nor
Bluetooth ship first, here; two-way pairing and a private mesh without
DNS are 0.9.0 (`docs/plan-0.9.0.md`); Bluetooth and relays through the
mesh are 0.10.0 (`docs/plan-0.10.0.md`). macOS moved to 0.11.0 and the
screen to 0.12.0.

- **Services by name in a browser** (#21, decided 2026-11-27): a device
  lists the services it offers, and every member reaches them at
  `*.localhost` URLs.
- **Rejoin by readmission** (ADR 0009): a device that fell behind, or
  never opened its Welcome (0.7.0 marks it never joined), rejoins on its
  own. Splits and healing are tested here with network splits; Bluetooth
  only adds another way to end up on an island.
- **Catching up with NIP-77**: fixes paging that misses events, which
  pays after any long absence, not only after a split.

## Services and `*.localhost` URLs (#21)

Decided 2026-11-27. A device keeps a list of named services and announces
it; every member runs a local proxy that turns them into browser URLs.
Browsers resolve `*.localhost` to loopback themselves (RFC 6761) and treat
it as a secure context, so there is no DNS and no certificate. The
loopback leg is plain HTTP that never leaves the machine; the leg to the
member is the existing forward path, end to end encrypted.

- [ ] **Named, saved services**: `noscat expose add <name> <port>
      [--tcp]`, `expose list`, `expose remove <name>`, saved in the device
      directory and edited by the apps through the client API. A service is
      on the member itself (a port on its loopback); no LAN targets for
      now. `--tcp` marks a service a browser cannot use (SSH, a
      database).
- [ ] **Quick, temporary exposes**: `noscat expose <port>` exposes a port
      while the command runs, named by its number, and is gone when it
      stops (a dev server). `up --serve-port` becomes a hidden alias for
      one release, then goes.
- [ ] **Announced in adverts**: the advert gains a services field (name,
      port, kind). Check first that 0.7 ignores an unknown advert field;
      spec change in `docs/nip-noscat.md`. Every member sees the names;
      the services access group still decides who may connect.
- [ ] **The proxy**, on every member while a client runs (CLI `up`, both
      apps): one listener on `127.0.0.1:7080` (configurable) for named
      services, `http://<service>.<device>.localhost:7080`, and a listener
      on each announced port number for `http://<device>.localhost:<port>`
      (the dev server case), falling back to the 7080 form when that local
      port is taken. Always 7080, never port 80: ports below 1024 need
      root on Linux, the BSDs and Android.
- [ ] **Routing per connection**: read the `Host` of a connection's first
      request, pick the member and service, then splice bytes like
      `forward` (browsers keep a connection per host name, and WebSockets
      keep working). `Host` reaches the service unchanged. An unknown name
      gets a page listing the known ones.
- [ ] **Device names in URLs**: the member's current name, lowercased,
      anything but a letter or digit turned into `-`, repeats merged, at
      most 63 characters ("Pixel 9a" is `pixel-9a`, "Noscat VPS"
      `noscat-vps`). Read from the roster at each connection, so a rename
      works at once; an old name redirects to the new one for 30 days.
      Two members with the same name: the second in roster order gets a
      short tag from its key (`pixel-9a-x7k`). The npub (63 characters,
      one DNS label) always works as a name that never changes.
- [ ] **Web pages cannot use it**: refuse a request whose `Origin` or
      `Referer` is not a `*.localhost` URL, so a site in the same browser
      cannot send requests to a member's service. Other users on the same
      machine can still connect to the loopback listener, as with
      `forward`; documented.
- [ ] **Client and FFI API** (API.md in the same commit): this device's
      saved services (list, add, remove), quick exposes, every member's
      announced services with the URL that works on this device, and an
      event when either list changes. The proxy runs with the client, so
      the apps get it without starting anything.

Apps (both replace today's Services tab, which is built around a single
expose target and the port forwards):

- [ ] **Desktop**: the Services tab becomes two lists. "On this device":
      this device's services (name, port, web or TCP), add and remove,
      plus any quick exposes running. Exposing no longer switches the app
      into an expose mode with a Stop button: services are served whenever
      the device runs. "In the mesh": every member's services, grouped by
      member, with Open (in the default browser) and Copy URL for web
      services and Forward to a local port for TCP ones. Port forwards
      stay, under the TCP services. Each member's card in Devices shows
      its services too.
- [ ] **Android**: the Services tab shows "In the mesh" as on the
      desktop: Open hands the URL to the browser (the proxy runs in the
      app's foreground service, so it works while the app runs), Copy URL,
      Forward for TCP. Members' cards show their services. The phone
      offering services itself stays out of 0.8.0 (it rarely runs one;
      Termux users have the CLI).
- [ ] Both apps: a rename or a member leaving updates the lists live
      (the event above); a service whose member is offline shows as such
      instead of disappearing.
- [ ] **Spike first**: `*.localhost` (subdomains included) in Chrome,
      Firefox, Safari and Edge on each platform, and in Chrome and Firefox
      on Android; Vite's host check and live reload through the proxy.
      Document the fallback where a browser does not resolve it.
- [ ] Netrig: a member's HTTP service through the proxy by name and by
      port, a WebSocket through it, a rename, an unknown name, and a
      request from another origin refused.

Later, not 0.8.0: the desktop app offering to expose a port it sees a
local dev server open; LAN targets (a router behind a member).

## Splits and healing

Decided 2026-11-25: no relay or event sync on each device. Relays carry
only the control plane (membership, invites, names, presence), and a
membership change happens only once a relay has accepted it (`commit`
publishes first and drops the change otherwise). So a group of devices
cut off from every relay (an island) keeps its data plane (chat, files,
forwards among its members, over any link, Bluetooth too from 0.10.0) but
cannot change membership; when a route to a relay comes back, its
devices catch up in order. History stays linear: nothing to reconcile.
Serving an island through a member that still reaches a relay comes with
relays through the mesh in 0.10.0 (`docs/plan-0.10.0.md`, phase 4).

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

## Release

- [ ] Docs in all three repos (README, API, man page, nip-noscat for the
      advert's services field and the rejoin request, CONTEXT terms), CI
      green, netns suite.
- [ ] noscat-relay with NIP-77 in the same lockstep.
- [ ] Lockstep 0.8.0 per `docs/releasing.md`.
