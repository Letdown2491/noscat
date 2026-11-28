# noscat 0.9.0 plan: two-way pairing, and a private mesh without DNS

0.9.0 ships in lockstep in noscat, noscat-desktop, noscat-android and
noscat-relay. It was phase 0 of 0.8.0 until the roadmap was re-cut on
2026-11-27 (`docs/plan-0.8.0.md` says why); Bluetooth follows in 0.10.0
(`docs/plan-0.10.0.md`).

Decided 2026-11-26. Joining becomes a two-way exchange of pairing codes,
on every mesh, and a private mesh needs no DNS, no certificate and no
plain socket: phases 2 to 4 of `docs/plan-no-dns.md`, in place of the
certificate pins once planned for 0.7.0. See
[ADR 0010](adr/0010-two-way-pairing.md). The relay over FIPS is also what
Bluetooth's relays through the mesh build on (0.10.0, phase 4), so this
comes first.

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

## Release

- [ ] Docs in all three repos (README, API, man page for `join` and
      `mesh add`, nip-noscat for pairing codes, approvals and the pending
      joiner, CONTEXT terms), CI green, netns suite, `tests/mdk-interop`.
- [ ] `docs/private-mesh.md` and `site/private-mesh.html` switch to the
      setup without a domain.
- [ ] noscat-relay listening on loopback only, in the same lockstep.
- [ ] Lockstep 0.9.0 per `docs/releasing.md`.
