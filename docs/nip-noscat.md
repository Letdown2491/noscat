# NIP-draft: Noscat, a private device mesh on Marmot and FIPS

`draft` `optional`

Version: Noscat 0.6.0.

---

## Abstract

Noscat joins a person's devices (or a small trusted group's) into a
private mesh with no coordinator and no root privileges. Membership is a
Marmot group (MLS, RFC 9420) carried by Nostr relays. Data travels
device to device over FIPS, an end-to-end encrypted overlay keyed by
Nostr identities, with QUIC streams on top for file transfer, text and
TCP forwarding.

Relays carry only Marmot traffic: key packages, gift-wrapped Welcomes
and encrypted group messages. They never see who is in a mesh, device
names, addresses or data.

## Motivation

Mesh VPNs need an account, a coordination server and usually root. Nostr
already gives every device a keypair and gives everyone relays. Marmot
turns those into an end-to-end encrypted group whose membership every
member can verify; FIPS turns the same keys into direct, encrypted paths
between devices. Noscat is the profile that combines them, so that:

1. the member list is the access list: a device that is not in the group
   cannot reach any member, and removal cuts it off at once;
2. any member can manage the mesh, so losing one device loses nothing;
3. everything runs in userspace on Linux, macOS, Windows, the BSDs and
   Android.

## Conventions

- MUST, SHOULD and MAY are used as in RFC 2119.
- Integers on streams are big-endian.
- "Device" is one Nostr keypair. Every device has its own npub; a person
  with three devices has three npubs.
- "Marmot" is the Marmot protocol as specified in the `marmot` repository
  (`transports/nostr.md`, `app-components/`, `protocol-core/`). Noscat
  implements the subset this document names and stays compatible with
  MDK clients such as White Noise.

## Overview

```
                 relays: Marmot only
         30443 key packages, 1059 (444 Welcome), 445 group
              ┌──────────────────────────────┐
              │                              │
         ┌────▼─────┐                   ┌────▼─────┐
         │ device A │◄─── FIPS (UDP) ──►│ device B │
         └──────────┘   QUIC streams    └──────────┘
```

| Layer | What | Where |
|---|---|---|
| Identity | Nostr keypair per device | local |
| Membership | Marmot group with the Noscat mesh profile | relays (encrypted) |
| Presence and endpoints | advert, an app message inside the group | relays (encrypted) |
| Transport | FIPS sessions between members | direct UDP, or relayed by a member |
| Streams | QUIC over FIPS service datagrams | inside FIPS |
| Apps | file, text, forward | QUIC streams |

## Meshes

A mesh is a Marmot group. Everything Marmot requires of a group applies;
this section lists what Noscat adds or narrows.

### Components

A Noscat mesh requires (in the `app_components` GroupContext list):

| Id | Component | Noscat use |
|---|---|---|
| `0x8003` | `marmot.group.admin-policy.v1` | every member is listed |
| `0x8004` | `marmot.group.nostr-routing.v1` | relays and `h` routing ids |
| `0x8009` | `marmot.member.account-identity-proof.v2` | binds each leaf to its npub |
| `0x800c` | `marmot.group.lifecycle.v1` | active; Noscat never disbands |

and carries, without requiring it:

| Id | Component | State |
|---|---|---|
| `0xf3a0` | `noscat.mesh.v1` | `opaque name<V>` (UTF-8, at most 64 bytes) |
| `0xf3a1` | `noscat.private.v1` | empty; present means the mesh is private |
| `0xf3a2` | `noscat.stun.v1` | `opaque servers<V>`: a list of `opaque server<V>` |

`noscat.mesh.v1` marks the group as a Noscat mesh and names it. Because
it is not required, non-noscat Marmot clients can join; they simply
ignore it. A group without it is a plain Marmot group: Noscat devices
can join it and exchange messages, and still use the data plane with
its other Noscat members.

`noscat.private.v1` makes the mesh private. Its devices then use only
the relays in the routing component (`0x8004`), not their own or public
defaults; they log in to those relays with NIP-42 as their device key;
and they log in nowhere else (a login ties a device to its `#h`
subscriptions, which a third-party relay must not learn). A private mesh
is meant for a members-only relay such as
[noscat-relay](https://github.com/Letdown2491/noscat-relay). Any admin
adds the component (an AppDataUpdate with empty state) or removes it.
Devices that do not know it keep using their own relays too, as in a
shared mesh.

`noscat.stun.v1` lists the STUN servers the mesh's devices use to learn
their public address, typically the mesh's own relay. Each server is an
IP literal and a port in canonical form (`198.51.100.7:3478`,
`[2001:db8::1]:3478`): no hostnames, so a mesh's STUN never needs DNS.
The list holds 1 to 8 servers, sorted by bytes and unique; any admin
replaces it (AppDataUpdate) or removes it. A device uses it from its next
start. Without the component, a shared mesh's devices use public STUN
servers and a private mesh's devices use none: they advertise no NAT
address and connect through the reachable member, so no third party
learns their addresses.

A Noscat device's leaf and key package advertise support for `0x0001`
and `0x8001`, `0x8003`, `0x8004`, `0x8009`, `0x800b`, `0x800c`,
`0xf3a0`, `0xf3a1` and `0xf3a2`. `0x800b` (encrypted media v2) is listed because MDK clients
require it in every new group; Noscat never sends media and leaves the
policy unchanged. Per Marmot, the key package event's `app_components`
tag lists exactly the advertised ids from `0x8000` up.

The leaf's MLS capabilities list extension `0x0006` (AppDataDictionary)
and proposals `0x0008` (AppDataUpdate) and `0x000a` (SelfRemove), and
nothing from the RFC 9420 default ranges.

### Every member is an admin

Each commit that adds a device also adds it to the admin policy; each
removal takes it out. Any member can add or remove members. Leaving is
two steps: a member removes itself from the admin policy (another admin
must remain), then sends a SelfRemove proposal that any other member
commits. The last member of a mesh forgets it locally.

### Convergence

With many admins, two members can commit at the same epoch. Noscat uses
Marmot's branch order (depth with a witness boost, witness score,
privileged before ordinary, lower committer key, lower commit digest).
It applies a commit at once and keeps the parent state of the last 5
commits. When a competing commit for one of those epochs arrives and
wins, the device rolls back and applies it. A device whose own change
lost reports it so the change can be retried. After input settles,
Noscat and MDK agree on the winning branch.

### Joining

The joining device publishes a key package (kind 30443) and its inbox
relays (kind 10050) and relay list (10002), then waits. An existing
member fetches the key package, commits the Add, publishes the commit
(kind 445) and sends the Welcome (kind 444) in a NIP-59 gift wrap
(kind 1059) to the new device's inbox relays.

A device that joins because its user scanned another device's QR code
MUST accept a Welcome only from that device (the gift wrap's rumor
author). The QR is the trust anchor; without it anyone could invite a
device into their own mesh.

While waiting, the joining device SHOULD send that device a join request
so its user can approve with one action instead of typing an npub: a
NIP-59 gift wrap (kind 1059) to the scanned device's inbox relays, whose
rumor is

| Field | Value |
|---|---|
| kind | `21196` |
| content | the joining device's name (UTF-8, at most 64 characters), or empty |
| tags | none |

A member that receives one from a non-member, with a rumor no older than
15 minutes, MAY show it to its user. A join request grants nothing: the
device is added only if a member then commits an Add for its key
package. Receivers MUST NOT prompt for requests from current members and
SHOULD show at most one prompt per device per 15 minutes, until they
answer it. A request from a current member that has not been heard from
since its Add means its Welcome went missing: the member that committed
the Add SHOULD resend the Welcome at once (below).

A joining device SHOULD repeat its request while it waits (Noscat every
15 seconds): a single gift wrap can be lost while relay connections come
up.

A device keeps at most its two newest key packages. After a successful
join it MUST delete the private keys of its key packages (it accepts no
further Welcome while in a mesh), and SHOULD ask its relays to delete
the published package: a NIP-09 kind 5 event, signed by the device, with
an `a` tag `30443:<pubkey hex>:<slot>` and a `k` tag `30443`.

A member MUST NOT add a key package that an Add it has applied already
consumed (compare the KeyPackageRef): the device behind it, removed
since or not, can no longer open a Welcome built on it.

The member that commits an Add keeps resending the Welcome until the new
member has sent anything in the group (an advert, a commit) or the
deadline passes: 7 days after the commit, or the key package's
`not_after` if sooner. A relay accepting the gift wrap is not proof of
delivery (some relays accept gift wraps they never serve back), so
Noscat resends after 30 seconds, doubling to an hour, while no relay has
accepted it, and after an hour, doubling to a day, once one has. Each
resend is a fresh gift wrap: NIP-59 backdates a wrap's `created_at` by
up to two days, and joiners look back three, so an old wrap would fall
out of view.

## Adverts

Every member sends an advert inside the group when it joins, on every
membership change, and at least every 2 minutes. An advert is a Marmot
application message whose inner event is:

| Field | Value |
|---|---|
| kind | `21195` |
| content | the device's FIPS overlay advert (a signed kind 37195 event, JSON), or empty while it has none |
| tags | `["name", "<device name>"]`, optional; `["reachable", "1"]` when the device is reachable from the internet (a fixed public UDP endpoint), so members can tell whether the mesh has one; `["control", "1"]` when the device offers control protocols (a terminal); it says nothing about who may use them; `["hello", "1"]` on the first advert a device publishes after it starts |

A member is online while its latest advert is under 10 minutes old.
Members feed the FIPS advert to their data plane; it is how they learn
each other's endpoints. Adverts never go to public relays.

A device that starts knows no member's endpoints: the adverts it
processed before are already marked seen, so catching up on the relays
does not bring them back. On an advert with `hello`, or from a member not
heard from for over 2.5 minutes, a member SHOULD answer with its own
advert at once instead of at its next tick: always for `hello` (answers
never carry it, so it cannot echo), and for the second case at most once
per 10 seconds per member. Devices that predate `hello` ignore it, and only answer the
second case.

## Data plane

Each device runs one FIPS endpoint keyed by its Nostr identity, with
link MTU 1320 so a path relayed by another member still carries 1210-byte
service datagrams.

Admission: the endpoint only accepts peers that are current members.
On every roster change the device replaces its peer list; a removed
device loses its links and sessions before the change returns.

Reachability: every mesh needs at least one member reachable from the
others (a forwarded port, a server, a public IPv6 address). Members
behind NAT reach each other directly where hole punching works and
through a reachable member otherwise. Devices on one LAN MAY find each
other by mDNS.

## Streams

QUIC (RFC 9000) runs over FIPS service datagrams on service port `4433`,
with 1200-byte packets. ALPN is `noscat`. The server certificate names
the device: its 64-character hex key split into two 32-character DNS
labels (`<hex[0..32]>.<hex[32..64]>`), and the dialer checks it. This
guards against misrouting only; authentication is FIPS's, since a
datagram's source is the member whose FIPS session carried it.

Before dialing, a device MAY ping service port `4434` until the member
answers, which waits out FIPS session setup.

## App protocols

Each app exchange is one bidirectional QUIC stream. The opener writes a
one-byte service tag and a header; the accepter answers with a status.

### Access

Membership lets a device open streams; it does not oblige the accepter to
serve them. Each accepter decides per member and per access group, and
answers "not permitted" when its rules say no:

| Group | Protocols |
|---|---|
| send | file (tag 1), text (tag 2) |
| services | forward (tag 3) |
| control | protocols that act on the device as its user (terminal, from 0.6) |

The accepter takes the opener's identity from the stream's connection,
which the QUIC handshake authenticates; the header carries no claim of
it. The rules are local to the accepter: they are never put in the group
state or in adverts. The reference implementation allows send and
services and asks its user on first use for control; a protocol that
asks tells the opener it waits, and treats no answer within 60 seconds
as not permitted. Older openers read "not permitted" as a refusal.

### File (tag 1)

```
opener:   [1][u16 name_len][name][u64 size][32-byte sha256]
accepter: [u64 offset]          u64::MAX = refused, 0xFFFFFFFFFFFFFFFE = not permitted
opener:   bytes offset..size, then finishes the stream
accepter: [u8 result]           0 = verified, 1 = sha256 mismatch
```

- `name` is UTF-8, at most 255 bytes, a base name only. Receivers MUST
  strip any path components (`/` and `\`) and leading dots, and refuse
  what is then empty or contains NUL.
- The receiver writes to `<name>.noscat-part` with a sidecar recording
  the expected sha256. If both exist and the sidecar matches, it answers
  with the partial's length and the sender resumes there.
- On a verified whole file it renames the partial into place (choosing a
  free name if one exists). On mismatch it deletes the partial.

### Text (tag 2)

```
opener:   [2][u8 kind][u32 len][utf8 text]    kind 0 = chat, 1 = clipboard
accepter: [0] once it has the text, [2] not permitted
```

Text is at most 65536 bytes. A receiver that gets clipboard text MAY put
it on the system clipboard; it SHOULD tell the user.

### Forward (tag 3)

```
opener:   [3][u16 port]
accepter: [u8 status]    0 = bridged, 1 = refused, 2 = not permitted
then raw bytes both ways until either side finishes
```

Port `0` is the member's default service, whatever it chose to expose.
Any other port is `127.0.0.1:<port>` on the member and is refused unless
the member serves that port. Receivers MUST NOT bridge to ports they did
not explicitly serve.

### Terminal (tag 4)

```
opener:   [4][u16 cols][u16 rows][u8 term_len][term]
accepter: [3]* then [u8 status]   3 = waiting for approval, 0 = started,
                                  1 = unavailable, 2 = not permitted
then frames both ways: [u8 type][u32 len][payload]
  opener:   0 = input (raw bytes), 1 = resize (u16 cols, u16 rows)
  accepter: 2 = output (raw bytes), 3 = exit (i32 status), last
```

A control protocol: the accepter runs the user's login shell in a PTY of
the given size, with `TERM` set from `term` (printable ASCII, at most 64
bytes; anything else becomes `xterm-256color`), as the user running the
accepter and never elevated. It MAY send `3` any number of times while it
asks its user. Frame payloads are at most 65536 bytes; receivers skip
frame types they do not know. When the shell exits the accepter sends
the exit status (`-1` when unknown, e.g. the session was ended) and
finishes the stream. The opener finishing its side ends the session.
Devices that cannot host a terminal (phones) answer `1`, and do not set
`["control", "1"]` in their adverts.

## Pairing QR codes

A QR code (or text) carries one device's address:

```
noscat:<npub>
noscat:<npub>?relay=<url>&relay=<url>
```

- The npub is NIP-19 bech32. Producers emit the lowercase `noscat:`
  prefix. Parsers MUST also accept a bare npub or hex key, and MUST
  ignore query parameters they do not know.
- `relay` (percent-encoded, repeatable) names a private mesh's relays. A
  device in a private mesh puts them in its QR; a device joining with
  such a code publishes its key package and join request there, logs in
  there (NIP-42) and waits for its invitation there, using no other
  relay.
- The payload is public. Scanning it lets the scanner invite the device
  or name it as the only device whose invitation to accept.

## Interoperability

- A Noscat mesh can invite a White Noise (or any MDK) account. It
  becomes a full member (admin included) and sees the mesh's messages;
  it does not use the data plane.
- A Noscat device can be invited into a White Noise group and exchange
  messages there.
- `tests/mdk-interop` in the reference implementation checks both
  directions against MDK's `wn` CLI.

## Security considerations

- Membership is authorization. A compromised member can add devices or
  remove the others; a mesh is for devices that trust each other.
- Removal is immediate on the data plane of every member that has
  processed the commit. A member that is offline keeps its old view until
  it catches up, but the removed device's MLS keys no longer decrypt
  anything new.
- Relays learn that a device publishes key packages and receives gift
  wraps, and which `h` routing ids it follows. They do not learn group
  membership, names or endpoints.
- Endpoints (IP addresses) are visible to other members only.
- Each device keeps its group state in one file written atomically with
  owner-only permissions. Anyone who reads it can act as that device.
- A member can do to a device only what that device's access rules
  allow it (see Access). Control is never on by default.
- File receivers bound what they accept (size limit, name rules) and
  never write outside their receive directory.

## Reference implementation

<https://github.com/Letdown2491/noscat> (Rust): `noscat-core` (data
plane, streams, Marmot group, device runtime, app protocols),
`noscat-client` (the UI layer) and the `noscat` CLI.
