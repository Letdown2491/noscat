# NIP-draft: noscat - Nostr-native userspace mesh tunnels

`draft` `optional` `relay` `encryption`

---

## Abstract

This NIP specifies **noscat**, a protocol for establishing peer-to-peer data
tunnels between a user's own devices, using Nostr purely as the control
plane. Two devices discover each other through relay-stored adverts,
establish a direct Noise-protected UDP transport out-of-band, and scope
membership to a user's device set ("mesh") with an MLS (RFC 9420) group
whose epoch secret doubles as the tunnel handshake PSK.

Nostr relays carry only discovery metadata and MLS control messages. Data
plane traffic never touches a relay.

## Motivation

Mesh VPNs (Tailscale, WireGuard-based overlays) require an account, a
coordinating daemon, and root privileges. Every Nostr user already holds a
cryptographic identity that follows them across devices and relays. This NIP
reuses that identity to:

1. advertise reachable endpoints for direct connections,
2. form an MLS group over a user's devices so membership *is* authorization,
3. derive a shared epoch PSK so tunnel handshakes fail cryptographically for
   removed devices.

Everything runs in userspace; no root, no coordinator, no account.

## Conventions

- The key words SHALL, SHOULD, and MAY are to be interpreted as described in
  RFC 2119.
- All JSON is minified, all hex is lowercase.
- "MLS" refers to RFC 9420. The reference ciphersuite is
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; clients MUST support it and
  MAY support others.
- "Identity" means a secp256k1 keypair in the standard Nostr sense (npub/nsec).

## Overview

```
                    ┌────────────┐
                    │   relays   │   control plane only:
                    └─────┬──────┘   adverts, key packages,
              kind 37195 /│30443/30444 (gift-wrapped)
        ┌─────────────────┴─────────────────┐
        │                                   │
   ┌────▼─────┐   Noise XK / XKpsk0, UDP  ┌─▼────────┐
   │ device A │◄──────────────────────────►│ device B │
   └──────────┘     data plane             └──────────┘
```

| Purpose | Kind | Scope |
|---|---|---|
| Endpoint advert | `37195` | public (parameterized replaceable) |
| MLS key package | `30443` | public (parameterized replaceable) |
| Mesh message (Welcome / commit) | `30444` | inside a NIP-59 gift wrap |
| Tunnel data | - | Noise XK over UDP, direct |

## Endpoint adverts (kind 37195)

A device that wants to accept connections publishes a **parameterized
replaceable** event, kind `37195`, with a `d` tag naming the advert slot
(`"noscat-overlay-v1"` in the reference implementation) and an `expiration`
tag. The content is JSON:

```json
{
  "noise_pub": "<hex curve25519 static public key>",
  "endpoints": [
    { "transport": "udp", "addr": "203.0.113.7:51820" },
    { "transport": "tcp", "addr": "203.0.113.7:443" }
  ]
}
```

The `noise_pub` field MUST be the Noise static public key derived from the
author's identity secret as follows: the static private key is
`HKDF-SHA256(salt = "noscat", ikm = identity-secret-bytes, info =
"noscat/noise-static-v1", L = 32)`, and the public half is the RFC 7748
X25519 base-point scalar multiplication of the standard-clamped private
key. This binds the Noise static key to the npub through the event
signature; peers MUST verify the derivation and reject adverts that do not
match.

Endpoints are candidates only: peers race them with a STUN-like
transaction-id handshake and keep the first that authenticates, falling back
to relay-reflected candidates for NAT traversal (out of scope here).

## Meshes

A **mesh** is one MLS group whose GroupId is the owner's npub (32 raw
bytes). It is the unit of membership and authorization for the tunnels
between a user's devices.

### Policy extension (0xffa0)

The group context of a mesh SHALL carry exactly one custom extension of
type `0xffa0` (private-use range, RFC 9420 §13.6). Its extension data is
JSON:

```json
{ "owner": "<hex npub bytes of the owner>" }
```

Every member SHALL enforce this policy at commit-merge time: a commit whose
sender credential identity is not the `owner` MUST NOT be merged, even
though it is validly signed and MLS-legal. This makes the owner the only
principal able to add or remove devices, without extending MLS itself.

Clients advertising membership in such a group MUST include extension type
`0xffa0` in the capabilities of their leaf nodes (key packages and update
paths), because add proposals and commit paths are validated against the
group context extensions.

### Key packages (kind 30443)

A device publishes a parameterized replaceable event, kind `30443`, with `d`
tag `"noscat-mesh-kp-v1"` and content being the **hex-encoded
TLS-serialized MLS KeyPackage** (the bundle's private init keys stay in the
publisher's local storage - only the publisher can decrypt the Welcome later).

The event is public but reveals only the publisher's intent to join *some*
mesh. The owner fetches it, commits an Add, and sends the Welcome.

### Mesh messages (kind 30444, gift-wrapped)

All group-control messages travel as NIP-59 gift wraps. The gift-wrapped
**rumor** is an unsigned event of kind `30444`, authored by the sender's real
key, with JSON content:

```json
{
  "commit": "<hex TLS-serialized MlsMessageOut carrying the commit>",
  "welcome": "<hex TLS-serialized MlsMessageOut carrying the Welcome>",
}
```

- `welcome` is present only in the message addressed to the newly invited
  device.
- `commit` alone is fanned out to every other member so the whole group
  ratchets into the same epoch.

Receivers:

1. Unwrap the gift wrap (NIP-59), then decrypt/verify the MLS message
   locally.
2. If the message contains a Welcome and the receiver is not yet in a
   mesh, it joins from the Welcome and merges the accompanying commit.
3. If the message contains only a commit, the receiver processes it: the
   sender credential MUST pass the policy extension check, then the commit
   is merged.
4. A commit whose epoch does not match the receiver's current epoch (e.g. a
   relay replay of an older commit) MUST be skipped, not merged.

The gift wrap SHOULD carry an `expiration` tag of at most 7 days: commits
are only meaningful for a short window, and stale Welcomes would let a
device join a group it may have since been removed from.

### Epoch PSK and tunnel binding

Every member derives the mesh's current tunnel key with the MLS exporter:

```
psk = MLS-Exporter("noscat/tunnel-psk-v1", "", 32)
```

Tunnel handshakes are Noise pattern `Noise_XKpsk0_25519_ChaChaPoly_SHA256`
(where the base pattern is `Noise_XK_25519_ChaChaPoly_SHA256`) with `psk` as
psk0. Consequences:

- Only group members of the same epoch can complete a handshake.
- **Removal ratchets the epoch**: when the owner commits a Remove and the
  remaining members merge it, a new exporter secret is derived. The removed
  device's PSK is stale immediately; its handshakes fail cryptographically
  even though it still holds old group state.

Removal of a device therefore requires no notification to the removed
device: it is locked out by the ratchet itself.

## File transfer framing

File transfer (`send`/`receive`) rides any established session - mesh-
scoped or not - as a small tagged protocol on top of the Noise transport.
One Noise message = one UDP datagram, and the session's Noise nonces advance
strictly sequentially and never appear on the wire; every reliability
mechanism below is built on replaying *previously transmitted ciphertexts*
(re-encryption would produce a nonce the peer cannot decrypt).

Exactly one transfer runs per session. All integers are big-endian.

### Message types

Every plaintext payload begins with a one-byte type tag:

| Tag | Name | Payload | Direction |
|---|---|---|---|
| `0x01` | HEADER | JSON, below | sender → receiver |
| `0x02` | CHUNK | u32 seq + ≤1200 bytes | sender → receiver |
| `0x03` | ACK | u32 next-expected-seq | receiver → sender |
| `0x04` | FIN | (empty) | sender → receiver |
| `0x05` | RESUME | u32 next-expected-seq | receiver → sender |

An authenticated frame smaller than 21 bytes MUST be treated as junk and
dropped: the only datagrams that fail to decrypt below that size are
traversal punch markers, which carry no transfer state.

### HEADER

The sender opens with a HEADER whose plaintext, after the tag, is minified
JSON:

```json
{
  "name": "report.pdf",
  "len": 104857600,
  "sha256": "7d6b56faef7f6fc4b07c9e84a3b7505d21383ca0d6c58ab1479b5e56e2a56dfc"
}
```

- `name` is only a filename (no path separators); receivers MUST sanitize it
  before joining it to their output directory.
- `len` is the file size in bytes.
- `sha256` is the lowercase-hex SHA-256 of the *whole* file. It is the
  transfer's identity: a receiver-held partial file is resumed only when its
  recorded `(len, sha256)` match, and the finished file is verified against
  it before being published under its real name.

The sender repeats the HEADER (same ciphertext) on a short retry budget. Any
authenticated reply proves the receiver is listening; losing the reply is not
fatal, because chunk ACKs re-ack the header implicitly.

The receiver answers with a **RESUME** frame carrying its resume point: the
number of complete chunks it already holds durably from a previous
interrupted attempt with the same `(len, sha256)`, or `0`. RESUME MAY equal
the total chunk count (the previous attempt wrote everything but died before
confirming), in which case the sender proceeds directly to the FIN exchange.

### CHUNK phase

The file is split into `total = ceil(len / 1200)` chunks of at most 1200
bytes (MTU-sized: one datagram is one loss unit, and a full window burst -
about 39 KiB - fits inside default kernel socket buffers). Chunk `i` covers
bytes `[i·1200, min(len, (i+1)·1200))`, and its frame payload is
`u32 seq` + the raw bytes. Sequences start at the resume point.

The sender keeps up to 32 chunks in flight. A chunk unacked after 400 ms is
retransmitted - by replaying the *same ciphertext*, never re-encrypting -
and after 120 failed retries per chunk the transfer is abandoned. The
receiver writes chunks strictly in order: because snow only decrypts frames
in nonce order and the sender emits seqs in nonce order, every frame that
decrypts *is* the next expected chunk; frames beyond a gap are undecryptable
and skipped.

The receiver ACKs cumulatively - "I expect seq *n* next" - only at window
boundaries and at the final chunk. Every ack is a fresh Noise message the
sender must consume in order, so a lost ack makes later acks undecryptable
until a replay fills the nonce gap; the receiver therefore keeps a bounded
history of recent ack ciphertexts and replays it (a) periodically, and (b)
immediately whenever the sender's retransmissions show it is stuck. On the
sender side, acks with `seq` below the highest seen are stale replays and
ignored.

### FIN and completion

After the last chunk the sender sends FIN and waits until either a
cumulative ack reaches `total` or the receiver FINs back. The receiver,
having flushed the file to disk, verifies the streamed bytes (including any
resumed prefix) against the HEADER's `sha256`; only on a match does it
rename the partial into place, and it then answers every sender replay with
its FIN plus ack history for a linger period (10 s in the reference
implementation) so the sender's wait always resyncs and completes only after
the file is truly on disk. A sha256 mismatch or an incomplete transfer MUST
leave the partial file (and its resume state) in place for the next attempt.

### Resume state (receiver-local)

Receivers persist, next to the partial file `<name>.noscat-part`, a sidecar
recording `(len, sha256, acked-chunk-count)`, refreshed at every window-
boundary ack *after* the flush. This sidecar is local state, never on the
wire. On the next HEADER:

- If the sidecar's `(len, sha256)` matches and the partial file holds at
  least the recorded chunk count, resume: seed the running sha256 with the
  durable prefix, append from there, and answer RESUME with the recorded
  count.
- Otherwise discard the partial and start from scratch.

Senders SHOULD refuse transfers whose chunk count would exceed
`u32::MAX` (about 5 TiB at 1200-byte chunks).

## One-shot streams

A node (`up`) dispatches each accepted session by its first plaintext byte
(stream-type tag) before any other interpretation:

| Tag | Name | Payload | Semantics |
|---|---|---|---|
| `0x01` | HEADER | (see File transfer framing) | a file transfer; the session becomes the transfer protocol above |
| `0x06` | CHAT | UTF-8 text | a one-shot chat message |
| `0x07` | CLIP | UTF-8 text | a clipboard share |
| any other | raw | unconstrained | bridged to the node's configured local service, if any; dropped otherwise |

For CHAT and CLIP the sender writes the tag followed by the UTF-8 payload,
then half-closes its end (FIN). The receiver reads to that FIN, delivers the
text (display, clipboard), and echoes its own FIN as the delivery
confirmation - the sender's wait for that FIN is what a UI reports as
"delivered". Receivers MUST tolerate any payload size by reading to the FIN
rather than a fixed length, and MUST treat invalid UTF-8 as a failed delivery.
There is exactly one one-shot stream per session; a new message dials a new
session.

## Pairing QR codes

Client UIs exchange peer addresses with QR codes. The QR payload is a URI
in the `noscat` scheme:

```
noscat:<npub>
```

For example:

```
noscat:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6
```

Rules:

- The only required payload is the peer's npub (bech32, per Nostr NIP-19).
  Everything else a client needs to dial - relays, mesh, endpoints -
  comes from the scanner's own configuration and the peer's published
  advert; the QR never carries endpoints or keys.
- Producers MUST emit the scheme prefix in lowercase. Parsers MUST accept
  a bare npub (no prefix) too, since users paste npubs as text, and MUST
  ignore unknown parameters if any are ever added
  (`noscat:<npub>?k=v` is reserved for future use).
- Parsers SHOULD validate the bech32 charset but need not verify the
  checksum; dialing validates the key against the relay-resolved advert
  anyway, and a bad npub fails there with a clear error.
- QR displays SHOULD let the peer show the payload as text as well, so
  devices without cameras can still copy-paste it.

The payload is public data: an npub is a public key, and scanning it only
allows reaching the device through the Noise-XK handshake, which
authenticates the scanner to the holder just as any other dial would.

## Client behavior summary

1. `advert`: publish/refresh kind `37195` with endpoints and `noise_pub`.
2. `key-package`: publish/refresh kind `30443`.
3. `create`: create the MLS group with the `0xffa0` policy extension.
4. `invite`: fetch the invitee's kind-30443 event, commit the Add, send the
   Welcome gift-wrapped to the invitee and the bare commit to all other
   members.
5. `join` / `sync`: subscribe to gift wraps addressed to the device's npub;
   process per the receiver rules above. `sync` first fetches stored gift
   wraps from the relays (they persist for their expiration) and merges
   them oldest-epoch first, so a device that missed a live commit catches
   up instead of staying stranded at the old epoch; replays of
   already-merged commits MUST be skipped, never fatal.
5a. `resend` (owner): re-gift-wrap the owner's recent commits to all (or
   one) members. Commit fan-out SHOULD treat a relay `OK` acknowledgement
   as delivery and retry failures before reporting success; a wrap stored
   by no relay is unrecoverable by backfill, so owners SHOULD keep the
   last commits they merged and re-publish them on request. Replays are
   safe: receivers skip commits at or below their epoch.
6. `serve`/`pipe`/`connect`: resolve the peer's advert, establish the Noise
   session (XKpsk0 when a mesh is in scope), and pump bytes.
7. `send`/`receive`: run the file-transfer framing above over the session;
   interrupted transfers resume from the receiver's durable point.
8. `up` (node): dispatch accepted sessions by stream-type tag per One-shot
   streams above (file / chat / clipboard / raw bridge), and answer join
   requests: watch kind-30443 key packages, confirm each requester, then
   commit the Add and send the Welcome gift-wrapped to that requester alone.
   It also subscribes to advert refreshes (kind 37195) to track which
   mesh-mates are live: a member is online while an advert arrived within
   the advert TTL.
9. `chat` / `clipboard`: dial a fresh session, write the one-shot tag plus
   UTF-8 payload, half-close, and treat the peer's echoed FIN as delivery.

## Security Considerations

- **Relay visibility.** Adverts and key packages are public but contain no
  secrets: a Noise static public key and an MLS key package. Mesh
  messages are double-wrapped (NIP-59): relays see only an ephemeral sender
  and the receiver npub.
- **Policy enforcement is cooperative.** The `0xffa0` check runs at
  merge time on honest members. A malicious member could technically merge a
  non-owner commit locally, but it gains nothing: the attacker cannot
  produce the removed device's ratchet and can only lock itself out. Future
  work may add `RequiredCapabilities`-style enforcement or an
  external-commit path so even this is impossible.
- **Single-owner meshes.** This draft specifies owner-only administration.
  Multi-owner or quorum policies can extend the `0xffa0` JSON with a rule
  list; the extension format is versioned by the `d`-tag slot name.
- **Replay.** Old commits replayed from relays are rejected by the epoch
  check (rule 4). Old Welcomes are bounded by the gift-wrap expiration and
  by the ratchet: joining from a stale Welcome yields a stale PSK that
  fails every handshake.
- **Key package hygiene.** Publishers SHOULD use fresh key packages with a
  bounded lifetime and republish on a schedule; the parameterized
  replaceable kind makes the latest one authoritative.
- **Transfer authenticity and integrity.** The transfer header travels
  inside the Noise channel, so its `sha256` and `name` are authenticated
  against the sender's static key - a man-in-the-middle cannot substitute a
  file or name. The sha256 additionally catches corruption and partial
  writes below the Noise layer (crashes between write and finalize); a
  mismatched finished file is never renamed into place.
- **Resume state is not attacker-controlled across files.** A partial file
  is only continued when its recorded `(len, sha256)` matches the new
  header, so a stale or hostile sidecar cannot splice bytes from one file
  into another; worst case it forces a fresh transfer. The sidecar lives
  next to the output and is never transmitted.
- **Replay within a transfer.** Replayed ciphertexts are load-bearing (they
  are how lost frames and acks recover) and safe: snow rejects replayed
  nonces with a decrypt failure, which the receiver answers by replaying
  its ack history, never by re-processing the frame.

## Reference implementation

A complete userspace implementation in Rust lives at
<https://github.com/Letdown2491/noscat> (crates `noscat-core`:
`mesh.rs`, `advert.rs`, `noise.rs`, `traversal.rs`, `tunnel.rs` - the
last of which implements the transfer framing above). It builds on
OpenMLS 0.8 and nostr-tools-compatible kinds (Marmot's key-package slot).
