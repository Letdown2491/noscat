# noscat

*like netcat, but over a Nostr-native mesh: npub-addressed tunnels, no root, no accounts.*

noscat gives every machine a self-generated Nostr identity (a keypair — no email, no
phone number, no account), and tunnels encrypted traffic between machines by that
identity. The data plane is direct end-to-end encryption over UDP with NAT hole
punching; Nostr relays are only ever the discovery/signaling channel, and any relay
you like will do.

Think `tailcat` (Tailscale's data plane without its control plane), but:

- the control plane is not a company — it is a Nostr event schema, so anyone can
  interoperate or self-host every piece,
- node identity *is* a Nostr identity, so addresses are people and agents, not blobs,
- it is written in Rust.

The wire protocol is specified in the draft NIP: [`docs/nip-noscat.md`](docs/nip-noscat.md).

## Status

**Working** — three layers, each verified live across containers over public relays
(`wss://nos.lol`, `wss://relay.primal.net`, `wss://nostr.mom`):

1. **Tunnels** (netcat mode): identity → relay advert → discovery → Noise-XK handshake
   over UDP → stdio bridge, with STUN reflexive discovery and NIP-59 gift-wrapped
   (kind-21059) endpoint signaling + UDP hole punching.
2. **Tailnet** (owned devices): an MLS group per tailnet on OpenMLS —
   `tailnet create/publish/invite/join`. Devices publish MLS key packages
   (kind 30443); invitations are NIP-59 gift-wrapped Welcomes (kind 30444).
3. **File transfer**: `send`/`receive` over the same tunnels, with an ACK +
   retransmit layer so large files survive socket-buffer overflow; a clean
   return means the whole file is on disk at the peer.

- `crates/noscat-core` — the library:
  - `identity` — one secp256k1 keypair is the Nostr identity and the mesh identity.
  - `advert` — signed, expiring endpoint advertisements (FIPS kind-37195 pattern),
    carrying the node's Noise static key, cryptographically bound to the npub by the
    event signature.
  - `relay` — publish/fetch/watch adverts, key packages, over any relays you configure.
  - `noise` — Noise XK sessions (`snow`, curve25519 + ChaChaPoly). The Noise static key
    is derived from the identity secret via HKDF (a deliberate, documented deviation
    from FIPS's direct secp256k1 static; see the module docs).
  - `stun` — hand-rolled RFC 5389 Binding requests (no extra dependency).
  - `traversal` — gift-wrapped candidate exchange and tailnet message watching.
  - `tailnet` — MLS group management; `export_secret` derives the epoch tunnel PSK.
  - `tunnel` — the data plane: one UDP datagram = one Noise message; stdio bridging
    with netcat-style half-close semantics; reliable file transfer on top.
- `crates/noscat` — the CLI.

### Try it

Machine A (the server; its npub is printed on start):

```
noscat serve --listen 0.0.0.0:41641
```

Machine B (dials A by npub — A's npub must be reachable: A's advert is published to
the default relays, so any relay B knows about works too):

```
echo hello | noscat pipe <A's npub>
```

Everything B types lands on A's stdout, encrypted, peer-to-peer; relays carry only the
discovery. `--identity <file>` (serve/receive) and `--identity <nsec|hex>` (pipe/send)
pin identities across runs; by default they are ephemeral.

Also available: `noscat keygen`, `noscat advertise`, `noscat watch`.

### Tailnets (devices you own)

```
# On the owner (device A), once:
noscat tailnet create --dir ./device-a

# On the joiner (device B):
noscat tailnet publish --dir ./device-b     # publishes its MLS key package

# Back on the owner:
noscat tailnet invite <B's npub> --dir ./device-a

# On the joiner:
noscat tailnet join --dir ./device-b
```

Membership is policy-enforced MLS: the group context carries an ACL extension
naming the owner, and every member rejects commits from anyone else — even a
validly signed one. The owner can add more devices (`publish` + `invite`, one
per device) and remove them:

```
# On the owner:
noscat tailnet members --dir ./device-a   # who is in, at which epoch
noscat tailnet remove <B's npub> --dir ./device-a

# On the other members (picks up the owner's commit from the relays):
noscat tailnet sync --dir ./device-c
```

Both devices now derive the same epoch PSK. Removing a device ratchets the
MLS epoch: the removed device's PSK goes stale immediately, so its handshakes
fail cryptographically even if it keeps trying. Scope any tunnel to the group
with `--tailnet <dir>` — the handshake becomes `Noise_XKpsk0`, so only members
of the same tailnet can complete it:

```
noscat serve --tailnet ./device-a
echo hi | noscat pipe <A's npub> --tailnet ./device-b
```

### Port forwarding

Expose any TCP service on one device; dial it by npub from another — like
`ssh -L`, but the tunnel is Nostr-native and (with `--tailnet`) members-only:

```
# On the device with the service (A) — expose an SSH server, web app, anything:
noscat expose --to 127.0.0.1:22 --tailnet ./device-a

# On another device (B) — localhost:2222 now *is* A's port 22:
noscat forward <A's npub> --port 2222 --tailnet ./device-b
ssh -p 2222 localhost
```

### File transfer

```
# Receiver (A):
noscat receive --out ./incoming --tailnet ./device-a

# Sender (B):
noscat send ./report.pdf <A's npub> --tailnet ./device-b
```

Transfers are resumable: an interrupted attempt leaves `report.pdf.noscat-part`
plus a sidecar recording how many chunks were acked, and the next
`send` of the same file picks up where the last one stopped — the sender is
told to skip ahead, and the finished file is verified against the sender's
sha256 before it lands under its real name.

### Roadmap

- ~~Transfer throughput (sliding-window ACKs) and resume.~~ (done)
- ~~Multi-member tailnets with ACL policy as Marmot GroupContext components.~~ (done)
- ~~Real MLS storage profile (SQLite) to replace the spike-grade memory serialization.~~ (done)
- ~~NIP draft.~~ (drafted: `docs/nip-noscat.md`)

## Development

The project targets atomic/bootc hosts: there is no toolchain on the host, builds run
in a container (same pattern as our other projects).

```
# Build the dev image (once, and whenever containers/ changes):
podman build -t localhost/noscat-dev -f containers/noscat-dev.containerfile containers/

# Build / test:
podman run --rm -v "$PWD:/work:Z" -w /work localhost/noscat-dev cargo build --workspace
podman run --rm -v "$PWD:/work:Z" -w /work localhost/noscat-dev cargo test --workspace

# Try the CLI:
podman run --rm -v "$PWD:/work:Z" -w /work localhost/noscat-dev cargo run -p noscat -- keygen
```

## License

MIT
