# noscat

*like netcat, but over a Nostr-native mesh: npub-addressed tunnels, no root, no accounts.*

noscat gives every machine a self-generated Nostr identity (a keypair - no email, no
phone number, no account), and tunnels encrypted traffic between machines by that
identity. The data plane is direct end-to-end encryption over UDP with NAT hole
punching; Nostr relays are only ever the discovery/signaling channel, and any relay
you like will do.

Think `tailcat` (Tailscale's data plane without its control plane), but:

- the control plane is not a company - it is a Nostr event schema, so anyone can
  interoperate or self-host every piece,
- node identity *is* a Nostr identity, so addresses are people and agents, not blobs,
- it is written in Rust.

The wire protocol is specified in the draft NIP: [`docs/nip-noscat.md`](docs/nip-noscat.md).

## Install

noscat is a single static binary with no dependencies, packaged for every
major platform: Linux (x86_64 and aarch64 - deb, rpm, apk, and a live pacman
repository), macOS (Intel and Apple Silicon, via Homebrew with prebuilt
bottles), and Windows (Scoop and winget, winget in community review). Nix
and cargo cover everything else, including the BSDs from source.

**All installation options: [`INSTALL.md`](INSTALL.md)**

The two most people want:

Linux and macOS, into `~/.local/bin`:

```
curl -fsSL https://raw.githubusercontent.com/Letdown2491/noscat/main/packaging/install.sh | sh
```

or Homebrew, on macOS and Linux:

```
brew install Letdown2491/tap/noscat
```

Every package ships shell completions (`noscat completions <bash|zsh|fish|powershell>`)
and a man page.

## Status

**Working** - three layers, each verified live across containers over public relays
(`wss://relay.primal.net`, `wss://relay.nostr.com`, `wss://nostr.mom`):

1. **Tunnels** (netcat mode): identity → relay advert → discovery → Noise-XK handshake
   over UDP → stdio bridge, with STUN reflexive discovery and NIP-59 gift-wrapped
   (kind-21059) endpoint signaling + UDP hole punching.
2. **Mesh** (owned devices): an MLS group per mesh on OpenMLS -
   `mesh create/publish/invite/join`. Devices publish MLS key packages
   (kind 30443); invitations are NIP-59 gift-wrapped Welcomes (kind 30444).
3. **File transfer**: `send`/`receive` over the same tunnels, with an ACK +
   retransmit layer so large files survive socket-buffer overflow; a clean
   return means the whole file is on disk at the peer.

- `crates/noscat-core` - the library:
  - `identity` - one secp256k1 keypair is the Nostr identity and the mesh identity.
  - `advert` - signed, expiring endpoint advertisements (FIPS kind-37195 pattern),
    carrying the node's Noise static key, cryptographically bound to the npub by the
    event signature.
  - `relay` - publish/fetch/watch adverts, key packages, over any relays you configure.
  - `noise` - Noise XK sessions (`snow`, curve25519 + ChaChaPoly). The Noise static key
    is derived from the identity secret via HKDF (a deliberate, documented deviation
    from FIPS's direct secp256k1 static; see the module docs).
  - `stun` - hand-rolled RFC 5389 Binding requests (no extra dependency).
  - `traversal` - gift-wrapped candidate exchange and mesh message watching.
  - `mesh` - MLS group management; `export_secret` derives the epoch tunnel PSK.
  - `tunnel` - the data plane: one UDP datagram = one Noise message; session
    primitives (`dial_session`/`serve_session`/`bind_listener`) plus
    `TunnelStream` (the tunnel as a plain byte stream) for API consumers;
    stdio bridging with netcat-style half-close semantics; reliable file
    transfer on top.
- `crates/noscat-client` - the UI-facing layer: an owned runtime, config, and
  an event stream (`connect`/`listen` primitives, stdio/TCP/file composites).
  This is what graphical clients embed.
- `crates/noscat-ffi` - UniFFI bindings over `noscat-client` for mobile apps
  (Kotlin today, Swift via the same scaffolding later): the Android client
  consumes the published crate.
- `crates/noscat` - the CLI: a terminal skin over `noscat-client`.

### Try it

Machine A (the server; its npub and a scannable pairing QR print on start):

```
noscat serve
```

Machine B (dials A by npub - A's npub must be reachable: A's advert is published to
the default relays, so any relay B knows about works too):

```
echo hello | noscat pipe <A's npub>
```

Everything B types lands on A's stdout, encrypted, peer-to-peer; relays carry only the
discovery. Every data-plane command shares one node identity per machine:
the first run generates it and stores it at `~/.noscat/identity.hex` (mode 0600),
and later runs reuse it, so your npub is stable. Pass `--identity <file>` to
use another identity file. For scripting, `NOSCAT_IDENTITY` (hex or `nsec1...`)
carries a secret without putting it on argv, where `ps` and shell history
would leak it - secrets are never accepted as a command-line flag.

Also available: `noscat keygen`, `noscat advertise`, `noscat watch`.

### The node: `noscat up`

One command that stays running and does everything: prints its npub and a
scannable pairing QR, accepts any number of inbound peers, saves inbound files
to `~/Downloads` (or `--out`), bridges raw inbound tunnels to a local
service with `--to`, and gives you a chat terminal:

```
# requires a mesh: membership is the authorization for inbound connections
noscat up --mesh
noscat up --mesh --out ~/incoming --to 127.0.0.1:22
```

With `--to`, any inbound stream that is not a file transfer is forwarded to
that TCP address (SSH, a web server, anything); peers dial it with
`noscat pipe <npub>`. Without it, raw tunnels are dropped and only files are
accepted.

One networking note: if a peer's handshake times out from anywhere, check that
the node's UDP port (41641 by default) accepts inbound datagrams - on
firewalld, `firewall-cmd --add-port=41641/udp` (plus `--permanent` to keep it).

### Meshes (devices you own)

```
# On the owner (device A), once:
noscat mesh create

# On the joiner (device B):
noscat mesh publish     # publishes its MLS key package

# Back on the owner:
noscat mesh invite <B's npub>

# On the joiner (scan the owner's QR or copy their npub):
noscat mesh join --owner <A's npub>
```

The device directory defaults to `~/.noscat/device`; pass `--dir <path>` to
keep several devices on one machine.

Membership is policy-enforced MLS: the group context carries an ACL extension
naming the owner, and every member rejects commits from anyone else - even a
validly signed one. The owner can add more devices (`publish` + `invite`, one
per device) and remove them:

```
# On the owner:
noscat mesh members   # who is in, at which epoch
noscat mesh remove <B's npub>

# On the other members (picks up the owner's commit from the relays -
# live, plus a backfill of commits published while the device was
# offline, so a missed invite or removal still lands):
noscat mesh sync
```

Both devices now derive the same epoch PSK. Removing a device ratchets the
MLS epoch: the removed device's PSK goes stale immediately, so its handshakes
fail cryptographically even if it keeps trying. Scope any tunnel to the group
with `--mesh` - the handshake becomes `Noise_XKpsk0`, so only members
of the same mesh can complete it:

```
noscat serve --mesh
echo hi | noscat pipe <A's npub> --mesh
```

### Port forwarding

Expose any TCP service on one device; dial it by npub from another - like
`ssh -L`, but the tunnel is Nostr-native and (with `--mesh`) members-only:

```
# On the device with the service (A) - expose an SSH server, web app, anything:
noscat expose --to 127.0.0.1:22 --mesh

# On another device (B) - localhost:2222 now *is* A's port 22:
noscat forward <A's npub> --port 2222 --mesh
ssh -p 2222 localhost
```

Sessions are concurrent: the exposed side serves every peer from one shared
UDP port (datagrams are demuxed by source address), and each `forward`
connection dials its own tunnel - parallel `ssh`/`scp`/browser connections
just work. The `forward` listener binds loopback by default (pass
`--bind 0.0.0.0` to expose it on your LAN); anyone who can reach it can make
the device dial the target.

### File transfer

```
# Receiver (A):
noscat receive --out ./incoming --mesh

# Sender (B):
noscat send ./report.pdf <A's npub> --mesh
```

Transfers are resumable: an interrupted attempt leaves `report.pdf.noscat-part`
plus a sidecar recording how many chunks were acked, and the next
`send` of the same file picks up where the last one stopped - the sender is
told to skip ahead, and the finished file is verified against the sender's
sha256 before it lands under its real name.

### Chat

`noscat up` includes a terminal chat: incoming messages print as
`# 💬 <peer>: <text>`, and you reply by picking a peer and typing lines:

```
to                       # list the mesh's devices
to <npub prefix>         # pick a peer (a prefix works; 'to owner' too)
hello from the laptop    # every following line goes to them
clip                     # share your clipboard: it becomes theirs
```

The Android app's Chat tab is the same protocol: messages are one-shot
tunnels carrying a chat tag; delivery is confirmed when the peer echoes
the tunnel's half-close (the phone shows "delivered" then). Peers are
displayed by their friendly device name when known (see below).

### Device names

Each device can publish a friendly name with its advert: `up --name`, the
mesh app sends the phone's model, and the CLI defaults to the hostname.
Names show up in the chat terminal, the roster (`mesh members`), and the
Android device list; nothing depends on them (addresses stay npub-keyed).

### Presence

Nodes watch each other's advert refreshes on the relays, so the mesh shows
who is live: the `up` chat's `to` list marks each peer "seen 5s ago" or
"offline", `mesh members` prints the same from the freshest advert, and
the Android device list shows an online dot. A node republishes its own
advert at half the advert TTL with its current endpoints, so a network
switch (Wi-Fi to cellular) heals on the next refresh without a restart.
A peer counts as online while its advert arrived within the advert TTL
(an hour); relays dropping and reconnecting never clears what was seen.

## Development

The project targets atomic/bootc hosts: there is no toolchain on the host, builds run
in a container (same pattern as our other projects).

```
# Build the dev image (once, and whenever containers/ changes):
podman build -t localhost/noscat-dev -f containers/noscat-dev.containerfile containers/

# Build / test (the :Z on the cargo volume matters on SELinux hosts):
podman run --rm -v noscat-cargo-home:/usr/local/cargo:Z -v "$PWD:/work:Z" \
  -w /work localhost/noscat-dev sh -c "cargo test --workspace"

# Try the CLI:
podman run --rm -v noscat-cargo-home:/usr/local/cargo:Z -v "$PWD:/work:Z" \
  -w /work localhost/noscat-dev cargo run -p noscat -- keygen
```

## License

MIT
