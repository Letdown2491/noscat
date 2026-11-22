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

## Status

**Working MVP** — netcat-mode tunnels end to end: identity → relay advert → discovery →
Noise-XK handshake over UDP → stdio bridge. Verified live across two containers with
discovery through public relays (`wss://nos.lol`).

- `crates/noscat-core` — the library:
  - `identity` — one secp256k1 keypair is the Nostr identity and the mesh identity.
  - `advert` — signed, expiring endpoint advertisements (FIPS kind-37195 pattern),
    carrying the node's Noise static key, cryptographically bound to the npub by the
    event signature.
  - `relay` — publish/fetch/watch adverts over any relays you configure.
  - `noise` — Noise XK sessions (`snow`, curve25519 + ChaChaPoly). The Noise static key
    is derived from the identity secret via HKDF (a deliberate, documented deviation
    from FIPS's direct secp256k1 static; see the module docs).
  - `tunnel` — the data plane: one UDP datagram = one Noise message; stdio bridging
    with netcat-style half-close semantics.
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
discovery. `--identity <file>` (serve) and `--identity <nsec|hex>` (pipe) pin identities
across runs; by default they are ephemeral.

Also available: `noscat keygen`, `noscat advertise`, `noscat watch`.

### Roadmap (from [research/00-synthesis.md](research/00-synthesis.md))

- NAT traversal: STUN endpoint discovery + gift-wrapped kind-21059 signaling.
- `port-forward`/`serve` modes (arbitrary TCP services, not just stdio).
- Tailnet control plane: one MLS group per tailnet (Marmot component model),
  ACLs as GroupContext components.
- NIP draft.

See [research/](research/) for the deep dives that shaped the design (FIPS,
nostr-vpn, Marmot/MLS).

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
