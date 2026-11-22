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

Early prototype. See [research/](research/) for the deep dives that shaped the design
(FIPS, nostr-vpn, Marmot/MLS) and [research/00-synthesis.md](research/00-synthesis.md)
for the architecture write-up.

- `crates/noscat-core` — the library: identity, overlay adverts (FIPS kind-37195
  pattern), data plane and MLS tailnet control plane to come.
- `crates/noscat` — the CLI.

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
