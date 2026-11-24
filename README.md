# noscat

*like netcat, but over your own device mesh: npub-addressed, end-to-end encrypted, no root, no accounts.*

noscat joins your devices into a private mesh. Each device has its own
self-generated Nostr identity (a keypair: no email, no phone number, no
account). Membership is a [Marmot](https://github.com/marmot-protocol)
group (MLS, the IETF group-encryption standard) carried by Nostr relays,
so every member can verify who is in the mesh and any member can manage
it. Data goes device to device over [FIPS](https://github.com/jmcorgan/fips),
an end-to-end encrypted overlay keyed by those same identities, with
QUIC streams on top. Relays never see who is in a mesh, names,
addresses or data.

Think Tailscale, but:

- the control plane is not a company: it is Marmot over any Nostr relays,
  so anyone can interoperate or self-host every piece (a White Noise
  account can even be invited into a mesh),
- there is no coordinator and no single owner: lose any device and the
  mesh carries on,
- everything runs in userspace on Linux, macOS, Windows, the BSDs and
  Android; no root, no kernel module,
- it is written in Rust.

The noscat-specific protocol is specified in [`docs/nip-noscat.md`](docs/nip-noscat.md).

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

## Clients

The CLI is not the only way to use noscat - the same protocol crate powers
native GUI clients:

- **[noscat-android](https://github.com/Letdown2491/noscat-android)** - native
  Kotlin (Compose) app over a Rust UniFFI bridge: chat, file send/receive,
  port forwards, and mesh join by invite.
- **[noscat-desktop](https://github.com/Letdown2491/noscat-desktop)** - pure
  Rust desktop app (GPUI), embedding `noscat-client` directly with no FFI
  layer: feature parity with the Android client plus expose/serve.

Both repos contain no protocol code - the wire format lives in this
workspace and is specified in the draft NIP above, so the clients are
interoperable by construction.

## Status

0.5.0 is a rewrite on FIPS and Marmot and does not talk to 0.4. It starts
fresh: no 0.4 state or identity is read (0.5 keeps its state in a new
place), so recreate the mesh after upgrading every device.

- `crates/noscat-core` - the library: `dataplane` (FIPS), `streams` (QUIC
  over FIPS), `marmot` (the mesh group), `device` (the runtime tying them
  to relays), `apps` (file transfer, text, TCP forwarding).
- `crates/noscat-client` - the UI-facing layer: one `Client` per device
  with an event stream. Graphical clients embed it.
- `crates/noscat-ffi` - UniFFI bindings over `noscat-client` for mobile
  apps (Kotlin today, Swift later).
- `crates/noscat` - the CLI: a terminal skin over `noscat-client`.

## Using the CLI

### The device

Each machine is one device. Its state (identity and mesh) lives in the
platform data directory (`~/.local/share/noscat` on Linux,
`~/Library/Application Support/noscat` on macOS, `%APPDATA%\noscat` on
Windows); `--dir` or `NOSCAT_DIR` picks another. `NOSCAT_IDENTITY` (hex
or nsec) supplies the identity instead of the stored file.

```
noscat id      # this device's npub and pairing QR
noscat up      # run it: receive files, chat, serve members (Ctrl-C to stop)
```

Only one process runs a device. While `noscat up` runs, every other
`noscat` command on the same directory goes through it; when nothing
runs, a command starts the device just for itself.

### A mesh

On the first device:

```
noscat mesh create home
noscat up --reachable          # this one has a forwarded UDP port or a public address
```

On each new device:

```
noscat mesh join <npub of a device in the mesh>
```

`mesh join` prints the new device's npub and QR, sends the device it
names a join request and waits. On that device, `up` prints

```
# 🙋 laptop (npub1...) asks to join; type `invite npub1...` to add it
```

Type that (or run `noscat mesh invite <npub>` from another terminal) and
the new device is in. In the apps, the join request is a prompt; on a
phone you scan the QR instead of typing the npub.

Every member can invite and remove:

```
noscat mesh members            # who is in, names and presence
noscat mesh remove <npub>
noscat mesh leave              # this device leaves
```

**Reachability.** Every mesh needs at least one member the others can
reach from the internet: a home server with a forwarded UDP port, a VPS,
anything with a public IPv6 address. Start it with `--reachable` (learn
the address by STUN) or `--reachable <ip:port>`. Members behind NAT reach
each other directly where they can and through that member otherwise.
Members on the same LAN find each other by mDNS.

### Sending things

Targets are npubs (or `noscat:` URIs from a QR). Only members can be
reached, and only members can reach you.

```
noscat send ./report.pdf <npub>        # resumes if interrupted; verified by sha256
noscat chat <npub> lunch at noon?
noscat clip <npub>                     # your clipboard becomes theirs
```

Received files go to `~/Downloads` (`up --out <dir>` changes it).

### Ports

A member's *default service* is whatever it exposes:

```
noscat up --to 127.0.0.1:22                # or: noscat expose --to 127.0.0.1:22
noscat forward <npub> --port 2222          # on another member; then: ssh -p 2222 localhost
```

A member can also allow specific local ports, which others reach by
number:

```
noscat up --serve-port 8080
noscat forward <npub> --port 9000 --remote-port 8080
```

### Netcat mode

```
noscat serve                       # on A: bridges the first member stream to stdio
echo hello | noscat pipe <A's npub>
```

### Chat

`noscat up` includes a terminal chat: incoming messages print as
`# 💬 <name>: <text>`, and you reply by picking a member and typing:

```
to                       # list members
to laptop                # pick one by name or npub prefix
hello from the server    # every following line goes to them
clip                     # share your clipboard
invite <npub>            # add a device that asked to join
```

### Names and presence

Each device has a name (`--name`, default the hostname; the apps use the
device model) and sends it with its advert, inside the group, every two
minutes. A member is online while its latest advert is under ten minutes
old.

## Development

The project targets atomic/bootc hosts: there is no toolchain on the host, builds run
in a container (same pattern as our other projects).

```
# Build the dev image (once, and whenever containers/ changes):
podman build -t localhost/noscat-dev -f containers/noscat-dev.containerfile containers/

# Build / test (use :z, not :Z, on shared volumes on SELinux hosts):
podman run --rm -v noscat-cargo-home:/usr/local/cargo:z -v "$PWD:/work:Z" \
  -w /work localhost/noscat-dev sh -c "cargo test --workspace"

# Try the CLI:
podman run --rm -v noscat-cargo-home:/usr/local/cargo:z -v "$PWD:/work:Z" \
  -w /work localhost/noscat-dev cargo run -p noscat -- id
```

## License

MIT
