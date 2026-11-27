# Noscat

*like netcat, but over your own device mesh: npub-addressed, end-to-end encrypted, no root, no accounts.*

Noscat joins your devices into a private mesh. Each device has its own
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
- everything runs in userspace on Linux, macOS, Windows, FreeBSD and
  Android; no root, no kernel module,
- it is written in Rust.

The noscat-specific protocol is specified in [`docs/nip-noscat.md`](docs/nip-noscat.md).

## Install

Noscat is a single binary, packaged for every major platform (the Linux
packages are static, with no dependencies): Linux (x86_64 and aarch64: deb, rpm, apk, and a live pacman
repository), macOS (Intel and Apple Silicon, via Homebrew with prebuilt
bottles), Windows (Scoop and winget, winget in community review), and
FreeBSD (a release tarball). Nix and cargo cover everything else
(`cargo install` on the BSDs waits on an upstream fix; INSTALL says how to
build there).

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

Every package ships shell completions (`noscat completions <bash|zsh|fish|powershell|elvish>`)
and a man page.

## Clients

The CLI is not the only way to use Noscat: the same protocol crate powers
native GUI clients:

- **[noscat-android](https://github.com/Letdown2491/noscat-android)**: native
  Kotlin (Compose) app over a Rust UniFFI bridge: chat, file send/receive,
  port forwards, clipboard sharing, terminals on the mesh's computers, and
  joining a mesh by scanning a member's QR.
- **[noscat-desktop](https://github.com/Letdown2491/noscat-desktop)**: pure
  Rust desktop app (GPUI), embedding `noscat-client` directly with no FFI
  layer: feature parity with the Android client plus expose/serve and
  hosting terminals for other members.

Neither app can create a mesh yet: a CLI device creates it. Once in, the
apps approve join requests like any member (Devices tab).

Both repos contain no protocol code; the wire format lives in this
workspace and is specified in the draft NIP above, so the clients are
interoperable by construction.

## Status

Version 0.7.0. The design decisions are in [`docs/adr/`](docs/adr/).

- `crates/noscat-core`: the library: `dataplane` (FIPS), `streams` (QUIC
  over FIPS), `marmot` (the mesh group), `device` (the runtime tying them
  to relays), `apps` (file transfer, text, TCP forwarding).
- `crates/noscat-client`: the UI-facing layer: one `Client` per device
  with an event stream. Graphical clients embed it.
- `crates/noscat-ffi`: UniFFI bindings over `noscat-client` for mobile
  apps (Kotlin today, Swift later).
- `crates/noscat`: the CLI: a terminal skin over `noscat-client`.

## Using the CLI

### The device

Each machine is one device. Its state (identity and mesh) lives in the
platform data directory (`~/.local/share/noscat` on Linux,
`~/Library/Application Support/noscat` on macOS, `%APPDATA%\noscat` on
Windows); `--dir` or `NOSCAT_DIR` picks another. `NOSCAT_IDENTITY` (hex
or nsec) supplies the identity instead of the stored file.

```
noscat id      # this device's npub and its QR (in a mesh, `noscat mesh qr`)
noscat up      # run it: receive files, chat, serve members (Ctrl-C to stop)
```

Only one process runs a device. While `noscat up` runs, every other
`noscat` command on the same directory goes through it; when nothing
runs, a command starts the device just for itself. If `noscat up` starts
while such a command still holds the device, it waits for it (up to 30 s)
instead of failing; a second `noscat up` fails at once.

### Running in the background

`noscat service install` keeps `noscat up` running at login, and at boot
on Linux, with whatever options you give it, global ones included:

```
noscat --reachable service install --to 127.0.0.1:22
noscat service status      # running? latest log lines
noscat service uninstall
```

On Linux it writes a systemd user unit (`~/.config/systemd/user/noscat.service`),
starts it, and enables lingering so it also runs at boot and after logout;
logs are in `journalctl --user -u noscat`. On macOS it is a launchd agent
logging to `~/Library/Logs/noscat.log`. Installing again replaces it.
While the service runs, every other `noscat` command goes through it.

Distribution packages also ship a plain user unit:
`systemctl --user enable --now noscat`, with options for `up` in
`~/.config/noscat/service.env` (`NOSCAT_UP_ARGS=--reachable`).
Homebrew's `brew services start noscat` runs a plain `noscat up`.

### A mesh

For a mesh that touches no third-party server at all (your own relay and
STUN on a small server), follow the step-by-step guide:
**[`docs/private-mesh.md`](docs/private-mesh.md)**. The quick version, on
public relays:

On the first device:

```
noscat mesh create home
noscat up --reachable          # this one has UDP 41641 forwarded, or a public address
```

On each new device:

```
noscat mesh join <pairing code or npub of a device in the mesh>
```

The pairing code is what `noscat mesh qr` (or `up`) prints on a member:
`noscat:<npub>`, plus the mesh's relays in a private mesh. `mesh join` prints the new device's npub and QR, sends the device it
names a join request and waits. On that device, `up` prints

```
# 🙋 laptop (npub1...) asks to join; type `invite npub1...` to add it
```

Type that and the new device is in. On a phone you scan the QR instead
of typing the npub. In the apps a request shows on the Devices tab with
Approve and Decline.

When `up` runs as a service there is no terminal to type into. Run
`noscat mesh requests` instead: it lists the devices that asked in the
last 15 minutes and asks y/n for each (a name is the device's own claim,
so check the npub on its screen). Not in a terminal, it only lists them.

To skip approving while you set up devices, run `noscat up --accept-joins`:
every device that asks is invited. A join request only needs this
device's npub, which is not secret (its key packages on relays carry it),
so leave the flag off once your devices are in.

Every member can invite and remove:

```
noscat mesh members            # who is in, names, presence, who is still joining
noscat mesh remove <npub>
noscat mesh leave              # this device leaves
```

**A shell on another device.** `noscat shell laptop` opens laptop's login
shell (cmd on Windows) in your terminal, as laptop's user. Laptop asks first (in its app)
unless it already allows you; a server with no app refuses until you run
`noscat allow <you> control` on it. On the host, `noscat sessions` lists
open sessions and `noscat sessions end <id>` ends one; each is logged in
`terminal.log` in the state directory.

**Who may do what.** Each device decides what every member may do to it,
in three groups: `send` (files, chat, clipboard), `services` (forwards)
and `control` (the terminal). Send and services are
allowed, as before; control asks on first use, and a device with no app
to answer (a server running `noscat up`) refuses it unless you allow it
ahead of time. The rules stay on the device; other members never see
them.

```
noscat access                      # the rules, and recent refused or asked requests
noscat allow laptop control        # a member by name or npub
noscat allow laptop control --once # just its next request (or the waiting one)
noscat deny everyone send          # the default for every member
noscat access reset laptop         # the defaults apply to it again
```

**Reachability.** Every mesh needs at least one member the others can
reach from the internet: a home server with a forwarded UDP port, a VPS,
anything with a public IPv6 address. Start it with `--reachable` (learn
the address by STUN) or `--reachable <ip:port>` (required in a private
mesh without STUN servers of its own); it listens on UDP 41641
unless `--listen` says otherwise. Members behind NAT reach
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

Each device has a name (`noscat name <new name>` saves one, `--name`
overrides it for a run, default the hostname; the desktop app uses the
hostname and the Android app the phone model, both changeable in
Settings) and sends it with its advert, inside the group, every two
minutes. A rename goes out at once, so members see it within seconds,
with no restart. A member is online while its latest advert is under ten minutes
old, and connected while data can reach it (a direct link or a live
connection; `noscat up` keeps one to every online member). Online but not
connected means it is on another network and no member is reachable from
the internet.

### Relays

**Run your own:** [noscat-relay](https://github.com/Letdown2491/noscat-relay)
is a members-only relay for one mesh. It carries only Noscat's events and
serves only your devices, so who is in the mesh, who gets invited and when
each device is online stay off third-party relays. Put it on the server that
runs your reachable member, then make the mesh private (below); the guide in
[`docs/private-mesh.md`](docs/private-mesh.md) walks through all of it.
Without one, Noscat uses public relays.

Relays carry only the mesh's encrypted control traffic (membership changes,
invitations, key packages, relay lists and presence adverts); data goes
device to device. By default Noscat uses three relays from different
operators: `wss://relay.snort.social`, `wss://relay.ditto.pub` and
`wss://nostr.mom`, chosen because each accepts every event kind Noscat uses
from a brand-new key, completes a join on its own, and is reachable from
mobile networks. A mesh also remembers the relays it was created with, and
members use both sets.

`--relay <url>` (repeatable) replaces the defaults, for example with your own
relay. Each relay connects in the background and is retried for as long as
the device runs, so one being down at start, or dropping later, costs
nothing: a publish goes to all of them and succeeds on the first that
accepts. Noscat sends each event once per relay (again only if that relay
was not connected), and republishes the device's relay lists only when they
change or once a week.

**A mesh's own relays, and private meshes.** Any member can change the
relays a mesh lists, and make it private:

```
noscat mesh relays                         # the mesh's relays, and whether it is private
noscat mesh relays add wss://relay.example
noscat mesh relays remove wss://nostr.mom
noscat mesh stun add 198.51.100.7:3478     # STUN from the mesh's own relay
noscat mesh private                        # devices use only the mesh's relays
noscat mesh shared                         # devices use their own relays too
```

In a private mesh every device uses only the mesh's relays, logs in to
them with its device key (NIP-42), and drops its own and the public ones.
That is meant for a members-only relay you run yourself, such as
noscat-relay. Noscat never logs in to any other relay. Add the relay
first and check members reach it, then go private. A private mesh's QR
(`noscat mesh qr`, or the one `up` prints) names its relays
(`noscat:<npub>?relay=wss%3A%2F%2F...`), so a new device that scans it
joins through them alone: from its first moment it uses only those relays,
so not even its key package reaches the public ones. (A `noscat up`
already running when `mesh join` is called has used its relays since it
started.)

STUN (how a device behind NAT learns its public address) comes from the
mesh too. noscat-relay answers it when started with `STUN_ADDR=":3478"`;
add it with `noscat mesh stun add <its ip>:3478`. A private mesh without
STUN servers of its own uses none, so no third party learns its devices'
addresses: they connect through the reachable member instead. A shared
mesh without any uses public STUN servers. Each device takes a new list
at its next start; `--stun` overrides it.

## Development

The project targets atomic/bootc hosts: there is no toolchain on the host, builds run
in a container (same pattern as our other projects).

```
# Build the dev image (once, and whenever containers/ changes):
podman build -t localhost/noscat-dev -f containers/noscat-dev.containerfile containers/

# Build / test (use :z, not :Z, on shared volumes on SELinux hosts):
podman run --rm -v noscat-cargo-home:/usr/local/cargo:z -v "$PWD:/work:Z" \
  -w /work localhost/noscat-dev sh -c "cargo test --workspace"

# A release binary at target/release/noscat (static builds come from CI):
podman run --rm -v noscat-cargo-home:/usr/local/cargo:z -v "$PWD:/work:Z" \
  -w /work localhost/noscat-dev cargo build --release -p noscat
```

Without a container, building on glibc Linux needs the libdbus and libclang
development packages (`libdbus-1-dev libclang-dev` on Debian and Ubuntu,
`dbus-devel clang-devel` on Fedora): the FIPS data plane links them for
its Bluetooth transport. macOS, Windows and musl builds need nothing extra.

Beyond `cargo test`, two harnesses check what unit tests cannot:
`tests/netrig/run.sh` (NAT and packet loss in network namespaces) and
`tests/mdk-interop/run.sh` (interop with White Noise's MDK).

## License

MIT
