# AGENTS.md

Guidance for AI agents working in this repo.

## What this project is

noscat: a Nostr-native, userspace device mesh. Membership is a Marmot (MLS)
group carried by Nostr relays; data goes device to device over FIPS with QUIC
streams on top. Packaged as a Rust CLI (`crates/noscat`) and reusable client
library (`crates/noscat-client`). Version 0.5.0; `docs/releasing.md` is the
release checklist, `docs/plan-0.5.0.md` the plan it came from, and
`docs/adr/` records why things are the way they are. Build/test in the
podman container only; the host has no toolchain:

```
podman run --rm -v noscat-cargo-home:/usr/local/cargo:z -v "$PWD:/work:Z" -w /work \
  localhost/noscat-dev sh -c "cargo test --workspace"
```

## Non-negotiable rules

1. **Cross-platform, always.** The CLI ships for Linux (glibc and musl), macOS
   (x86_64 and aarch64), Windows, and the BSDs (via `cargo install`; 0.5 waits
   on an upstream FIPS fix, issue #19, so keep BSD cfg hygiene anyway). Every change
   must compile and behave correctly on all of them:
   - No platform-specific code outside `#[cfg(...)]` branches with a fallback for
     the other platforms (see `IdentitySource::File` in `crates/noscat-client` for
     the pattern: unix 0600 file mode, plain write elsewhere).
   - Paths: never assume `/`-prefixed homes or `$HOME` alone; Windows-native
     environments set `USERPROFILE` and `APPDATA`, not `HOME` (see `default_dir`
     in `crates/noscat/src/main.rs`).
   - Unix-only APIs (file modes, symlinks, signals, fork) need a documented
     Windows/BSD fallback or a graceful degradation.
   - BSDs are tested only by compilation (`cargo install`); keep dependencies
     portable and avoid Linux-only crates (io_uring, procfs) unless gated.
   - CI (.github/workflows/ci.yml) is the compile gate for the release
     targets: it builds and tests Linux, macOS and Windows on every push to
     main. Check it after pushing (`gh run list --workflow ci.yml`); the
     local container has the Linux target only, so lean on cfg hygiene and
     CI for the rest.
2. **No em or en dashes anywhere in the repo, and no hyphen standing in for
   one** (" - " between words): use a colon, semicolon, comma or parentheses.
   Code comments, UI text, docs and commit messages alike.
3. **GitHub pushes go over SSH**: `git push git@github.com:Letdown2491/noscat.git main`.
   The stored HTTPS credential lacks the `workflow` scope.
4. **Versioning for releases**: bump the workspace version in Cargo.toml before
   tagging; the crates.io publish step refuses a tag/workspace mismatch and is
   idempotent on reruns. The crates.io token allowlists `noscat`, `noscat-core`,
   `noscat-client`, `noscat-ffi`; a new crate name needs a dashboard update
   before its first publish.
5. **Tests are offline.** They run against an in-process relay
   (`nostr-relay-builder` `MockRelay`) and loopback FIPS. `tests/mdk-interop`
   (MDK's `wn` CLI against noscat) and `tests/netrig` (network namespaces) are
   separate harnesses with their own `run.sh`; run them after touching the
   Marmot group or the data plane.

## Layout

- `API.md`: the app-facing API contract (`noscat-client` + `noscat-ffi`
  surfaces, event semantics, threading contracts). ANY change to a pub item
  of those two crates updates API.md in the same commit, even when only the
  semantics changed. The app-repo agents rely on it being current.

- `crates/noscat-core`: `dataplane` (FIPS), `streams` (QUIC over FIPS),
  `marmot` (the mesh group: `MeshGroup`, Marmot codecs, Nostr transport),
  `device` (the runtime tying them to relays, adverts, the mesh's STUN
  servers), `apps` (file, text, forward, terminal: the stream protocols),
  `access` (who may do what to this device: the send, services and control
  groups, rules in the device's sealed `access.json`).
- `crates/noscat-client`: the reusable client: one `Client` per device,
  identity sources, mesh operations, an event stream, and the app operations
  (`up`/`expose`/`forward`/`send_file`/`send_chat`/stdio), access (rules,
  asks answered by an app, `authorize` on every incoming stream) and
  terminals (`terminal.rs` hosts the PTY; `start_terminal` runs a viewer's
  stream for apps).
- `crates/noscat-ffi`: UniFFI bridge for mobile apps (Kotlin now, Swift later):
  `NoscatClient`, `Event` callback, identity and `mesh_*` functions (which use
  the app's running client for a directory, or run the device for the call).
  The Android app (`~/Documents/noscat-android`) builds it from this
  checkout (`scripts/build-native.sh local`) or a published version.
- `crates/noscat`: the CLI: a thin skin over the client. One process runs a
  device (`Client::start` locks the state directory); `control.rs` is the
  loopback channel every other command on that directory goes through
  (unrelated to the control access group); `shell.rs` is `noscat shell`,
  the raw-mode terminal on a member.
  `tests/cli.rs` drives the real binary. The man page
  (`packaging/noscat.1`) is written by hand: a change to commands, flags or
  defaults updates it, README's CLI section and the `--help` text together.
- `docs/nip-noscat.md`: the wire protocol spec (the interop contract).
- `packaging/`: man page, nfpm, the AUR package and winget manifests
  (templates the release workflow fills and attaches to each release),
  bottle script; `flake.nix` at the root;
  `.github/workflows/ci.yml`: build and test on every release platform
  for each push to main, plus a crates.io dry run;
  `.github/workflows/release.yml`: the whole release pipeline on a tag
  (builds, crates.io, tap, scoop, pacman, AUR and winget files).
- `containers/noscat-dev.containerfile`: the dev image (Rust plus the
  libdbus and libclang the FIPS crates need on glibc).
- `docs/plan-0.6.0.md`: next release, access and privacy: access
  groups (three trust groups, control asked on first use), a terminal
  into members that allow it, pairing codes and
  STUN for private meshes.
- `docs/plan-0.6.1.md`: BSD binaries (#19), the CLI only.
- `docs/plan-0.7.0.md`: Bluetooth on Linux and Android, relays through the
  mesh, splits and healing.
- `docs/plan-0.8.0.md`: macOS (desktop app and Bluetooth).
- `docs/plan-0.9.0.md`: viewing and controlling a member's screen (our own
  Rust implementation, royalty-free codecs).
- `docs/plan-no-dns.md`: unscheduled: private meshes with no DNS, no
  certificates and no URLs (QR carries npubs and addresses, relay over FIPS).
- `docs/releasing.md`: the release checklist across the repos, from the
  tag on (crates.io first, then the desktop drops its git patch, then the
  Android release APK).
- `docs/upstream/`: drafts of issues and patches for FIPS. Never post them
  without the user's approval.

## Related projects

Three repos build on this one. The two app repos, each with its own
AGENTS.md, carry no protocol code; protocol changes belong here, and API.md
is their contract:

- `~/Documents/noscat-android`: native Kotlin over `noscat-ffi`.
- `~/Documents/noscat-desktop`: GPUI in Rust, embedding `noscat-client`
  directly (from this repo's `main` through `[patch.crates-io]` until
  0.5.0 is published).

- `~/Documents/noscat-relay`: a members-only relay (Go, khatru) for one
  mesh. It reads its member list from `noscat mesh members` output (any
  npubs in it count), so keep npubs in that output; it serves only the
  event kinds noscat uses (445, 1059, 30443, 10050, 10002), so a new kind
  needs a relay change too.

All four repos work on their default branch (`main`; `master` for
noscat-android) and release in lockstep.
