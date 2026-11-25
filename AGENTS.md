# AGENTS.md

Guidance for AI agents working in this repo.

## What this project is

noscat: a Nostr-native, userspace device mesh. Membership is a Marmot (MLS)
group carried by Nostr relays; data goes device to device over FIPS with QUIC
streams on top. Packaged as a Rust CLI (`crates/noscat`) and reusable client
library (`crates/noscat-client`). `main` is 0.5.0, not released yet (the
last release is 0.4.3); `docs/plan-0.5.0.md` tracks what is left and
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
   - The release workflow (.github/workflows/release.yml) is the compile gate for
     all five targets; a tag push runs it. Local container has the Linux target
     only, so lean on cfg hygiene and CI for the rest.
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
  `device` (the runtime tying them to relays), `apps` (file, text, forward).
- `crates/noscat-client`: the reusable client: one `Client` per device,
  identity sources, mesh operations, an event stream, and the app operations
  (`up`/`expose`/`forward`/`send_file`/`send_chat`/stdio).
- `crates/noscat-ffi`: UniFFI bridge for mobile apps (Kotlin now, Swift later):
  `NoscatClient`, `Event` callback, identity and `mesh_*` functions (which use
  the app's running client for a directory, or run the device for the call).
  The Android app (`~/Documents/noscat-android`) builds it from this
  checkout (`scripts/build-native.sh local`) until 0.5.0 is published.
- `crates/noscat`: the CLI: a thin skin over the client. One process runs a
  device (`Client::start` locks the state directory); `control.rs` is the
  loopback channel every other command on that directory goes through.
  `tests/cli.rs` drives the real binary. The man page
  (`packaging/noscat.1`) is written by hand: a change to commands, flags or
  defaults updates it, README's CLI section and the `--help` text together.
- `docs/nip-noscat.md`: the wire protocol spec (the interop contract).
- `packaging/`: man page, nfpm, AUR prep (pinned at 0.1.1), winget (the
  0.1.1 submission), bottle script; `flake.nix` at the root;
  `.github/workflows/release.yml`: the whole release pipeline (builds,
  crates.io, tap, scoop, pacman).
- `containers/noscat-dev.containerfile`: the dev image (Rust plus the
  libdbus and libclang the FIPS crates need on glibc).
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
