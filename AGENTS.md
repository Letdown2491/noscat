# AGENTS.md

Guidance for AI agents working in this repo.

## What this project is

noscat: a Nostr-native, userspace device mesh. Membership is a Marmot (MLS)
group carried by Nostr relays; data goes device to device over FIPS with QUIC
streams on top. Packaged as a Rust CLI (`crates/noscat`) and reusable client
library (`crates/noscat-client`). `docs/plan-0.5.0.md` tracks the 0.5.0
rewrite and `docs/adr/` records why things are the way they are. Build/test in the podman container only; the host has no
toolchain:

```
podman run --rm -v noscat-cargo-home:/usr/local/cargo:z -v "$PWD:/work:Z" -w /work \
  localhost/noscat-dev sh -c "cargo test --workspace"
```

## Non-negotiable rules

1. **Cross-platform, always.** The CLI ships for Linux (glibc and musl), macOS
   (x86_64 and aarch64), Windows, and the BSDs (via `cargo install`). Every change
   must compile and behave correctly on all of them:
   - No platform-specific code outside `#[cfg(...)]` branches with a fallback for
     the other platforms (see `IdentitySource::File` in `crates/noscat-client` for
     the pattern: unix 0600 file mode, plain write elsewhere).
   - Paths: never assume `/`-prefixed homes or `$HOME` alone; Windows-native
     environments set `USERPROFILE`, not `HOME` (see `default_identity` in
     `crates/noscat/src/main.rs`).
   - Unix-only APIs (file modes, symlinks, signals, fork) need a documented
     Windows/BSD fallback or a graceful degradation.
   - BSDs are tested only by compilation (`cargo install`); keep dependencies
     portable and avoid Linux-only crates (io_uring, procfs) unless gated.
   - The release workflow (.github/workflows/release.yml) is the compile gate for
     all five targets; a tag push runs it. Local container has the Linux target
     only, so lean on cfg hygiene and CI for the rest.
2. **No em dashes anywhere in the repo** (plain hyphens instead).
3. **GitHub pushes go over SSH**: `git push git@github.com:Letdown2491/noscat.git main`.
   The stored HTTPS credential lacks the `workflow` scope.
4. **Versioning for releases**: bump the workspace version in Cargo.toml before
   tagging; the crates.io publish step refuses a tag/workspace mismatch and is
   idempotent on reruns. The crates.io token allowlists `noscat`, `noscat-core`,
   `noscat-client`, `noscat-ffi` - a new crate name needs a dashboard update
   before its first publish.
5. **Tests are offline.** They run against an in-process relay
   (`nostr-relay-builder` `MockRelay`) and loopback FIPS. `tests/mdk-interop`
   (MDK's `wn` CLI against noscat) and `tests/netrig` (network namespaces) are
   separate harnesses with their own `run.sh`; run them after touching the
   Marmot group or the data plane.

## Layout

- `API.md` - the app-facing API contract (`noscat-client` + `noscat-ffi`
  surfaces, event semantics, threading contracts). ANY change to a pub item
  of those two crates updates API.md in the same commit, even when only the
  semantics changed. The app-repo agents rely on it being current.

- `crates/noscat-core` - `dataplane` (FIPS), `streams` (QUIC over FIPS),
  `marmot` (the mesh group: `MeshGroup`, Marmot codecs, Nostr transport),
  `device` (the runtime tying them to relays), `apps` (file, text, forward).
- `crates/noscat-client` - the reusable client: one `Client` per device,
  identity sources, mesh operations, an event stream, and the app operations
  (`up`/`expose`/`forward`/`send_file`/`send_chat`/stdio).
- `crates/noscat-ffi` - (being moved to 0.5 in phase 4) UniFFI bridge for mobile apps (Kotlin now, Swift later):
  `NoscatClient`, `Event` callback, identity/mesh helpers. The Android app
  (`~/Documents/noscat-android`) consumes the published crate.
- `crates/noscat` - (being moved to 0.5 in phase 4) the CLI: a thin skin over the client.
- `docs/nip-noscat.md` - the wire protocol spec (the interop contract).
- `packaging/` - nfpm, AUR prep, bottle script; `.github/workflows/release.yml` -
  the whole release pipeline (builds, crates.io, tap, scoop, pacman).

## Related project

The Android client lives in `~/Documents/noscat-android` (separate repo, its own
AGENTS.md): native Kotlin over a UniFFI bridge that consumes the published
`noscat-client` crate. Protocol changes belong here; the app repo carries none.
