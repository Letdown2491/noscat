# Releasing

noscat, noscat-desktop and noscat-android release in lockstep (same
version). noscat-relay versions on its own. Everything below that can be
checked before a tag is checked by CI on every push to main; this list is
what happens from the tag on, in order.

## Before tagging

- [ ] CI is green on noscat's `main` (`gh run list --workflow ci.yml`):
      Linux (glibc tests, musl builds for both architectures), macOS (both
      architectures), Windows, and the crates.io dry run.
- [ ] CI is green on noscat-desktop's `main` (both Linux variants).
- [ ] The workspace version in `Cargo.toml` equals the tag (the publish
      step refuses a mismatch). The desktop's `Cargo.toml` and the Android
      app's `versionName` carry the same version; `versionCode` is bumped.
- [ ] The netns suite passes: `tests/netrig/run.sh`.
- [ ] No "not released yet" notes are left in noscat's docs. The apps' notes about building from noscat's git branch or a
      local checkout go in steps 2 and 3, with the build change.

## 1. noscat

```
git tag v0.6.0 && git push origin v0.6.0
```

The release workflow builds every package, publishes `noscat-core`,
`noscat-client`, `noscat` and `noscat-ffi` to crates.io (in that order),
attaches everything to the GitHub release, and updates the Homebrew tap,
the Scoop bucket and the pacman repository. Wait for it to finish
(`gh run watch`), and check `cargo search noscat-client` shows the version.

Manual, from the release's assets:

- **AUR**: unpack `noscat-aur-v0.6.0.tar.gz`, then push `PKGBUILD` and
  `.SRCINFO` to `ssh://aur@aur.archlinux.org/noscat.git`.
- **winget**: unpack `noscat-winget-v0.6.0.tar.gz` into
  `manifests/l/Letdown2491/noscat/0.6.0/` in a fork of
  `microsoft/winget-pkgs` and open a PR titled
  "Add: Letdown2491.noscat version 0.6.0".

## 2. noscat-desktop

Only once the crates are on crates.io:

1. Remove the `[patch.crates-io]` section from `Cargo.toml`.
2. `cargo update -p noscat-client -p noscat-core` (in the dev container),
   build, and check `Cargo.lock` now points at crates.io.
3. Remove the "noscat's main branch" notes from README and AGENTS.
4. Commit, push, wait for CI, then `git tag v0.6.0 && git push origin
   v0.6.0`. The release workflow attaches `noscat-desktop` (Wayland) and
   `noscat-desktop-x11`.

## 3. noscat-android

1. `scripts/build-release.sh 0.6.0`: builds the published `noscat-ffi`
   optimized and a signed `app-release.apk` (needs `keystore.properties`).
2. Remove the "built from a local noscat checkout" notes from README and
   AGENTS.
3. Commit, push, `git tag v0.6.0 && git push origin v0.6.0`, and attach
   the APK: `gh release create v0.6.0 app/build/outputs/apk/release/app-release.apk --generate-notes`.

## 4. After

- Redeploy any server running noscat from the release binaries.
- Close `docs/plan-<version>.md`: tick its release phase.
