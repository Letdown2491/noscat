# Installing noscat

All channels are driven by a single tag push: binaries, packages, the Homebrew
tap, the pacman repository, the Scoop bucket, and crates.io are all updated
automatically per release. Latest release page:
<https://github.com/Letdown2491/noscat/releases>.

> Every channel below installs the latest **release**, currently 0.4.3. The
> `main` branch is 0.5.0, which is not released yet and does not talk to
> 0.4. Only the from-git methods (`cargo install --git`, `nix run`) build
> `main`.

## Quick install (Linux and macOS)

Shell installer, into `~/.local/bin`:

```
curl -fsSL https://raw.githubusercontent.com/Letdown2491/noscat/main/packaging/install.sh | sh
```

## Homebrew (macOS and Linux)

```
brew install Letdown2491/tap/noscat
```

Works on Linux without a C toolchain: Linux users get a prebuilt bottle
(static musl binary), macOS users a plain tarball.

## Linux packages

`.deb`, `.rpm`, and `.apk` attach to every release, built from static musl
binaries with no dependencies. Grab them from the release page.

## Arch Linux

A pacman repository is published per release. Add to `/etc/pacman.conf`:

```ini
[noscat]
SigLevel = Never
Server = https://letdown2491.github.io/noscat/x86_64
# Server = https://letdown2491.github.io/noscat/aarch64
```

then `pacman -Sy noscat`; normal `pacman -Syu` upgrades pick up new releases.

An AUR source package is prepared in [`packaging/PKGBUILD`](packaging/PKGBUILD)
for when AUR account registration reopens. It is still pinned at 0.1.1, so
use the pacman repository above instead; the PKGBUILD is refreshed at its
submission.

## Windows

Scoop (bucket updates automatically per release):

```
scoop bucket add letdown2491 https://github.com/Letdown2491/scoop-bucket
scoop install noscat
```

Or grab the zip from the release page. A winget manifest is pending merge in
the community repo ([#486661](https://github.com/microsoft/winget-pkgs/pull/486661));
after it merges, `winget install Letdown2491.noscat` works and stays updated
through winget upgrade.

## Nix

```
nix run github:Letdown2491/noscat
```

A flake is at the repo root; `nix profile install github:Letdown2491/noscat`
adds it to a profile. Linux and macOS, x86_64 and aarch64. It builds the
`main` branch (0.5.0 today); add `?ref=v0.4.3` for the release.

## cargo (any platform with a Rust toolchain)

The latest release from crates.io:

```
cargo install --locked noscat
```

Or `main` straight from git:

```
cargo install --locked --git https://github.com/Letdown2491/noscat
```

On glibc Linux, 0.5 needs the libdbus and libclang development packages to
build (`libdbus-1-dev libclang-dev pkg-config` on Debian and Ubuntu,
`dbus-devel clang-devel` on Fedora). macOS, Windows and musl need nothing
extra.

## BSDs (FreeBSD, OpenBSD, NetBSD)

There are no prebuilt BSD packages yet; `cargo install` above is the
install method. 0.4.3 builds on all three. 0.5 does not build on FreeBSD
yet: one of the FIPS crates (`nvpn-mdns-sd`) uses a Linux-only socket
option, and the fix is waiting upstream (`docs/upstream/01-freebsd-build.md`).
OpenBSD and NetBSD have not been tried with 0.5. A FreeBSD port (and then
pkgsrc-wip) is on the table if there is demand.

## Every package ships

- a man page (`noscat(1)`),
- shell completions: `noscat completions <bash|zsh|fish|powershell|elvish>`.
