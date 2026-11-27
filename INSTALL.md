# Installing Noscat

All channels are driven by a single tag push: binaries, packages, the Homebrew
tap, the pacman repository, the Scoop bucket, and crates.io are all updated
automatically per release. Latest release page:
<https://github.com/Letdown2491/noscat/releases>.

> The from-git methods (`cargo install --git`, `nix run`) build `main`,
> which may be ahead of the latest release.

## Quick install (Linux, macOS and FreeBSD)

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
Server = https://nos.cat/x86_64
# Server = https://nos.cat/aarch64
```

then `pacman -Sy noscat`; normal `pacman -Syu` upgrades pick up new releases.

An AUR source package is prepared in [`packaging/PKGBUILD`](packaging/PKGBUILD)
for when AUR account registration reopens: each release attaches it,
filled in, as `noscat-aur-<tag>.tar.gz`. Until then, use the pacman
repository above.

## Windows

Scoop (bucket updates automatically per release):

```
scoop bucket add letdown2491 https://github.com/Letdown2491/scoop-bucket
scoop install noscat
```

Or grab the zip from the release page. winget manifests are pending merge in
the community repo ([#486661](https://github.com/microsoft/winget-pkgs/pull/486661)
for the package, [#490013](https://github.com/microsoft/winget-pkgs/pull/490013)
for 0.6.0);
after it merges, `winget install Letdown2491.noscat` works and stays updated
through winget upgrade.

## Nix

```
nix run github:Letdown2491/noscat
```

A flake is at the repo root; `nix profile install github:Letdown2491/noscat`
adds it to a profile. Linux and macOS, x86_64 and aarch64. It builds the
`main` branch; add `?ref=v0.7.1` for the release.

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

From 0.7.0, every release attaches a FreeBSD binary
(`noscat-<tag>-x86_64-unknown-freebsd.tar.gz`, built on FreeBSD 14), and
the shell installer above picks it on FreeBSD.

`cargo install noscat` still fails on the BSDs: two of the FIPS crates
need small fixes that are waiting upstream
(`docs/upstream/01-freebsd-build.md`). The release builds with those
fixes applied; to build from a checkout the same way:

```
cargo build --release -p noscat $(packaging/bsd/patch-crates.sh)
```

The script fetches the two crates, applies `packaging/bsd/patches/` and
prints the cargo options that use the patched copies (it needs `patch`,
which FreeBSD's base system has). OpenBSD and NetBSD do not build yet,
even patched: the socket library behind LAN discovery does not support
them (`docs/plan-0.7.0.md`). A FreeBSD port (and then pkgsrc-wip) is on the table if there is
demand.

## Every package ships

- a man page (`noscat(1)`),
- shell completions: `noscat completions <bash|zsh|fish|powershell|elvish>`.
