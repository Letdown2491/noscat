# Installing noscat

All channels are driven by a single tag push: binaries, packages, the Homebrew
tap, the pacman repository, the Scoop bucket, and crates.io are all updated
automatically per release. Latest release page:
<https://github.com/Letdown2491/noscat/releases>.

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
binaries - no dependencies. Grab them from the release page.

## Arch Linux

A pacman repository is published per release. Add to `/etc/pacman.conf`:

```ini
[noscat]
SigLevel = Never
Server = https://letdown2491.github.io/noscat/x86_64
# Server = https://letdown2491.github.io/noscat/aarch64
```

then `pacman -Sy noscat`; normal `pacman -Syu` upgrades pick up new releases.

An AUR source package is also prepared in
[`packaging/PKGBUILD`](packaging/PKGBUILD) (submission pending AUR account
registration reopening); until then it can be installed by hand:

```
git clone https://github.com/Letdown2491/noscat && cd noscat/packaging
makepkg -si
```

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
adds it to a profile. Linux and macOS, x86_64 and aarch64.

## cargo (any platform with a Rust toolchain)

Once the crates are published:

```
cargo install --locked noscat
```

Or straight from git, which also works on the BSDs and anywhere else a Rust
toolchain exists:

```
cargo install --locked --git https://github.com/Letdown2491/noscat
```

## BSDs (FreeBSD, OpenBSD, NetBSD)

There are no prebuilt BSD packages yet. Rust builds out of the box on all
three, so the git-based `cargo install` above is the install method. A
FreeBSD port (and then pkgsrc-wip) is on the table if there is demand.

## Every package ships

- a man page (`noscat(1)`),
- shell completions: `noscat completions <bash|zsh|fish|powershell>`.
