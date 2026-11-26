# noscat 0.6.1 plan: BSD binaries

Moved out of 0.6.0 on 2026-11-26, so the access and terminal release does
not wait on it. noscat only: the BSDs get the CLI, and the apps keep their
0.6.0 (their version shares noscat's major.minor; the patch is their own).
Issue [#19](https://github.com/Letdown2491/noscat/issues/19).

## Phase 1: BSD binaries

Decided 2026-11-25 (option A): ship BSD binaries built with our patches
instead of waiting for upstream. Independent of everything else.

- [ ] The two patches from `docs/upstream/01-freebsd-build.md` live in the
      repo (`packaging/bsd/patches/`): `nvpn-mdns-sd` on `socket-pktinfo`
      0.4, and the `bind_socket_to_interface` fallback in
      `nvpn-fips-core`. Only the BSD CI job adds the `[patch]` section, so
      every other platform keeps building pure crates.io code.
- [ ] CI: FreeBSD build and tests (a FreeBSD VM action, or cross with a
      sysroot as in the spike); the release attaches
      `noscat-<tag>-x86_64-unknown-freebsd.tar.gz`.
- [ ] OpenBSD and NetBSD: try the same; ship binaries for those that
      build and pass, and record what fails for the others.
- [ ] Docs: INSTALL's BSD section points at the binaries (`cargo install
      noscat` keeps failing on the BSDs until upstream fixes it). A
      FreeBSD port (with the patches) and pkgsrc-wip later, on demand.
- [ ] When upstream ships the fixes, drop the patches; the upstream
      draft stays unposted unless approved.

## Phase 2: release

- [ ] INSTALL, README and the man page name the BSD binaries.
- [ ] noscat 0.6.1 per `docs/releasing.md` (crates and the CLI; the apps
      do not change).
