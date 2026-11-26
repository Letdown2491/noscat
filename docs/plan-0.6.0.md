# noscat 0.6.0 plan: access and privacy

0.6.0 lets a device decide what each member may do to it, adds a
terminal into any member that allows it, and makes a private mesh reach
no third party at all. It ships in lockstep in noscat, noscat-desktop and
noscat-android.

Decided 2026-11-25 (the roadmap was re-cut that day: Bluetooth moved to
0.7.0, macOS to 0.8.0, screen view and control to 0.9.0):

- **Terminal**: a Terminal action on a member opens a shell on it, like
  SSH but with the mesh identity as the login: no keys, no sshd. Our own
  app protocol, not SSH carried over a forward.
- **Each device decides** which members get terminal access, through
  per-device permissions (moved here from 0.7.0, since the terminal needs
  them and the screen in 0.9.0 builds on them).
- **Private meshes, all the way**: the apps' invite codes carry a private
  mesh's relays ([#20](https://github.com/Letdown2491/noscat/issues/20)),
  and STUN comes from the mesh's own relay ([#1](https://github.com/Letdown2491/noscat/issues/1)).
- **BSD binaries** ([#19](https://github.com/Letdown2491/noscat/issues/19)).

## Phase 0: pairing codes in the apps (#20)

- [ ] `noscat-ffi`: `NoscatClient::pairing_uri()`, a wrapper over
      `Client::pairing_uri()`; listed in API.md.
- [ ] noscat-android: cache it at client start (never on the main thread)
      and use it in Invite a device instead of `Pairing.encode(npub)`.

## Phase 1: STUN for private meshes ([#1](https://github.com/Letdown2491/noscat/issues/1))

- [ ] noscat-relay serves STUN on UDP (`STUN_PORT`, off by default), with
      pion/stun next to the relay: same box and operator as the relay, so
      no new exposure. Its own release, before noscat 0.6.0.
- [ ] The mesh carries its STUN servers like its relays: in the group
      state of a private mesh and in the pairing QR
      (`noscat:<npub>?relay=...&stun=...`, which phase 0 puts in the
      apps), so a joining device uses them from its first moment. Spec change in `docs/nip-noscat.md`.
- [ ] A private mesh never falls back to the public defaults: with no
      STUN of its own, its devices advertise no NAT address and connect
      through the reachable member.
- [ ] CLI: `--stun` shown in `--help` and the man page; `noscat mesh stun
      add|remove`. Apps show the mesh's STUN servers next to its relays.
- [ ] Deployment note: Caddy proxies TCP only, so STUN needs UDP 3478
      open on the relay's host (on vm-2252, ask before changing it).

## Phase 2: per-device permissions

A device decides which members may do what to it: for example, the
desktop takes files from the VPS but not from the phone. The receiver
enforces it on each incoming stream, whose opener is authenticated by
the QUIC handshake, so a sender cannot get around it.

- [ ] Actions: files, chat, clipboard, forwards to the default service,
      forwards to served ports, terminal, and (0.9) screen view and
      control.
- [ ] Policy: a per-device default per action (everyone or nobody), plus
      per-member overrides. Defaults stay "everyone" (terminal and screen:
      nobody), so existing meshes behave as before. New members get the
      defaults.
- [ ] Local and private: kept in the device's own settings, not in the
      group state. A refused stream gets a clear reason ("does not accept
      files from this device"): every app protocol's refusal answer gains
      a "not permitted" code (wire change in `docs/nip-noscat.md`). The
      apps remember it and grey the action out for that member.
- [ ] CLI: `noscat allow|deny <device> <action>`, `noscat permissions`.
      Desktop and Android: the UI is designed with the user before it is
      built (device rows have no overflow menu, decided for 0.5.1).
- [ ] Not covered: membership. Every device stays an admin (ADR 0007).

## Phase 3: terminal (protocol, host, CLI)

```
  viewer (CLI or app)                      member
  ───────────────────                      ─────────────────────────
  terminal emulator <── output ── stream ── PTY <── login shell
  keys, resizes     ── input  ──> stream ──> PTY
```

- [ ] Protocol (`docs/nip-noscat.md`): a Terminal app protocol (tag 4).
      The opener sends the terminal size and `TERM`; the accepter answers
      started, not permitted, or unavailable; then framed messages: input
      and resizes one way, output and the exit status the other.
- [ ] Host: a PTY through `portable-pty` (Linux, macOS, BSD; ConPTY on
      Windows) running the user's login shell in their home directory, as
      the user running noscat (never elevated). A noscat run as a system
      service runs shells as its service user; the docs say so.
- [ ] Off unless allowed: terminal is a permission action whose default
      is nobody. A device that allows anyone says so in its advert, so
      apps show Terminal only on members that offer it.
- [ ] On the host: each session logged (who, when, how long), open
      sessions listed and endable (`noscat sessions`, and in the desktop
      app), and a notice when one starts.
- [ ] CLI client: `noscat shell <device>` (raw mode, resizes followed,
      exit status passed through).
- [ ] Rig test: a session through the reachable member at 3% loss stays
      usable; a member without permission gets "not permitted".

## Phase 4: terminal in the apps

- [ ] `noscat-ffi`: open a session (`openTerminal(target, cols, rows)`)
      returning a handle with `write`, `resize` and `close`; output and
      the exit arrive as events (on a background thread: apps hop to
      their UI thread).
- [ ] noscat-desktop: an embedded terminal (`alacritty_terminal` for the
      emulation, drawn in GPUI, as Zed does). Launching a system terminal
      running the CLI is not an option: the CLI on the same computer is a
      different device. As host, Settings shows open sessions.
- [ ] noscat-android (client only; a shell into the app's sandbox is
      useless): a terminal view with a row of extra keys (Esc, Ctrl, Alt,
      Tab, arrows). Check the license of any terminal library before
      using it.
- [ ] Where the action sits in each app is designed with the user before
      it is built.

## Phase 5: BSD binaries ([#19](https://github.com/Letdown2491/noscat/issues/19))

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

## Phase 6: release

- [ ] Docs in all three repos (README, API, man page, nip-noscat for the
      wire changes, CONTEXT terms), CI green, netns suite.
- [ ] Lockstep 0.6.0 per `docs/releasing.md`.
