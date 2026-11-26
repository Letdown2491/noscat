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
- **Each device decides** what other members may do to it, through
  access groups (moved here from 0.7.0, since the terminal needs them and
  the screen in 0.9.0 builds on them). Decided 2026-11-25 after a UX
  review: three trust groups instead of per-action toggles, and the host
  is asked on first use for control instead of configuring it ahead of
  time. Settings is for review and revoking, not setup. To be tried and
  revisited after use.
- **Private meshes, all the way**: the apps' invite codes carry a private
  mesh's relays ([#20](https://github.com/Letdown2491/noscat/issues/20)),
  and STUN comes from the mesh's own relay ([#1](https://github.com/Letdown2491/noscat/issues/1)).
- **BSD binaries** ([#19](https://github.com/Letdown2491/noscat/issues/19)).

## Phase 0: pairing codes in the apps (#20)

- [x] `noscat-ffi`: `NoscatClient::pairing_uri()`, a wrapper over
      `Client::pairing_uri()`; listed in API.md.
- [x] noscat-android: read it when Invite a device opens (off the main
      thread, not cached: a mesh can turn private while the app runs)
      instead of `Pairing.encode(npub)`.

## Phase 1: STUN for private meshes ([#1](https://github.com/Letdown2491/noscat/issues/1))

- [x] noscat-relay serves STUN on UDP (`STUN_ADDR`, off by default), with
      pion/stun next to the relay: same box and operator as the relay, so
      no new exposure. Its own release (0.2.0), before noscat 0.6.0.
- [x] The mesh carries its STUN servers in the group state
      (`noscat.stun.v1`, `0xf3a2`: IP literals with a port, no hostnames).
      Spec change in `docs/nip-noscat.md`.
- [x] A private mesh never falls back to the public defaults: with no
      STUN of its own, its devices advertise no NAT address and connect
      through the reachable member. A device in no mesh uses none either.
- [x] CLI: `--stun` shown in `--help` and the man page; `noscat mesh stun
      add|remove`.
- [x] Apps show the mesh's STUN servers (`mesh_stun()`, and
      `set_mesh_stun()` to edit them, in the FFI): Settings > Network on
      both, editable.
- [x] Deployment: Caddy proxies TCP only, so STUN needs UDP 3478 open on
      the relay's host (on vm-2252, ask before changing it). The VPS's
      noscat is reachable without an address today, so before it runs a
      0.6 build it needs `--reachable <ip:port>` or the mesh's STUN.
      Done 2026-11-26: noscat-relay with `STUN_ADDR=0.0.0.0:3478` (no host
      firewall; answers from the internet), the VPS's noscat on
      `--reachable 185.18.221.60:41641`, mesh STUN `185.18.221.60:3478`.

Changed from the first draft (2026-11-25): FIPS takes its STUN list when
the data plane binds and has no way to change it at runtime, so a device
picks its list at start (explicit `--stun`, else the mesh's, else public
for a shared mesh, else none) and a new list applies from each device's
next start. That makes `&stun=` in the pairing QR pointless (a device
that just joined takes the list from the group at its next start), so the
QR carries no STUN. A device that just joined a private mesh has no STUN
until it restarts: it still connects, through the reachable member.

## Phase 2: access groups

A device decides what each member may do to it, in three groups ordered
by risk. The receiver enforces it on each incoming stream, whose opener is
authenticated by the QUIC handshake, so a sender cannot get around it.

| Group | Covers | Default |
|---|---|---|
| Send me things | files, chat, clipboard | allowed |
| Use my services | forwards to the default service and to served ports | allowed |
| Control this device | terminal (0.6), screen view and control (0.9) | ask |

- [x] Per member, each group is allowed, denied, or (Control only) ask.
      Control's choices on a prompt: allow once (this session), always
      allow, deny. Defaults keep today's behavior for the first two
      groups, so existing meshes behave as before.
- [x] Local and private: kept in the device's own settings, never in the
      group state or adverts.
- [x] Ask on first use: an incoming Control request waits while the host
      decides. The opener is told it is waiting; the request times out
      after 60 s as denied. `noscat-client` raises an access request event
      with the requester and group, and takes the answer (API.md).
- [x] Headless hosts (no app attached to answer): Control requests are
      denied unless allowed ahead of time. Pending and recent requests are
      listed by `noscat access`; `noscat allow|deny <device> <group>
      [--once]` answers or sets them.
- [x] Wire (`docs/nip-noscat.md`): every app protocol's refusal answer
      gains "not permitted"; Control protocols gain "waiting for approval"
      before started or not permitted. A device advertises "control
      offered" unless its Control default is never; the advert never
      carries who is allowed.
- [x] Fine-grained per-action switches stay out of the apps; a CLI flag
      may expose them later if someone needs them.
- [x] Not covered: membership. Every device stays an admin (ADR 0007).

Done 2026-11-25, with these choices:

- The CLI adds `noscat ask <member|everyone> control` and `noscat access
  reset <member>`; `everyone` in place of a member sets the default.
  Members are picked by name or npub.
- `--once` with nothing waiting allows the member's next request, until
  the device stops.
- "Waiting for approval" and "control offered" in adverts arrive with
  the first Control protocol (phase 3); the ask path is built and gets its
  end-to-end tests there.
- The FFI carries none of it yet: the access methods and events reach the
  apps in phase 4.

## Phase 3: terminal (protocol, host, CLI)

```
  viewer (CLI or app)                      member
  ───────────────────                      ─────────────────────────
  terminal emulator <── output ── stream ── PTY <── login shell
  keys, resizes     ── input  ──> stream ──> PTY
```

- [x] Protocol (`docs/nip-noscat.md`): a Terminal app protocol (tag 4).
      The opener sends the terminal size and `TERM`; the accepter answers
      waiting for approval (optional), then started, not permitted, or
      unavailable; then framed messages: input and resizes one way, output
      and the exit status the other.
- [x] Host: a PTY through `portable-pty` (Linux, macOS, BSD; ConPTY on
      Windows) running the user's login shell in their home directory, as
      the user running noscat (never elevated). A noscat run as a system
      service runs shells as its service user; the docs say so.
- [x] Gated by the Control group (phase 2): asked on first use, never on
      by default.
- [x] On the host: each session logged (who, when, how long), open
      sessions listed and endable (`noscat sessions`).
- [x] CLI client: `noscat shell <device>` (raw mode, resizes followed,
      exit status passed through; prints "waiting for <device> to
      approve" while asked).
- [ ] Rig test: a session through the reachable member at 3% loss stays
      usable; a denied member gets "not permitted"; an unanswered request
      times out.

Done 2026-11-25, except the rig test (still open below). Choices:

- The shell scrubs `NOSCAT_IDENTITY`, `NOSCAT_DIR` and `RUST_LOG` from
  its environment; it runs in the home directory.
- A device advertises control only when someone could get in (an allow
  rule, or ask with an app attached), so a headless server with the
  defaults offers nothing.
- Piped input to `noscat shell` ends with Ctrl-D, so `echo cmd | noscat
  shell host` runs and returns.
- Covered end to end in `noscat-client/tests/client.rs` (real shell:
  refused headless, asked, once, deny, always, host ends a session).
- [ ] Rig test (3% loss through the reachable member) not written yet.

## Phase 4: access and terminal in the apps

- [x] `noscat-ffi`: access request events and their answer; the access
      settings (read, change, revoke); open a terminal
      (`openTerminal(target, cols, rows)`) returning a handle with
      `write`, `resize` and `close`; output, waiting and exit arrive as
      events (on a background thread: apps hop to their UI thread).
- [x] Prompt (desktop and Android): "<device> wants to open a terminal on
      this <computer|phone>", with Allow once, Always allow, Deny. On the
      desktop it raises the window and shows through the tray if hidden.
      Desktop: a strip across the top of the main window with a countdown;
      the window is raised, or reopened when closed to the tray. Android
      needs none for now: only control asks, and phones host no terminal.
- [x] Settings, a new **Access** card after Network: one row per member
      with a one-line summary ("can send things, use services, control:
      always"); tapping a row edits its three groups or revokes. Below it,
      recent terminal sessions (who, when, how long). Desktop: Everyone
      plus a row per member, Edit opens Allow / Ask / Block per group;
      recent sessions are this run's only (the full history is
      `terminal.log`). Android: the Send group only, as phones offer
      neither services by default nor control.
- [x] The Terminal action is an icon on device rows, shown only for
      devices that advertise control offered (in practice computers, so
      phone rows keep four icons). Refused: the icon greys out for that
      device, with the reason as its tooltip. Waiting: the opener shows
      "Waiting for <device> to approve".
- [x] noscat-desktop: a terminal opens in its own window (embedded
      `alacritty_terminal` drawn in GPUI, as Zed does), titled with the
      device's name; closing it ends the session. Launching a system
      terminal running the CLI is not an option: the CLI on the same
      computer is a different device.
- [x] While a member has a terminal open on this computer: a persistent
      banner naming it, with End, and the tray icon changes. Not a toast.
- [x] noscat-android (client only; a shell into the app's sandbox is
      useless): a full-screen terminal with a row of extra keys (Esc,
      Ctrl, Alt, Tab, arrows). Check the license of any terminal library
      before using it. Termux `terminal-view` (Apache 2.0). Built and unit
      tested; not yet run on a device (the Pixel keeps release 0.5.1).
- [x] Checked end to end on a throwaway local mesh (mock relay, CLI host,
      desktop): the desktop's terminal window ran the host's shell with
      colours and the cursor; the CLI's `noscat shell` raised the desktop's
      prompt and got a shell after Allow once.
- [ ] Try it, then revisit: after the first real use, review the groups,
      the prompt and the card with the user before the release.

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
