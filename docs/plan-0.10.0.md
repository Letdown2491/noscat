# noscat 0.10.0 plan: view and control a device

0.10.0 adds a **Screen** action to every member that allows it: click it
in the desktop app or the Android app (or run `noscat screen <device>`)
to see that device's screen and control it. It ships in lockstep in
noscat, noscat-desktop and noscat-android, after 0.6.0 (access groups and
the terminal), 0.8.0 (Bluetooth) and 0.9.0 (macOS). It was 0.9.0 until
the roadmap was re-cut on 2026-11-25.

Decided 2026-11-25:

- **Our own implementation, in Rust**, not voxl. voxl covers X11, macOS
  and Windows hosts but not Wayland or Android, wraps its stream in a
  WebSocket we do not need inside the mesh, and links x264 (GPL-2.0, and
  H.264 is patent-encumbered). voxl is MIT, so we may borrow pieces
  (damage tracking, encoder tuning, touch handling) with attribution.
- **Royalty-free codecs**: the OS hardware encoders first, VP8/VP9
  (libvpx, BSD) as the software fallback. No software H.264 (x264 or
  OpenH264) unless decided otherwise.
- **Nothing hosted anywhere**: the device being viewed captures and
  encodes locally; the stream is a noscat stream between members, end
  to end encrypted. No server, no relay for video.
- **Off by default** on every device: "Allow members to view this
  device", with view only or view and control, and ask each time (the
  default) or unattended. Screen view and control join the terminal in
  0.6.0's Control group (asked on first use; allow once, always, or
  deny), so a device can allow some members only. Whether view only
  needs its own level inside Control is decided when 0.10.0 starts.
- **Control from every client**: built-in viewers in both apps; the CLI
  opens a small viewer noscat serves on localhost.

## Components

```
  viewer (app or browser)                 device being viewed
  ───────────────────────                 ──────────────────────────
  decode + draw  <── video ── noscat stream ── encode <── capture
  input events   ── input ──> noscat stream ──> inject
```

| Piece | Linux X11 / headless | Linux Wayland | macOS | Windows (CLI) | Android |
|---|---|---|---|---|---|
| Capture | XShm + XDamage | portal ScreenCast + PipeWire | ScreenCaptureKit | DXGI duplication | MediaProjection |
| Encode | VA-API, else libvpx | VA-API, else libvpx | VideoToolbox | Media Foundation, else libvpx | MediaCodec |
| Input | XTest | portal RemoteDesktop (libei) | CGEvent | SendInput | accessibility service |
| Unattended | yes | when the portal restores the grant (GNOME, KDE), else a prompt | after granting permissions once | yes | **no**: Android 14+ needs a tap per session |

Packaging: the CLI stays one static binary, so headless and CLI-only
machines (a VPS serving a virtual desktop) install a small
`noscat-screen` companion package. The desktop app links the screen code
directly; the Android app has its own. Viewers need nothing extra.

## Phase 1: core and spike (Linux X11)

- [ ] Protocol (`docs/nip-noscat.md`): a screen service on a noscat
      stream: session setup (codec, size, view only or control), video
      frames, input events, clipboard later. Advertised in the member's
      advert so apps know who offers a screen.
- [ ] Host: X11 capture with damage tracking, encode (VA-API or libvpx),
      XTest input. Works on Xvfb, so a VPS can serve a virtual desktop.
- [ ] Viewer spike in the desktop app: decode in Rust and draw frames in
      GPUI at 60 fps on Linux. If GPUI cannot keep up, fall back to a
      native child window for the video.
- [ ] Browser viewer for the CLI (WebCodecs), served on localhost.
- [ ] Measure latency and bandwidth over a direct link and through the
      reachable member.

## Phase 2: Linux Wayland

- [ ] Capture through the ScreenCast portal and PipeWire; input through
      the RemoteDesktop portal; keep the restore token so unattended
      access survives restarts where the desktop allows it.

## Phase 3: Android

- [ ] Host: MediaProjection capture, MediaCodec encode, input through an
      accessibility service (the user enables it once); a notification
      to approve each session.
- [ ] Viewer: native MediaCodec decode on a surface; tap and drag as
      mouse, long press as right click, pinch to zoom, on-screen keyboard
      with a key bar (Esc, Ctrl, Alt).

## Phase 4: macOS and Windows hosts

- [ ] macOS: ScreenCaptureKit, VideoToolbox, CGEvent, in the 0.9 desktop
      app and `noscat-screen`.
- [ ] Windows: DXGI, Media Foundation (libvpx fallback), SendInput, in
      `noscat-screen` (there is no Windows app).

## Phase 5: release

- [ ] Settings in both apps and the CLI (off, view only, view and
      control; ask each time or unattended); a visible indicator on a
      device while someone is viewing it, and a way to end the session.
- [ ] A "send key" menu for shortcuts the viewer's own desktop takes
      (Super, Alt+Tab).
- [ ] Docs in all three repos, `noscat-screen` packaging, CI, and the
      lockstep release per `docs/releasing.md`.
