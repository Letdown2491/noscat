# noscat 0.7.0 plan: BSD binaries, invitations that arrive

Numbered 0.6.1 until 2026-11-27, when its release stopped at the API check:
the member states and the invite result change the public API, which
takes a minor release (0.x rules). The plans after it moved up one: two-way
pairing and Bluetooth are 0.8.0, macOS 0.9.0, the screen 0.10.0.

BSD moved out of 0.6.0 on 2026-11-26, so the access and terminal release
does not wait on it (issue [#19](https://github.com/Letdown2491/noscat/issues/19)).
Also added that day: invitations that are retried until they arrive, and
key packages that do not outlive their use (phase 2). The member list
gains states, so both apps ship 0.7.0 too.

Pinned relay certificates were planned here the same day and dropped the
same day: a private mesh without DNS comes from `docs/plan-no-dns.md`
instead (phase 0 of 0.8.0), where members reach the relay over FIPS and
need no certificate at all.

## Phase 1: BSD binaries

Decided 2026-11-25 (option A): ship BSD binaries built with our patches
instead of waiting for upstream. Independent of everything else.

- [x] The two patches from `docs/upstream/01-freebsd-build.md` live in the
      repo (`packaging/bsd/patches/`): `nvpn-mdns-sd` on `socket-pktinfo`
      0.4, and the `bind_socket_to_interface` fallback in
      `nvpn-fips-core`. `packaging/bsd/patch-crates.sh` fetches and patches
      the crates and prints `--config patch...` options, so Cargo.toml
      stays untouched and every other platform keeps building pure
      crates.io code. A cross build for FreeBSD 14.5 (clang, lld and the
      base sysroot in the dev container) compiles and links with it.
- [x] CI: FreeBSD build and tests in a VM (`vmactions/freebsd-vm`; the
      whole suite passes since the buffer fix below); the release attaches
      `noscat-<tag>-x86_64-unknown-freebsd.tar.gz` (job written) and the
      shell installer picks it (done; the installer also asked for
      tarball names no release had, so it failed everywhere: fixed).
- [x] OpenBSD and NetBSD: tried in CI VMs (2026-11-27); neither builds,
      even patched. Both fail in `socket-pktinfo` 0.4 (through
      `nvpn-mdns-sd`, the mDNS for LAN discovery): OpenBSD has no
      `IP_PKTINFO`/`in_pktinfo`, NetBSD lacks socket2's
      `InterfaceIndexOrAddress` and `join_multicast_v4_n`. No binaries and
      no CI job until that crate supports them (or mDNS becomes optional
      in FIPS).
- [x] FreeBSD refuses a socket buffer above `kern.ipc.maxsockbuf` (2 MiB
      by default) instead of clamping it, so FIPS's 16 MiB default kept
      UDP from starting (CI's first run). noscat asks for 1 MiB on the
      BSDs (`dataplane.rs`).
- [x] Docs: INSTALL's BSD section points at the binaries (`cargo install
      noscat` keeps failing on the BSDs until upstream fixes it). README
      and the site follow in the release commit (the site deploys from
      main). A FreeBSD port (with the patches) and pkgsrc-wip later, on
      demand.
- [ ] When upstream ships the fixes, drop the patches; the upstream
      draft stays unposted unless approved.

## Phase 2: invitations that arrive

Decided 2026-11-26, after Nostr Compass #50 (MDK's Welcome fanout and
delivery deadline; Marmot's key package rules and its invite link draft,
marmot#429). Today an invite whose Welcome no relay accepts still reports
success and leaves a member that never joins, and a joined device keeps its
consumed key package (the private key in its state, the event on relays)
for as long as it stays in the mesh.

Key packages:

- [x] After a successful join, delete this device's key package private
      keys (`init_key`) from the mesh state and publish a NIP-09 deletion
      for the consumed kind 30443 event. A device in a mesh refuses
      Welcomes, so it needs neither; Marmot (`foundation/key-packages.md`)
      requires the deletion within 24 hours of a replacement or at
      `not_after`. Otherwise anyone who later gets the state file can open
      the original Welcome, still on the relays.
- [x] Remember the key package refs of every Add the mesh commits
      (bounded, in mesh state) and refuse them in `MeshGroup::add`.
      Without it, re-inviting a device that was removed while offline
      picks its old, consumed package from a relay, and the commit adds a
      member that can never open its Welcome (its storage was wiped on
      removal). `invite` then tries the next package, or says the device
      must run `noscat join` to publish a fresh one. (A device knows only
      the Adds it applied, so one that joined later cannot refuse a
      package consumed before it arrived.)
- [x] A device outside a mesh publishes the same key package again (in
      a newer event) instead of minting one at every start and `join`;
      with two kept, a device invited while stopped pushed out the very
      package its waiting Welcome needed (found by the Windows CI run of
      the lost invitation test).
- [x] noscat-relay accepts the deletion: kind 5 for the author's own
      key packages, by coordinate only, never served back.
- [x] Tests: a joined device has no key package material left and its
      event is deleted on the mock relay; re-inviting a removed device
      that has only its consumed package is refused, and works once it
      publishes a fresh one.

Welcome delivery (`publish` already sends to every inbox relay at once and
lets the slower ones finish, as MDK and Haven now do; what is missing is
what happens when none of them takes it):

- [x] Owed Welcomes are kept in mesh state with a deadline: 7 days after
      the commit or the key package's `not_after`, whichever comes first
      (as MDK's #3708). The inviter retries each with backoff (30 s,
      doubling to 1 h) while it runs, until the new member is seen or the
      deadline passes; once a relay has accepted it, only every hour,
      doubling to a day (a relay may still never serve it back).
- [x] Each retry wraps the Welcome again. NIP-59 backdates a gift wrap by
      up to 2 days and a joiner looks back only 3
      (`GIFT_WRAP_LOOKBACK_SECS`), so republishing the first wrap would
      soon fall out of its window.
- [x] A join request from a member that has never been seen means its
      Welcome went missing: resend the owed Welcome at once instead of
      dropping the request (`on_join_request` drops it today).
- [x] Delivered means the new member's first advert arrived, not a
      relay's OK: a relay can accept a gift wrap it never serves back (MDK
      found relay.damus.io doing so for about 10% of recipients).
- [x] `invite` reports "added; invitation not delivered yet" when no relay
      took the Welcome, instead of a plain success (CLI and the client's
      result).

Member state:

- [x] The member list (`MemberStatus` and the client's) marks a member
      that was added but never seen as pending, and one past its Welcome
      deadline as never joined; the fix for now is to remove it and invite
      it again (automatic re-admission comes in 0.8.0, ADR 0009).
      `noscat mesh members` shows the state and keeps the npubs that
      noscat-relay reads; API.md and the man page follow.
- [ ] Both apps show the states (joining, never joined) and the invite
      result.

MDK interop:

- [x] Move `tests/mdk-interop` from `08f3ebf` to current MDK main (the
      Welcome fanout, #3687, and delivery deadline, #3708, landed after
      it) and add a scenario: `wn` invites a noscat device that is not
      running, which joins later and finds the same Welcome on several
      relays. Passes against MDK `9384348`, with scenario 2 also checking
      that a White Noise member counts as active once it talks.

## Phase 3: release

- [x] INSTALL and README name the FreeBSD binary; README and the man page
      cover the member states and the invite result.
- [ ] Lockstep 0.7.0 per `docs/releasing.md` (noscat and both apps; no
      winget PR this time, 0.8.0 follows soon). noscat-relay 0.3.0 with
      the key package deletion.
