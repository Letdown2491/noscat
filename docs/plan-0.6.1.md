# noscat 0.6.1 plan: BSD binaries, invitations that arrive

BSD moved out of 0.6.0 on 2026-11-26, so the access and terminal release
does not wait on it (issue [#19](https://github.com/Letdown2491/noscat/issues/19)).
Also added that day: invitations that are retried until they arrive, and
key packages that do not outlive their use (phase 2). The member list
gains states, so both apps ship 0.6.1 too.

Pinned relay certificates were planned here the same day and dropped the
same day: a private mesh without DNS comes from `docs/plan-no-dns.md`
instead (phase 0 of 0.7.0), where members reach the relay over FIPS and
need no certificate at all.

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

## Phase 2: invitations that arrive

Decided 2026-11-26, after Nostr Compass #50 (MDK's Welcome fanout and
delivery deadline; Marmot's key package rules and its invite link draft,
marmot#429). Today an invite whose Welcome no relay accepts still reports
success and leaves a member that never joins, and a joined device keeps its
consumed key package (the private key in its state, the event on relays)
for as long as it stays in the mesh.

Key packages:

- [ ] After a successful join, delete this device's key package private
      keys (`init_key`) from the mesh state and publish a NIP-09 deletion
      for the consumed kind 30443 event. A device in a mesh refuses
      Welcomes, so it needs neither; Marmot (`foundation/key-packages.md`)
      requires the deletion within 24 hours of a replacement or at
      `not_after`. Otherwise anyone who later gets the state file can open
      the original Welcome, still on the relays.
- [ ] Remember the key package refs of every Add the mesh commits
      (bounded, in mesh state) and refuse them in `MeshGroup::add`.
      Without it, re-inviting a device that was removed while offline
      picks its old, consumed package from a relay, and the commit adds a
      member that can never open its Welcome (its storage was wiped on
      removal). `invite` then tries the next package, or says the device
      must run `noscat join` to publish a fresh one.
- [ ] Tests: a joined device has no key package material left and its
      event is deleted on the mock relay; re-inviting a removed device
      that has only its consumed package is refused, and works once it
      publishes a fresh one.

Welcome delivery (`publish` already sends to every inbox relay at once and
lets the slower ones finish, as MDK and Haven now do; what is missing is
what happens when none of them takes it):

- [ ] Owed Welcomes are kept in mesh state with a deadline: 7 days after
      the commit or the key package's `not_after`, whichever comes first
      (as MDK's #3708). The inviter retries each with backoff (30 s,
      doubling to 1 h) while it runs, until the new member is seen or the
      deadline passes.
- [ ] Each retry wraps the Welcome again. NIP-59 backdates a gift wrap by
      up to 2 days and a joiner looks back only 3
      (`GIFT_WRAP_LOOKBACK_SECS`), so republishing the first wrap would
      soon fall out of its window.
- [ ] A join request from a member that has never been seen means its
      Welcome went missing: resend the owed Welcome at once instead of
      dropping the request (`on_join_request` drops it today).
- [ ] Delivered means the new member's first advert arrived, not a
      relay's OK: a relay can accept a gift wrap it never serves back (MDK
      found relay.damus.io doing so for about 10% of recipients).
- [ ] `invite` reports "added; invitation not delivered yet" when no relay
      took the Welcome, instead of a plain success (CLI and the client's
      result).

Member state:

- [ ] The member list (`MemberStatus` and the client's) marks a member
      that was added but never seen as pending, and one past its Welcome
      deadline as never joined; the fix for now is to remove it and invite
      it again (automatic re-admission comes in 0.7.0, ADR 0009).
      `noscat mesh members` shows the state and keeps the npubs that
      noscat-relay reads; API.md, the man page and both apps follow.

MDK interop:

- [ ] Move `tests/mdk-interop` from `08f3ebf` to current MDK main (the
      Welcome fanout, #3687, and delivery deadline, #3708, landed after
      it) and add a scenario: `wn` invites a noscat device that is not
      running, which joins later and finds the same Welcome on several
      relays.

## Phase 3: release

- [ ] INSTALL, README and the man page name the BSD binaries; README and
      the man page cover the member states and the invite result.
- [ ] Lockstep 0.6.1 per `docs/releasing.md` (noscat and both apps;
      noscat-relay has no change of its own).
