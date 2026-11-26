# noscat 0.6.1 plan: BSD binaries, and a private mesh without DNS

BSD moved out of 0.6.0 on 2026-11-26, so the access and terminal release
does not wait on it (issue [#19](https://github.com/Letdown2491/noscat/issues/19)).
Pinned relay certificates were added the same day: with them a private mesh
needs no domain, no DNS and no certificate authority. The pins live in the
shared client, so both apps ship 0.6.1 too.

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

## Phase 2: pinned relay certificates (no DNS, no CA)

Decided 2026-11-26. A private mesh's relay can run on a bare IP address
with its own self-signed certificate; devices trust it through the pairing
code they already scan, the same way they trust the member's npub.

- [ ] Optional and per relay: a relay with a pin accepts only the
      certificate matching it; a relay without one is verified against
      the usual certificate authorities, exactly as today. Public relays,
      relays behind a domain, and a mix of both keep working. STUN is
      unaffected (plain UDP; `mesh stun` stays its own choice).
- [ ] Wire (`docs/nip-noscat.md`): the pin travels with the relay URL in
      pairing codes (`?relay=wss://203.0.113.10:443&pin=<sha256 of the
      certificate's public key>`, one pin per relay) and in the mesh's
      relay list, so every member and every new device gets it. Devices
      that predate pins ignore it and fall back to normal verification
      (which fails for a self-signed relay: say so in the release notes).
- [ ] noscat-core: relay connections check the pin with a custom TLS
      verifier (the nostr-sdk transport); a mismatch refuses the relay
      and logs why. Tests: right pin connects, wrong pin and a
      CA-valid-but-unpinned certificate are refused, no pin uses the CAs.
- [ ] CLI: `noscat mesh relays add wss://<ip>:<port> --pin <pin>`;
      `mesh relays` and `mesh qr` show and carry it.
- [ ] noscat-relay: serves TLS itself when asked (`TLS_ADDR`, generating
      and keeping a self-signed certificate on first start) and prints its
      pin at startup and with `noscat-relay pin`. Caddy stays the option
      for a domain.
- [ ] Apps: pairing codes with pins join as today (the parsing is in the
      shared client); Settings shows a relay as "pinned".
- [ ] Guide (`docs/private-mesh.md`): the no-DNS path becomes the main
      one (no domain, no Caddy: steps 1 and 4 mostly go); the domain
      stays as an alternative.

## Phase 3: release

- [ ] INSTALL, README and the man page name the BSD binaries; README and
      the man page cover pins.
- [ ] Lockstep 0.6.1 per `docs/releasing.md` (noscat, both apps, and
      noscat-relay for its TLS).
