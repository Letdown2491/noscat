# Upstream drafts (not sent)

Drafts of issues and patches for the FIPS crates noscat 0.5 builds on. Nothing
here has been posted. Review, edit and send them yourself; each file is the
body of one issue or patch, with a short note to you at the top.

Where they go:
- `nvpn-fips-core`, `nvpn-fips-endpoint`, `nvpn-mdns-sd`: mmalmi's FIPS fork,
  hosted on nostr git (NIP-34) at
  `https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/fips`.
  Issues there are NIP-34 issue events (kind 1621), patches are kind 1617
  (or `git format-patch` output sent the same way).
- `nvpn-fips-tcp`: `https://github.com/mmalmi/fips-tcp`.

| # | File | Kind | Crate | Why noscat needs it |
|---|---|---|---|---|
| 1 | `01-freebsd-build.md` | 2 patches | nvpn-mdns-sd, nvpn-fips-core | FreeBSD is a supported noscat platform |
| 2 | `02-optional-native-deps.md` | patch | nvpn-fips-core | glibc builds without libdbus and libclang |
| 3 | `03-transit-fragmentation.md` | issue | nvpn-fips-core | relayed paths silently drop datagrams over MTU minus 110 |
| 4 | `04-first-datagram-dropped.md` | issue | nvpn-fips-core | first datagram to a peer is lost (1 s QUIC handshake) |
| 5 | `05-external-traversal-signaling.md` | issue | nvpn-fips-core | NATed devices cannot first-contact without a reachable member |
| 6 | `06-fips-tcp-sack-wscale.md` | issue | nvpn-fips-tcp | optional; noscat uses QUIC instead |

Suggested order: 1 and 2 first (small, verified, no design questions), then
3 and 4 (bugs with measurements), then 5 (a feature request with a design
question). 6 is a courtesy note and can be skipped.

Patches are against the published crates (`nvpn-fips-core 0.4.124`,
`nvpn-mdns-sd 0.19.2`); paths may need adjusting to the repo's workspace
layout. Verification for each is recorded in its file.
