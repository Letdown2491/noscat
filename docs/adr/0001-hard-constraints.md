---
status: accepted
date: 2026-11-23
---

# Hard constraints: no root, crates.io only, five platforms

noscat aims to be a decentralized, trustless Tailscale built on Nostr. Three constraints are fixed and every other decision is measured against them:

1. **No root, ever, for the core features.** Tunnels, forwards, files and chat must work as an unprivileged user with no system TUN, no daemon and no setuid helper. A system TUN (or Android `VpnService`, which needs no root) is an optional extra on top, never a requirement.
2. **Every dependency comes from crates.io.** The library crates (`noscat-core`, `noscat-client`, `noscat-ffi`) are published so other developers can build on them, and crates.io rejects git dependencies. Git-only code may appear only as a dev-dependency (stripped on publish) or as a CI-only `[patch]`.
3. **Linux (glibc and musl), macOS, Windows, the BSDs and Android stay supported.** A dependency that cannot build on one of them needs a fix offered upstream, a feature gate, or a replacement before it is adopted.

## Consequences

- Upstream projects we depend on (FIPS, OpenMLS) must publish releases we can pin; when they lag, we wait or offer patches rather than ship git pins.
- A CI-only `[patch]` keeps our own builds green but does not help crates.io users on the affected platform until upstream releases the fix, so such patches are tracked as release blockers for that platform.
