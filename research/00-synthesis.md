# noscat — Research Synthesis (2026-11-21)

Companion files: [fips.md](fips.md), [nostr-vpn.md](nostr-vpn.md), [marmot-mdk.md](marmot-mdk.md).
All claims are cited in those files; this file is the strategic read-out.

## TL;DR

The research changed our plan in one big way and confirmed it in another:

1. **Changed:** the data plane is a commodity. Two MIT-licensed Rust implementations of a
   Nostr-native mesh data plane already exist (upstream FIPS, and mmalmi's benchmarked
   `nvpn-fips-*` fork crates). Writing a third from scratch is dominated. noscat's
   originality lives entirely in the **control plane and the UX layer**.
2. **Confirmed:** the ambitious route ("Nostr as a full control plane") is the right bet,
   because the existing control planes are the weakest links in the ecosystem:
   nostr-vpn uses a **custom, non-NIP event envelope with flat rosters** — no ACLs, no
   forward-secret membership, no admin delegation. That is exactly the gap noscat should fill,
   and Marmot's MLS-over-Nostr spec is a ready-made, formally-modeled shape for filling it.

## What each project is, in one line

| Project | What it actually is | License | Best artifact |
|---|---|---|---|
| **FIPS** (jmcorgan) | Self-organizing mesh daemon: transports → FMP (Noise IK, spanning-tree routing) → FSP (Noise XK, e2e). Nostr discovery + gift-wrapped hole-punch signaling (kinds 37195 / 21059 / 10050). | MIT | Design + wire-format docs of unusually high quality; a live multi-thousand-node test mesh; `fips-mesh` 0.5.3 on crates.io |
| **nostr-vpn** (mmalmi / Martti Malmi) | 7-platform Tailscale-style VPN product on a perf-evolved FIPS fork (~3× upstream), signed-roster control plane, MagicDNS, exits, Cashu paid exits | MIT | The `nvpn-fips-core/-endpoint/-tcp` dataplane crates (published, wire-format-stable-ish, actively hardened) |
| **Marmot / MDK** | MLS (RFC 9420) over Nostr, adopted spec + MIT Rust impl (succeeded White Noise). Commits are the consensus log; admin policy and routing state live inside GroupContext as signed app-components | MIT (relicensed from AGPL) | The **spec**: kind 445 group events, NIP-59 Welcomes, kind 30443 KeyPackages, admin-policy + ACL-shaped app-components, MLS-exporter key derivation |

## The three-layer answer

Research resolved our "build on what?" question into a clean separation:

1. **Data plane** — *commodity, don't build from scratch, choose a supplier.*
2. **Control plane** — *the genuine gap and noscat's core contribution.* A NIP-draft:
   tailnet-as-MLS-group, per FIPS-compatible discovery, ACLs as GroupContext app-components.
3. **UX layer** — *the tailcat heritage nobody has cloned:* no-root, ephemeral
   bearer-capability addresses, netcat/port-forward/serve CLI on top.

## Decision matrix: data plane supplier

| Option | Pros | Cons |
|---|---|---|
| **A. Depend on `nvpn-fips-*` fork crates** | Best-measured dataplane (3× upstream), published on crates.io, MIT, actively hardened, wire-format-preserving | One-publisher ecosystem (exact-pinned 0.4.x), fork diverged from upstream FIPS, no compat promise |
| **B. Run upstream `fips` daemon, build on native API** | Multi-transport (Tor/Nym/BLE), independent maintainer, interop with FIPS mesh, npub:port API is *the intended* client surface | Daemon-first (ship a whole mesh daemon for 2-node tunnels), native API explicitly experimental/withdrawable, Unix-only, **datagrams only — no reliability layer** (a TCP-proxying tool must build its own), double encryption always |
| **C. Own thin data plane** (Noise XK over UDP + Nostr signaling mirroring FIPS kinds) | Minimal, embeddable, no daemon, full control; mirroring FIPS event formats buys interop | We write + maintain the hardest boring part; duplicate work two MIT impls already did |

**Leaning:** C for the netcat-style core (it is small: XK handshake + UDP socket mux + the
three FIPS-pattern Nostr events), with A/B as later interop targets rather than foundations.
This keeps noscat embeddable (no daemon requirement) which neither A nor B gives us.
Revisit if our throughput needs exceed a simple pipeline.

## Decision matrix: control plane implementation

| Option | Pros | Cons |
|---|---|---|
| **D. Depend on `cgka-engine` (mdk) via git** | Battle-tested engine, Tamarin-modeled convergence, MIT | `publish = false`, 0.19.0-dev churn, OpenMLS pinned to a git rev, chat-shaped runtime to bypass |
| **E. Implement the Marmot subset directly on OpenMLS** | Only the tailnet surface (identity proof, KeyPackages, admin-policy, ACL component), no chat runtime, we own the API | We own the convergence subtleties that mdk already solved |

**Leaning:** start with **E as the spec target and D as the reference implementation** —
design the tailnet components (`tailnet.acl.v1`, address assignment, liveness) as Marmot
app-components per its registry patterns; prototype against `cgka-engine` via git pin;
promote to a real dependency only when its publishing story stabilizes.

## What the tailnet control plane NIP-draft contains (sketch)

- Identity: nostr keypair per device (FIPS-compatible: same key signs events and Noise handshakes).
- Membership: MLS group per tailnet; join = Welcome (NIP-59) after admin approval
  (`admin-policy-v1` pattern); removal = Remove commit → MLS forward secrecy; per-epoch
  MLS-exporter-derived pre-shared keys rotate the data plane for free.
- ACLs: `tailnet.acl.v1` GroupContext component (per-npub/per-prefix policy), updated only
  by admin commits — strictly more than nostr-vpn's flat rosters, which lack ACLs entirely.
- Discovery/liveness: FIPS-pattern kind 37195-style signed replaceable endpoint adverts with
  NIP-40 expiry, gift-wrapped traversal signaling (21059 pattern) — candidate for interop
  with actual FIPS nodes.
- Naming: NIP-05 for `alice@domain → npub`, MagicDNS-style local resolution above that.

## Honest risks

1. **Everything interesting here is pre-1.0 and fast-moving** (FIPS native API "may be
   withdrawn in any release"; mdk `publish = false`; nostr-vpn exact pins). noscat must pin
   git revs and budget for churn — or be the stable spec while implementations churn.
2. **No security audits anywhere in the stack** (FIPS lists it as a near-term priority;
   nostr-vpn ships RUSTSEC fixes briskly but has none; Marmot has Tamarin models but no audit).
3. **Revocation latency** in MLS is convergence-bounded — a tailnet needs a local kill switch
   keyed to epoch state rather than waiting for commit fan-in.
4. **Scope gravity** — the defense is still spec-first: publish the event schema early so
   others (including nostr-vpn, which currently has zero NIP interop) can adopt it.
5. **Name collision**: "FIPS" collides with the US federal standard; keep noscat's naming clean.

## Immediate next steps

1. Decide data-plane supplier (A/B/C above) — the pivotal fork in the road.
2. Draft the tailnet MLS component schema against the Marmot app-component registry.
3. Prototype the netcat core (XK over UDP + three Nostr events, mirroring FIPS formats).
4. Open dialogue with FIPS and Marmot maintainers early — interop and component-registry
   coordination are cheap now and expensive later.
