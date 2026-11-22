# Marmot / MDK research: MLS-over-Nostr as a tailnet control plane

Researched 2026-11-21. Sources: GitHub (marmot-protocol org), raw.githubusercontent.com spec/README text, crates.io API.

---

## 1. What mdk provides as a library

**Claim: mdk ("Marmot Development Kit") is the Rust implementation of the Marmot protocol — MLS (RFC 9420) group state machine + Nostr transport + app runtime — and succeeded whitenoise-rs.**
- Source: https://github.com/marmot-protocol/mdk (README): "MDK is the Rust implementation of Marmot… It powers White Noise: the protocol engine, encrypted storage, Nostr transport, the app runtime behind the mobile bindings, the `wn` command-line app, and the `wn-agent` connector."
- whitenoise-rs README now carries: "This repository is obsolete and is no longer updated. Use the crates in marmot-protocol/mdk instead." (https://github.com/marmot-protocol/whitenoise-rs, master README). Repo was archived (API: `"archived": true`, last push 2026-08-05).

**Claim: the layering is clean — the MLS engine knows nothing about Nostr.**
- From the README architecture diagram (https://github.com/marmot-protocol/mdk#how-mdk-is-built):
  - `cgka-engine` — OpenMLS-backed group state machine + commit convergence (generic over a storage trait; "knows nothing about Nostr")
  - `traits` (`cgka-traits`) — shared traits/cross-boundary types
  - `storage-sqlite` — SQLCipher persistence (one DB per account-device)
  - `transport-nostr-peeler` / `transport-nostr-adapter` / `transport-nostr` — Nostr event ⇄ engine message boundary, relay I/O, per-account relay sessions
  - `marmot-session`, `marmot-account` — account-device runtime, signing keys, secret storage
  - `marmot-app` — multi-account app runtime; `marmot-uniffi` (MarmotKit: Swift/Kotlin), `marmot-c` (C ABI), `cli` (`wn`, `wnd`, `wn tui`)
- Crate list verified from workspace `Cargo.toml` (https://raw.githubusercontent.com/marmot-protocol/mdk/master/Cargo.toml) and `crates/` directory listing.

**Claim: crates.io publishes exist, but they are from an older repo layout and are now stale (master is `publish = false`).**
- Published crates (crates.io API, https://crates.io/api/v1/crates?q=mdk):
  - `mdk-core` 0.8.0 (2026-05-04), MIT, ~18.2k downloads — "A simplified interface to build secure messaging apps on nostr with MLS"
  - `mdk-storage-traits` 0.8.0, `mdk-sqlite-storage` 0.8.0, `mdk-memory-storage` 0.8.0, `mdk-macros` 0.8.0
  - Version history: 0.6.0 (2026-02-23), 0.7.0/0.7.1 (2026-03), 0.8.0 (2026-05-04). Nothing published since May 2026.
- Current master `Cargo.toml`: `[workspace.package] version = "0.19.0-dev", license = "MIT", publish = false`. The crates named `mdk-core`/`mdk-sqlite-storage` no longer exist in the workspace; they were renamed/superseded (`cgka-engine`, `storage-sqlite`, `marmot-session`, …). So **you cannot `cargo add mdk-core` and get the current code** — the published line is ~11 minor versions behind and does not match master's API.
- Master pins OpenMLS to a **git rev, not a release**: `openmls = { git = "https://github.com/openmls/openmls.git", rev = "6100df3…" }` because no OpenMLS release yet contains needed fixes (Cargo.toml comment cites openmls#2133, #2249, #2261, RUSTSEC-2026-0387 etc.).

**Claim: as of today, mdk is usable as a dependency only via git dependency or vendoring, and its API is moving fast.**
- Releases: `v0.18.0` (2026-11-20) plus per-artifact tracks (`marmotkit-v0.18.0`, `marmotc-v0.18.0`, `wn-agent-v0.18.0`); daily nightlies at 0.19.0 (GitHub releases API). README: "MDK versions the whole workspace as one compatibility cohort", with per-release upgrade guides (`docs/integration/0.18.0.md` is "the latest").
- API surface is broad but messaging-app-shaped: accounts, groups, messages, KeyPackages, device linking, agent connectors — not a generic group-keyring library. `marmot-c` (C ABI) and MarmotKit (UniFFI) exist if a non-Rust control plane wanted to embed it.

**Claim: usable today by an unrelated project? Conditionally.**
- MIT license removes friction, and `cgka-engine` + `cgka-traits` + `transport-nostr-peeler` are (per README) engine/transport-separated and WASM-compilable. But: no crates.io releases of the current crates, git-pinned OpenMLS, `0.19.0-dev` churn, and the runtime crates (`marmot-app`, `marmot-session`) are opinionated about accounts/SQLCipher/relays. A VPN control plane would realistically depend on `cgka-engine` via git and write its own transport adapter — or depend on nothing and re-implement the spec.

---

## 2. How MLS-over-Nostr works in the spec

Primary source: https://github.com/marmot-protocol/marmot (spec "Status: adopted"), especially `transports/nostr.md` (~48 KB, adopted). All claims below cite that file unless noted.

**Event kinds used (transports/nostr.md, "Event identity and tag cardinality" + sections):**

| Kind | Purpose | Key rules |
| --- | --- | --- |
| `445` | Group MLS messages (commits, proposals, app messages) | `h` tag = random `nostr_group_id`; **pubkey MUST be a fresh ephemeral key** per event, never the sender identity; content = base64(nonce ‖ ChaCha20-Poly1305 ciphertext of the MLS message under `group_event_key = MLS-Exporter("marmot", "group-event", 32)`) |
| `1059` ⊃ `13` seal ⊃ `444` rumor | Welcome delivery (and pairing, push) | NIP-59 gift wrap addressed to invitee's Nostr pubkey; published to invitee's kind `10050` inbox relay list (NIP-17 re-use) |
| `30443` (addressable) | KeyPackage publication | content = base64 `MLSMessage` with `mls_key_package` wire format; tags `d` (random publication-slot id), `i` (KeyPackageRef), `mls_ciphersuite`, `mls_extensions`, `mls_proposals`, `app_components`, optional NIP-89 `client` |
| `5` (NIP-09) | KeyPackage slot/publication deletion | `a` = `30443:<author>:<d>` or `e` = event id, `k` = `30443` |
| `10002` / `10050` | NIP-65 relay list / NIP-17 DM inbox list | discovery: KeyPackages go to `10002` write-capable relays; Welcomes go to `10050` inbox relays |
| `30078` (NIP-78) | Encrypted backup pointer | address derived from recovery-key public half |

**Group epochs/commits propagate as data, not consensus-by-relay:**
- "In Marmot, commits are the consensus log. Clients fetch from several relays, see messages in different orders… The engine — not relay order or timestamps — picks the canonical branch." (mdk README, "How convergence works"; spec: `protocol-core/convergence.md`, `protocol-core/group-state.md`).
- Kind `445` envelope carries **no epoch hint**; receivers trial-decrypt against retained candidate states (canonical epoch, rollback horizon, staged local commit) — "Outer decryption and epoch selection". Relay event ids/timestamps/order are "transport evidence" and "MUST NOT choose group state".
- Redundant delivery is mandatory: "Marmot transports MUST support redundant delivery" — sender MUST fan out every signed group event to every relay in the group's `marmot.transport.nostr.routing.v1` component (`nostr_group_id` + canonical relay list, in GroupContext `app_data_dictionary`); the obligation persists across restarts until each target is attempted ("Publish targets and acknowledgements"). Routing state itself is signed group state (`app-components/nostr-routing-v1.md`) and can rotate via commits.

**Relay requirements:** relays are dumb and never decrypt; SHOULD accept ≥2 MiB events (Welcome gift wraps carry the ratchet tree and are ~3× MLS Welcome size; sizing analysis supports roughly ~1,900-member groups on 2 MiB relays, ~56–81 members on 64 KiB relays — "NIP-44 and event size"). No dedicated Marmot relay software required.

**Privacy properties — metadata minimization is explicitly engineered:**
- Kind `445`: sender identity hidden (fresh ephemeral key per event); group id is random and "not derived from any member key, so it does not link members across groups"; **no recipient/member list is exposed** — content is encrypted under the per-epoch group-event key, so relays see only size/timing. There is no member-addressed fanout for group messages at all (unlike NIP-17-style per-recipient wrapping).
- Welcomes/pairing/push: NIP-59 gift wrap + seal hide sender and inner rumor; the only deliberate exception is the inbox `p` tag = recipient identity ("Metadata exposed to the transport": "the inbox address is the deliberate account-addressing exception").
- Known leaks, self-declared: KeyPackage events (`30443`) are account-signed (that's their purpose), and slot count roughly reveals device count; optional `client` tag reveals client software; kind `445` `expiration` tag (when retention enabled) reveals the retention policy; a non-member can spam kind `445` envelopes to reach trial decryption (no member-authenticated prefilter).
- Answering "gift wrap used?": **yes** — NIP-59 (`1059`/`13`/rumor) for all account-directed messages (Welcomes, pairing, push); gift-wrapping is used for 1:1 delivery, group messages instead use the shared per-epoch key envelope (kind `445`).

---

## 3. Key management

**Claim: identity = Nostr pubkey; MLS leaf keys are separate and provably bound to it.**
- "Marmot account identity is a Nostr public key" (32-byte x-only secp256k1) — `foundation/identity.md`.
- "The MLS signature key for a leaf is not the Marmot account identity." Every LeafNode/KeyPackage MUST carry `marmot.member.account-identity-proof.v2` (`0x8009`), a component that "proves the account named by the BasicCredential authorized the leaf's MLS signature public key" — implemented via a signed Nostr event (`app-components/account-identity-proof-v2.md`). Clients MUST reject leaves with missing/invalid proofs.

**Claim: per-device key hygiene is strict.**
- One MLS leaf per account-device per group; devices never share MLS secrets ("A client MUST NOT copy MLS group state, leaf secrets, or KeyPackage private key material to another device") — `foundation/identity.md` "Devices".
- KeyPackage lifecycle (`foundation/key-packages.md`): one random publication slot (`d`) per device, never derived from identity material; `init_key` private material never published; KeyPackages refreshed at least every 7 days, Lifetime ≤ 30 days + 1 h skew; refresh after a Welcome consumes one; slot monitored for rogue republication (a "publication the device did not make" triggers outrank-or-delete).

**Claim: rotation and forward secrecy — yes, inherited from MLS plus protocol-level departures.**
- Group keys evolve per-epoch through MLS commits (the kind `445` outer key is itself re-derived per epoch: "group_event_key is scoped to one MLS group epoch" — nostr.md). Member removal is done via MLS Remove proposals in a Commit, so the removed member cannot derive the new epoch secrets → **standard MLS forward secrecy / post-compromise guarantees apply on removal**.
- The spec adds protocol-core departure flows on top: `SelfRemove` (MLS extensions proposal), admin removal, and removal by a sibling device; a removed member runs a "Realizing removal" flow (`protocol-core/member-departure.md`). Multi-device accounts are removed leaf-wise; removing an account requires removing *all* its leaves in one Commit.
- Leaf rotation on device compromise: each device can update its own leaf; admin-policy coupling rules keep the admin list consistent with membership (`app-components/admin-policy-v1.md`).

---

## 4. Suitability as membership/key-distribution layer for a mesh-VPN tailnet

**What fits well:**
1. **Membership as MLS epochs.** Devices joining/leaving = Add/Remove proposals + Commit; every honest client converges to the same epoch ("commits are the consensus log"). A tailnet's member set is exactly a continuously-agreed group state.
2. **Admin approval is first-class.** `marmot.group.admin-policy.v1` (`0x8003`) puts a sorted admin pubkey list *inside GroupContext app_data_dictionary*; only active admins may commit invites, removals, or component changes ("Admin-Gated Actions"). Device-link limits and pairing approvals similarly live in group state (`features/device-group.md`, `device-pairing.md`). This is exactly "admin approval" for tailnet enrollment.
3. **ACLs fit the extension mechanism.** Marmot's app-component system is the designed way to attach versioned state to GroupContext (20+ components exist: `admin-policy-v1`, `nostr-routing-v1`, `device-roster-v1`, `group-lifecycle-v1` disband, `message-retention-v1`…). A `tailnet.acl.v1` component (nodes, prefixes, allowed routes) would be the natural analogue to `nostr-routing-v1` — signed group state, updated only by admin commits, validated on every Commit.
4. **Key distribution = MLS exporter.** Any symmetric tailnet traffic key (e.g. WireGuard pre-shared keys) can be derived via `MLS-Exporter`, the same primitive Marmot uses for kind-`445` envelope encryption — per-epoch PSK rotation falls out of membership commits.
5. **Metadata privacy.** Random group id, ephemeral sender keys, no member list on group events; relays can't enumerate a tailnet's membership from kind-`445` traffic.
6. **Optional-transport design.** The spec explicitly keeps identity/content/key-agreement independent of relay transport ("Transport beyond that stays agnostic… transports MUST support redundant delivery", marmot README) — a VPN control plane could run the same engine over QUIC (a `transports/quic.md` binding existed) instead of Nostr relays.

**What is messaging-specific / needs extension:**
1. **No crates.io releases of current code** (§1) and a fast-moving 0.x API — dependency risk for a control plane that wants stability.
2. **Message-oriented runtime.** `marmot-app`/`marmot-session` assume chat accounts, NIP relay sessions, SQLCipher homes, markdown, media. A VPN control plane wants just `cgka-engine` + a thin session loop; expect to bypass or fork the app runtime.
3. **No network-config primitives.** IP/prefix assignment, node liveness/heartbeats, key.rotation cadence for data-plane keys, and ACL data-models are absent — all must be new app components with registry ids, following `nostr-routing-v1`/`admin-policy-v1` patterns (spec: registries, capability negotiation — every member's KeyPackage must advertise the new components, so old clients can't join a tailnet group that requires ACLs).
4. **Convergence latency vs control-plane responsiveness.** Marmot's commit convergence tolerates forked/branched state deliberately (offline-first), with `PendingPublish`/`Merging`/`Recovering` lifecycle states and trial-decryption retries. ACL revocation latency ("kick device now") depends on commit fanout + fan-in; a tailnet may want a hard local kill switch keyed to local epoch state rather than waiting for convergence.
5. **Group size economics.** Welcome gift wraps carry the full ratchet tree; sizing analysis (~1,900 members on 2 MiB events) is fine for a tailnet but the per-join cost is O(tree) — fine at ≤ hundreds of devices.
6. **Relay availability model.** Multi-relay redundant fanout is mandatory; a tailnet control plane would need to run its own "relay" equivalents (or adopt the retired QUIC binding) rather than depend on public Nostr relays.

---

## 5. License, maintenance, adoption

**License:** MIT — mdk workspace `Cargo.toml` (`license = "MIT"`) and GitHub API (`spdx_id: "MIT"`); mdk README License section: "[MIT](LICENSE)". The marmot spec repo is also MIT. (By contrast, the archived whitenoise-rs was AGPL-3.0 — the relicensing to MIT happened with mdk.) Published `mdk-core` on crates.io: MIT.

**Maintenance (very active):**
- mdk: created 2025-09-12; last push 2026-11-22 (day of research); 317 open issues (high throughput, not neglect); releases `v0.18.0` 2026-11-20 plus daily nightlies; formal Tamarin models, conformance simulator, and nightly convergence campaigns in-repo (README "Development", `formal/`, `crates/cgka-conformance-simulator`).
- marmot spec: last push 2026-11-21; "Status: adopted" spec with per-surface normative docs.
- whitenoise-rs: archived, last push 2026-08-05.

**Adoption:**
- Stars: whitenoise-rs 442 (legacy), marmot 151, mdk 73, keycast 28. Bindings/repos across Kotlin, Swift, Python, Ruby, TS, web (`mdk-kotlin`, `mdk-swift`, `mdk-python`, `mdk-ruby`, `mdk-web`, `marmot-ts`).
- `awesome-marmot` (https://github.com/marmot-protocol/awesome-marmot): claims 32 client apps, 8 SDKs, 16 agent integrations for "Marmot v2" — including third-party wallets (Sessions Wallet, coinos v3, Fedimint-adjacent Chascuro) and independent MLS/Marmot implementations in JS/TS (Textor on ts-mls), plus MDK-compiled-to-WASM usage (FreedomStack).
- crates.io: `mdk-core` ~18k downloads total — modest but real third-party usage; a third-party "NMP" crate (`nmp-marmot` 1.0.0-rc.1, "Marmot Protocol (MLS-over-Nostr) as a Layer-4 NIP crate. Sole importer of mdk-core/openmls") shows outsiders building on the stack.

---

## Verdict for noscat

**The protocol is an unusually good conceptual fit for a tailnet control plane; the current code drop is not yet a drop-in dependency.**

- The hard cryptographic problems a VPN membership layer faces — admin-approved enrollment, device joining/leaving, per-epoch key distribution with forward secrecy on removal, and tamper-proof group state that all nodes converge on — are exactly what Marmot specifies and MDK implements, with formal verification effort (Tamarin) behind the convergence model. Admin policy and signed routing state already live *inside* GroupContext, so an ACL component is following the grain of the design, not fighting it.
- The MLS engine (`cgka-engine`) is deliberately transport-agnostic and MIT-licensed; the Nostr transport binding documents every event kind precisely enough to re-implement over QUIC/HTTP if public relays are unwanted.
- Risks: (a) no crates.io releases of the current workspace (`publish = false`, `0.19.0-dev`) — a noscat dependency would pin a git rev and absorb churn; (b) the app runtime is chat-shaped and would be largely bypassed; (c) tailnet-specific state (address assignment, ACLs, liveness) is a spec-extension project (new registry ids, components, capability negotiation), and (d) revocation latency is bounded by convergence, not instant.
- Recommendation: treat Marmot/MDK as the reference for *protocol shape* (MLS epochs + signed GroupContext components + exporter-derived data-plane keys) and either (1) track `v0.18.0`+ via git dependency on `cgka-engine` with a custom transport adapter, or (2) implement the subset of the spec (foundation identity/key-packages + a custom transport + a tailnet ACL component) directly on OpenMLS, using MDK's engine as the reference implementation.
