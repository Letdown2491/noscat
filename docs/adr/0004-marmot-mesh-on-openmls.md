---
status: accepted
date: 2026-11-23
---

# The mesh is a Marmot group, implemented by us on published OpenMLS

A mesh is now a Marmot-compatible MLS group (spec at marmot-protocol/marmot, reference implementation MDK): kind 445 group events encrypted with the per-epoch exporter key, random group ids with the `marmot.transport.nostr.routing.v1` component, 444 Welcomes in 1059 gift wraps to kind 10050 inbox relays, 30443 key packages, and the Marmot admin-policy component for multiple admins. We implement only the subset a mesh needs, on published OpenMLS, behind a noscat-owned `MeshGroup` seam, and run MDK as a git dev-dependency in CI to prove interop.

## Considered Options

- **Keep the 0.4 custom scheme** (kind 30444 rumors gift-wrapped to each member, group id = owner npub, single-owner `0xffa0` extension). Rejected: relays can read the membership graph from per-member wraps, the owner device is a single point of failure, and it interoperates with nothing.
- **Depend on MDK's `cgka-engine` directly.** Best convergence story (formal models, conformance simulator), but MDK is not on crates.io and pins OpenMLS to a git revision, which breaks ADR 0001. Revisit if MDK publishes; the `MeshGroup` seam makes that a local swap.
- **Build on MDK's `marmot-app` runtime.** Chat-shaped (multi-account, SQLCipher homes, media, push); a mesh would bypass most of it.

## Consequences

- Target OpenMLS 0.10 (0.10.0-rc.1 published 2026-11-23). On 0.8.x, noscat carried 10 `cargo audit` vulnerabilities through `hpke-rs`/`libcrux-*`, `libsqlite3-sys` and `crypto-bigint`; 0.9.2 cuts that to 4, and 0.10's dependency line (p256 0.14, rusqlite 0.41) should clear the rest. 0.10 also carries the last-resort key package encoding Marmot uses.
- Every device in the mesh can be an admin, so losing any one device never locks the mesh.
- Our own Marmot app component carries mesh state (endpoint adverts, ADR 0006) using an id in Marmot's private range (at or above `0xf000`).
- We own convergence subtleties MDK has already solved; the MDK interop suite in CI is the guard.

## Updates (2026-11-24, as implemented)

- MDK interop is checked by a standalone harness, `tests/mdk-interop/run.sh`, which builds MDK's `wn` CLI at a pinned commit in a container. It is not a dev-dependency, so the published crates never see MDK, and it runs by hand rather than in CI. Both directions pass.
- Endpoint adverts travel as Marmot application messages (kind 21195), not in a component. The noscat component (`noscat.mesh.v1`, `0xf3a0`) holds only the mesh name and is not required, so other Marmot clients can join a mesh.
- OpenMLS 0.10.0-rc.1 with in-memory storage persisted to one file: rusqlite and the OpenMLS sqlite storage are gone, and `cargo audit` reports no vulnerabilities (only upstream unmaintained or unsound warnings, listed in the 0.5.0 plan).
