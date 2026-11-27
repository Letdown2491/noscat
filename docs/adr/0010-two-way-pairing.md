---
status: proposed
date: 2026-11-26
---

# Joining is a two-way exchange of pairing codes, approved by any member

Until 0.7.0 a joiner scans a member's code, sends a join request over the relays, and someone approves the prompt. Information flows one way: the mesh learns the joiner's npub only from the request. For a private mesh with no DNS (`docs/plan-no-dns.md`) that is a problem: the relay is reached over FIPS, FIPS admits only configured npubs (`configured_only`), and the relay host cannot admit a joiner it has never heard of.

From 0.7.0 the codes go both ways. The joiner scans or pastes any member's code (that member's npub is its trust anchor; for a private mesh the code also names the relay host's npub and address). A member scans or pastes the joiner's code, and that act is the approval. Any member may approve, since every device is an admin (ADR 0007). The approval is recorded in the group with an expiry and is single use; on a private mesh the relay host then admits the joiner's npub in FIPS as a pending joiner, confined to the relay's service port, and any online member commits the Add once the joiner's key package is in hand. The joiner accepts a Welcome for a mesh in which the member it scanned is a member. Join requests go, on every mesh.

## Considered options

- **Plain `ws://` listener for the join**: signed and gift-wrapped events keep it safe from forgery and reading, but anyone on the path sees the joiner's and the inviter's npubs, the relay faces the internet, and a member that logs in over it can have its login reused by someone in the middle.
- **A one-time guest key in the inviter's QR**: keeps one-way pairing, but puts a secret in the QR and adds a second identity on the joiner (its dataplane runs as the guest, then restarts). Any one-way exchange needs some such credential; only a two-way exchange needs none.
- **The inviter makes the joiner's key and hands it over**: every member is an admin, so a leaked QR would be a permanent admin of the mesh, and the new device's whole identity would have been seen by another.
- **Pinned relay certificates**: encrypt the path to a relay on a bare IP, but keep the relay on the internet and a key file that must never be lost; the FIPS path gives the same with no certificate.
- **Two-way exchange, any member approves (chosen)**: no secret in any code, approval before the joiner can send anything, and the relay need not face the internet.

## Consequences

- Pairing takes two scans side by side, or two messages remotely. A headless machine prints its code as a terminal QR and takes codes pasted over SSH; a mesh of only headless machines adding its first phone needs the phone's code pasted in.
- A pasted code is checked by a short code derived from the joiner's npub, shown on both screens.
- FIPS admission no longer always means membership: the pending joiner is the one exception, and the data plane must confine it to the relay's service port, for one join, for 15 minutes at most.
- The prompt anyone who knows a member's npub could trigger disappears with join requests. The rejoin request (ADR 0009) remains, from devices already in the roster only.
- A lost or stolen member can approve devices, as it could already invite them; removing it ends that, and members see who added whom.
