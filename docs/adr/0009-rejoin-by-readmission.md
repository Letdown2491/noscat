---
status: proposed
date: 2026-11-26
---

# A member that fell behind rejoins by re-admission, committed automatically

A device can end up in the roster without a usable group state: it missed commits that no relay keeps any more (noscat-relay prunes group messages after 30 days), an island it was on lost by more than the 5 commits a member can rewind (ADR 0007), or it never opened its Welcome. Its group's events keep arriving (the routing id does not change with the epoch) but none decrypt, its FIPS roster goes stale (ADR 0005), and to everyone else it just looks offline. MLS has no way back for it within its old leaf.

Such a device notices it is behind (undecryptable events for its routing id that persist past catch-up while its epoch stays put), publishes a fresh key package, and sends a rejoin request: a gift-wrapped request to the members, signed by its own key (join requests themselves go in 0.7.0, ADR 0010; a rejoin request comes only from a device already in the roster). Any member that receives one from an npub in the current roster commits a re-admission: one commit that removes the device's old leaf and adds its fresh key package, with no prompt. The device accepts the Welcome for the mesh it is already in (from a member of that mesh) and replaces its state. A member that never opened its Welcome is answered the same way once its Welcome deadline has passed.

## Considered options

- **Members republish the commits they applied**: keeps the old leaf, but every member would have to store commit events for as long as a device might be away, which contradicts the decision to keep no event store on devices (`docs/plan-0.7.0.md`), and it cannot help past the rewind limit.
- **Ask a person, like a join request**: the device that is stuck cannot reach anyone through the mesh (it reads nothing), and the person who would approve it sees only an offline member. Most stuck devices would stay stuck.
- **Remove and invite by hand**: works today, but the user has to notice first, and the device has to be in `noscat join` at the right moment.
- **Automatic re-admission (chosen)**: heals on its own whenever the device and any member are online.

## Consequences

- The rejoin request is a wire addition (`docs/nip-noscat.md`), and `join` gains a path that replaces an existing group state.
- Only npubs in the current roster are re-admitted. A removed device is not in the roster, so a rejoin request gives it nothing. A compromised member could already add and remove devices (ADR 0007), so this grants it nothing new.
- A re-admitted device starts at the current epoch with fresh secrets; noscat keeps no group history, so nothing is lost.
- Two members answering the same request race like any two commits and converge by ADR 0007; the loser's commit is superseded, not retried, if the device is already re-admitted.
