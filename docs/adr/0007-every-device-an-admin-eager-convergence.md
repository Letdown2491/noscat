---
status: accepted
date: 2026-11-24
---

# Every device is an admin; commits apply eagerly and roll back on a lost race

In 0.4 one owner device made every membership change, so a lost or offline owner froze the mesh. In 0.5 every device is a Marmot admin: an add puts the new device in the admin policy (0x8003) in the same commit, a remove takes it out. Any member can add or remove devices; there is no single point of failure. The trade is that any compromised device can remove the others, which matches the trust model of a personal mesh (all devices belong to one person or a small group that trusts each other).

With many admins, two devices can commit at the same epoch. Marmot's convergence rule picks one branch (depth with a witness boost, then witness score, then privileged before ordinary, then the lower committer key, then the lower commit digest). MDK waits for a settlement window before applying a commit. noscat applies a commit as soon as it arrives, keeps a storage snapshot of the parent state for each of the last 5 commits, and when a valid competing commit for an older epoch arrives, replays it on the snapshot, compares the two branches by the same order, and rolls back if the competitor wins. Our own commit that lost is reported (`Change::Superseded`) so the caller can retry it.

## Considered options

- **Owner-only commits (0.4)**: simple and race-free, but the owner is a single point of failure, and the user asked for any device to manage the mesh.
- **Settlement window before applying (MDK)**: never rolls back, but every membership change and every roster update to the data plane waits for the window. For a VPN-style mesh, admitting a new device immediately matters more.
- **Eager apply with rollback (chosen)**: changes take effect at once; races, which need two admins committing within seconds of each other, cost a rollback.

## Consequences

- After input settles, noscat and MDK agree on the winning branch, so mixed groups converge.
- State keeps up to 5 full storage snapshots. Mesh groups are small, so this is a few hundred kilobytes at most.
- A branch older than 5 commits is never rewound; a device that was offline longer joins the branch it finds.
- Leaving needs two steps: an admin steps down (another admin must remain), then sends a SelfRemove proposal for another member to commit. The last device of a mesh just forgets it locally.
