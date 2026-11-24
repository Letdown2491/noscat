# noscat

A decentralized, trustless Tailscale built on Nostr: a user's devices form a private mesh and reach each other directly, with no account, no coordinator and no root.

## Language

**Device**:
One running noscat installation with its own Nostr identity (npub). Every device has a unique npub; identities are never shared between devices.
_Avoid_: node (except when talking about FIPS internals), host, client

**Mesh**:
The set of devices that may reach each other, represented as one Marmot (MLS) group.
_Avoid_: network, tailnet, group (except when talking about MLS itself)

**Member**:
A device currently in the mesh's roster.
_Avoid_: peer (a peer is any FIPS neighbor, member or not)

**Roster**:
The list of members as of the mesh's current MLS epoch. The roster is the authorization: only members are admitted.

**Admin**:
A member allowed to add and remove members. Normally every device in the mesh is an admin.
_Avoid_: owner

**Advert**:
A device's signed statement of where it can currently be reached. Shared only inside the mesh.
_Avoid_: announcement, beacon

**Stream**:
A reliable, ordered byte channel between two members, used by forwards, file transfer, chat and clipboard.
_Avoid_: tunnel (0.4 term)
