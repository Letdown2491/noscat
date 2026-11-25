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
_Avoid_: tunnel

**Key package**:
A device's published, single-use offer to be added to a mesh. A device not in a mesh keeps one on its relays.

**Mesh relays**:
The Nostr relays a mesh lists in its group state, which every member uses for its control traffic. A device may use its own relays too, unless the mesh is private.

**Private mesh**:
A mesh whose devices use only the mesh relays, log in to them with their device key, and use no other relay. Meant for a members-only relay the user runs. The opposite is a shared mesh.
_Avoid_: closed mesh, locked mesh

**Invitation**:
What a device receives when an admin adds it: the encrypted welcome into the mesh. A device accepts an invitation only from the device it was told to expect.
_Avoid_: pairing request

**Join request**:
A joining device's message to the member whose QR it scanned, asking to be invited. It grants nothing by itself: a member still has to invite the device.
_Avoid_: key package (that is what makes the invitation possible, not the request)

**Leave**:
A member asking the others to remove it. Someone else completes it; the last device of a mesh just forgets the mesh.

**Reachable device**:
A member that the others can reach directly from the internet (a forwarded port, a server, a public IPv6 address). Every mesh needs at least one; members behind NAT reach each other through it when they cannot connect directly.
_Avoid_: relay (that is a Nostr relay), server, exit node

**Default service**:
What a member exposes to the rest of the mesh without naming a port, such as a local web server or the far end of a netcat session. Other local ports are reachable only if the member serves them by number.
