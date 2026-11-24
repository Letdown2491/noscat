<!-- Note to you: feature request. It describes noscat's design (adverts
carried inside an MLS group instead of public relays); trim if you'd rather
not describe the project yet. Text to send is below the line. -->

---

**Title:** External peerfinding: allow traversal offers/answers to be carried outside FIPS sessions

With `NostrPeerfindingSource::External`, the app carries signed adverts itself
(`local_nostr_discovery_advert_event` out, `ingest_nostr_event` in). We use
this to keep adverts private: they travel inside an end-to-end encrypted
group instead of being published to public relays.

That works for reachable nodes, but not for first contact between two NATed
nodes. A NATed node advertises `{"transport":"udp","addr":"nat"}`; its
public address only appears in a traversal offer, and in External mode
offers and answers travel only as `MeshTraversalSignal` over existing FIPS
sessions. Two NATed nodes with no reachable node in common therefore have no
path for the first offer.

### Measured (0.4.124, network namespaces, nftables NAT)

| A | B | Reachable member C | A to B |
|---|---|---|---|
| cone | cone | none | never connects |
| cone | cone | yes | connects, then punches a direct link |
| cone | symmetric | yes | connects, transit via C |
| symmetric | symmetric | yes | connects, transit via C |

So FIPS does all the hard parts once one reachable node exists. The gap is
only the bootstrap signal.

### Request

An External-mode hook for traversal signaling, mirroring adverts:

- an outbound stream (or callback) of traversal offers/answers the node wants
  delivered to a given peer, as signed events or opaque blobs, and
- an ingest call for offers/answers received out of band.

The app would then carry them over its own channel (for us, the same
encrypted group as the adverts). Cone NATs could punch with no reachable
node, and nothing has to touch public relays.

If something like this already exists, or you'd prefer a different shape
(for example, letting the app supply the relay transport for kind 21059
only), I'm happy to work with that and to help test.
