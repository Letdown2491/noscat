---
status: accepted
date: 2026-11-23
---

# Endpoint adverts travel inside the mesh, not on public relays

FIPS normally publishes kind 37195 adverts (endpoint IPs and ports) to public relays, which ties a device's home IP to its npub in public, permanently. A private mesh has no reason to do that. noscat runs FIPS with `peerfinding_source: External`, takes the signed advert from `local_nostr_discovery_advert_event()`, ships it to members inside the Marmot group (encrypted with the epoch key), and members feed received adverts back with `ingest_nostr_event()`.

## Consequences

- Relays see only Marmot's kind 445 traffic: random group id, ephemeral sender keys, no member list, no endpoints.
- Adverts are still the ordinary signed FIPS events, so this stays wire-compatible with FIPS; only the delivery path changes.
- In External mode, hole-punch coordination runs over existing FIPS sessions. Two NATed devices with no reachable member in common may not be able to make first contact; this is the main open question for 0.5.0 (see the plan) and may require keeping relay-based signaling as a fallback.
- An opt-in public mode (advertise on relays so anyone can dial by npub) remains possible for the netcat-style "reach this npub" use case.
