---
status: accepted
date: 2026-11-23
---

# Membership is enforced by FIPS peer admission, not a handshake PSK

In 0.4 the MLS exporter secret became the Noise `psk0`, so a removed device failed every handshake cryptographically. FIPS sessions have no PSK slot, so in 0.5 each device feeds the current MLS roster into FIPS peer admission (`configured_only` plus `update_peers`), and a device drops a removed npub as soon as it merges the commit. This is equivalent in practice, since a removed device keeps its own key either way and admission is what stops it, but it depends on every remaining member enforcing the roster rather than on the math alone.

## Consequences

- Revocation latency is the time for each member to merge the removal commit. The FIPS call itself is a revocation barrier (0.3 ms in the spike), so the delay is all control-plane propagation.
- A member that never receives the commit keeps admitting the removed device. Commit delivery must be reliable (relay ACK checks and resend carry over from 0.4).
- A PSK or channel-binding hook in FIPS would restore the cryptographic property; worth proposing upstream, not required.
