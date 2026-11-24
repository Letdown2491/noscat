<!-- Note to you: the evidence is indirect (quinn's loss counter plus the
warm-up experiment), and the issue says so. Text to send is below the line. -->

---

**Title:** First service datagram to a peer is dropped while the session is set up

When a node sends the first service datagram to a peer it has an adjacency
with but no end-to-end session yet, that datagram appears to be dropped
rather than queued until the session is up.

### What we see (0.4.124)

Two in-process endpoints on loopback, each with the other in `update_peers`,
waiting until `peers()` shows the adjacency `connected`. Then quinn connects
over `send_datagram`:

- Cold: the QUIC handshake takes 1003 ms and quinn reports exactly 1 lost
  packet, every run. That's quinn's initial probe timeout: its first Initial
  vanished.
- After first sending one throwaway datagram to an unregistered port on the
  peer and waiting about 50 ms: handshake 2 ms, 0 lost packets.

So the adjacency being `connected` isn't enough for the first datagram to
arrive. I haven't traced the exact drop point in the code.

### Why it matters

Any request/response protocol over `send_datagram` pays a full retransmit
timeout (about 1 s for QUIC) on first contact with each peer, and simple
fire-once datagrams are lost outright.

### What would help (any of)

1. Queue a small number of datagrams per peer while the session is being
   established and send them when it completes.
2. Or expose a "session ready" signal (an event, or a field on
   `FipsEndpointPeer`) so callers can wait instead of guessing.
3. Or return an error from `send_datagram` when the datagram can't be sent
   yet, so callers know to retry.

We currently send a warm-up datagram and sleep, which works but is a guess.
