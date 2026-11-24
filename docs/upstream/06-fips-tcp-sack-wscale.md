<!-- Note to you: optional courtesy report for github.com/mmalmi/fips-tcp.
noscat doesn't depend on this being fixed (it uses QUIC). Text to send is
below the line. -->

---

**Title:** Throughput under latency and loss (no window scaling or SACK)

Measured `nvpn-fips-tcp 0.2.6` / `nvpn-fips-tcp-endpoint 0.2.58` between two
in-process FIPS endpoints on loopback with `tc netem`, sha256 verified on every transfer (correctness was perfect, including
3% loss with 10% reordering):

| Link | Throughput |
|---|---|
| clean loopback | 355 Mbit/s |
| 50 ms RTT | 8.9 Mbit/s |
| 50 ms RTT, 1% loss | 1.9 Mbit/s |
| 50 ms RTT, 3% loss | 0.8 Mbit/s |
| 50 ms RTT, jitter, 3% loss, 10% reorder | 0.6 Mbit/s |

The 50 ms figure matches a 64 KB window with no window scaling
(64 KB / 50 ms is about 10 Mbit/s), and the loss figures look like
go-back-N style recovery without SACK. For comparison, quinn (BBR) over the
same FIPS datagrams on the same links did 166 / 154 / 156 Mbit/s at
0 / 1 / 3% loss.

Not asking for anything specific, just sharing numbers in case window
scaling (RFC 7323) and SACK (RFC 2018) are on your list.
