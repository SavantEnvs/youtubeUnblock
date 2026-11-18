# log_packet dereferences a NULL ip6h under --trace for a non-IPv4/IPv6 version nibble

**Cause.** `src/dpi.c` `log_packet()` (called from `process_packet` when the trace level is on) takes the
IPv6 branch for anything whose `ipver` is not IPv4 and dereferences `pkt->ip6h`, which is NULL when the
packet's version nibble is neither 4 nor 6 (`process_packet` logs before it rejects the packet).

**Impact.** Crash of the daemon with `--trace` on a packet with a bad IP version.

**Fix.** Return early in `log_packet` when `pkt->iph == NULL && pkt->ip6h == NULL`.

**Not reproduced by the committed harness.** `fuzz_process_packet` caps the preset trace level at debug
(`trace_ok = 0` in `mayhem/common.h`) so this crash does not hide everything behind it. The wrapped
targets (`fuzz_tcp_payload`, `fuzz_quic_udp_payload`) build well-formed headers and run the trace preset,
which covers the UDP/TCP logging path instead.
