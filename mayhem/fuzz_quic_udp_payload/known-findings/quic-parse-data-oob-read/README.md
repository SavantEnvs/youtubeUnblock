# quic_parse_data reads the source-connection-id length one byte past the packet

**Cause.** `src/quic.c` `quic_parse_data()` checks `left_len < 2` before reading the destination connection
id length, then consumes `dst_len` bytes and reads `src_len = *cur_rawptr++` without checking that a byte is
left. A QUIC long header that ends exactly after the destination connection id reads one byte past the
buffer (`quic.c:134`).

**Impact.** 1-byte heap over-read on any UDP/443 payload that looks like a QUIC long header. Same parser family as the
upstream fixes `1b62bb6cb2` and `aefabe7e0a`.

**Fix.** `if (left_len < 1) goto invalid_packet;` before `nqci.src_len = *cur_rawptr++;`.

Run: `/mayhem/fuzz_quic_udp_payload-standalone repro`.
