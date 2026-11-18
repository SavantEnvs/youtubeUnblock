# ip6_payload_split accepts an IPv6 payload length that runs 40 bytes past the buffer

**Cause.** `src/utils.c` `ip6_payload_split()` checks `buflen < ntohs(ip6_plen)`, but `ip6_plen` does not
include the 40-byte IPv6 header, so a packet whose `ip6_plen` is up to 40 bytes larger than the bytes
actually present passes the check. `transport_payload_len` is then 40 bytes too long and every parser
downstream reads past the end of the buffer. (The IPv4 twin, `ip4_payload_split`, compares against `tot_len`
correctly.)

**Impact.** Heap over-read of up to 40 bytes while parsing a TCP/UDP payload. Every `fuzz_process_packet`
defect except the NULL dereference in `tcp-short-doff-null-iph` is this one cause: each crashing input has
`ip6_plen` larger than the bytes after the IPv6 header, and rewriting `ip6_plen` (and the UDP length) to the
real size makes all 18 recovered inputs run clean. The frames differ only in which downstream code reads the
missing bytes first (one reproducer each; `process_packet` is the entry for all of them):
- `repro-tcp6-split`: `utils.c:277` `tcp6_payload_split` reads `thdr->doff` of a TCP header that is not in the buffer.
- `repro-udp6-split`: `utils.c:372` `udp6_payload_split` reads `uhdr->len` of a UDP header that is not in the buffer.
- `repro-tls-analyze`: `tls.c:236` `analyze_tls_data` via `process_tls_packet` (TLS record walk).
- `repro`: `tls.c:133` `analyze_tls_message` (TLS ClientHello, ciphers length read).
- `repro-trie`: `trie.c:168` `trie_process_str` via `bruteforce_analyze_sni_str` (domains brute-force scan).
- `repro-quic-varlength`: `quic.c:37` `quic_parse_varlength` via `quic_parse_initial_header` (QUIC Initial). Not a
  separate missing length check: the QUIC parser trusts the payload length it is handed, which is 40 bytes too long.
- `repro-gcm`: `deps/cyclone/gcm.c:603` `gcmXorBlock` via `quic_parse_initial_message` (QUIC Initial decrypt).

**Reachability.** A real NFQUEUE packet already has a consistent `ip6_plen` (`ipv6_rcv` drops a packet whose
`ip6_plen + 40` exceeds the skb and trims any excess), so none of these frames is reachable from a
kernel-validated packet. They need a malformed packet delivered by another path (a raw-socket injector, or the
kernel-module build); this is a validation bug, not a remotely triggerable one on stock Linux. The one
`fuzz_process_packet` defect that does not depend on it is `../tcp-short-doff-null-iph`.

**Fix.** `if (buflen < pktlen + hdr_len)` in `ip6_payload_split`.

Run: `/mayhem/fuzz_process_packet-standalone repro` (first byte selects the config preset).
