# send_tcp_frags ignores a failed tcp_payload_split and passes an unset iph to post_fake_sni

**Cause.** `src/mangle.c` `send_tcp_frags()` (the `frag_sni_faked` branch, ~line 239) calls
`tcp_payload_split(frag2, f2len, &iph, ...)` and ignores the return value. `iph` is an uninitialised local, so
when the split fails it is passed as-is to `post_fake_sni()`, whose `memcpy(rfsiph, iph, iph_len)` (`mangle.c:276`)
then reads through it (NULL in the sanitized build, stack garbage otherwise).

**How the split can fail on a packet the first split accepted.** `tcp4_payload_split`/`tcp6_payload_split` accept a
TCP data offset below 5 (`thdr_len = doff * 4` is only compared with the payload length, never with
`sizeof(struct tcphdr)`). `tcp_frag` copies `tcph_len` (< 20) bytes of TCP header into `frag2`, so
`frag2`'s TCP part is `tcph_len + s2_plen` bytes and is rejected by the `tcph_plen < sizeof(struct tcphdr)` test
whenever the second fragment's payload is short.

`repro` is a 43-byte IPv4 packet (`tot_len` consistent with the buffer) with TCP `doff = 1` and a 17-byte payload,
run under the `--tcp-match-all --frag=tcp --frag-sni-faked=1 --fake-sni=1` preset (first byte `0x43` selects it).

**Impact.** NULL dereference (crash of the daemon) on one crafted TCP segment. Unlike the IPv6 length finding
this does not rely on an inconsistent IP length: the IPv4 header is valid and netfilter does not check the TCP
data offset, so the packet reaches NFQUEUE; the default (non-`--tcp-match-all`) configuration additionally needs
the segment to carry a TLS ClientHello to port 443.

**Fix.** Check the result in `send_tcp_frags`: `if (ret < 0) goto erret_lc;` after the `tcp_payload_split(frag2, ...)`
call, and reject `thdr_len < sizeof(struct tcphdr)` in `tcp4_payload_split`/`tcp6_payload_split`.

Run: `/mayhem/fuzz_process_packet-standalone repro`.
