# Infinite loop in fail_packet's TCP option walk on a zero-length option

**Cause.** `src/utils.c` `fail_packet()` (`FAKE_STRAT_TCP_TS` branch) walks the TCP options of the packet
being faked. For an option whose length byte is `0`, `optp_len -= len; optp += len;` makes no
progress, so the `while (optp_len && *optp != 0x00)` loop never ends. The
packet is the client's own, so the option bytes are attacker-controlled. Reached through `gen_fake_sni`
-> `post_fake_sni` -> `perform_attack` on a TLS ClientHello with a TCP option whose kind is not 0/1/8 and whose length byte is 0.

**Impact.** The NFQUEUE worker spins at 100% CPU forever on one crafted packet: remote denial of service
of the filter (and, since packets are processed in line, of the traffic it handles).

**Fix.** In the option loop: `if (len < 2 || len > optp_len) { lgerr("Tcp option parsing failed"); break; }`.

Run: `timeout 5 /mayhem/fuzz_process_packet-standalone repro` (it does not return; libFuzzer reports a
`timeout`).
