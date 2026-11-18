/* TLS over TCP: the input is the TCP payload (a ClientHello), wrapped in valid IP/TCP headers. */
#include "common.h"

static const int tcp_presets[] = {
	P_DEFAULT, P_TLS_FRAG_TCP, P_TLS_FRAG_IP, P_DOMAINS_BRUTE, P_SECTIONS, P_TCP_ALL_IPV4, P_DOMAINS_PARSE,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	static uint8_t pkt[MAX_WRAPPED_PAYLOAD + 80];
	harness_init();
	if (size < 1)
		return -1;

	const struct config_t *cfg = &configs[tcp_presets[(data[0] & 0x7f) % (sizeof(tcp_presets) / sizeof(*tcp_presets))]];
	size_t plen = wrap_packet(data[0] >> 7, IPPROTO_TCP, data + 1, size - 1, pkt);
	uint8_t *copy = dup_input(pkt, plen);
	run_packet(cfg, copy, plen, 1);
	free(copy);
	return 0;
}
