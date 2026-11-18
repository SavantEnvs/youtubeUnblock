/* QUIC over UDP/443: the input is the UDP payload, wrapped in valid IP/UDP headers. */
#include "common.h"

static const int udp_presets[] = {
	P_UDP_FAKE_PARSE, P_UDP_DROP_ALL, P_SECTIONS, P_UDP_BRUTE,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	static uint8_t pkt[MAX_WRAPPED_PAYLOAD + 80];
	harness_init();
	if (size < 1)
		return -1;

	const struct config_t *cfg = &configs[udp_presets[(data[0] & 0x7f) % (sizeof(udp_presets) / sizeof(*udp_presets))]];
	size_t plen = wrap_packet(data[0] >> 7, IPPROTO_UDP, data + 1, size - 1, pkt);
	uint8_t *copy = dup_input(pkt, plen);
	run_packet(cfg, copy, plen, 1);
	free(copy);
	return 0;
}
