/* Whole-pipeline fuzzer: byte 0 picks an option set, the rest is a raw IP packet. */
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	harness_init();
	if (size < 1)
		return -1;

	uint8_t *pkt = dup_input(data + 1, size - 1);
	run_packet(&configs[data[0] % N_PRESETS], pkt, size - 1, 0);
	free(pkt);
	return 0;
}
