/*
 * Decrypted QUIC Initial payload (frame sequence). Initial packets are AES-GCM protected, but the
 * tag is not verified, so garbage plaintext reaches this parser in the real pipeline; calling it
 * directly lets the fuzzer control the frames. Mirrors detect_udp_filtered() after decryption.
 */
#include "common.h"
#include "quic.h"
#include "tls.h"

static const int sections[] = {P_TLS_FRAG_TCP, P_DOMAINS_PARSE, P_DOMAINS_BRUTE};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	harness_init();
	if (size < 1)
		return -1;

	const struct section_config_t *section = preset_section(sections[data[0] % 3]);
	parse_global_lgconf(&configs[P_TLS_FRAG_TCP]);

	uint8_t *msg = dup_input(data + 1, size - 1);
	uint8_t *crypto = NULL;
	size_t crypto_len = 0;
	if (parse_quic_decrypted(section, msg, size - 1, &crypto, &crypto_len) == 0) {
		struct tls_verdict tlsv;
		memset(&tlsv, 0, sizeof(tlsv));
		if (section->sni_detection == SNI_DETECTION_BRUTE)
			bruteforce_analyze_sni_str(section, crypto, crypto_len, &tlsv);
		else
			analyze_tls_message(section, crypto, crypto_len, &tlsv);
		free(crypto);
	}
	free(msg);
	return 0;
}
