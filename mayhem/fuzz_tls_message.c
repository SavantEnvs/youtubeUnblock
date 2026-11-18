/* TLS ClientHello parsing: record-wrapped (analyze_tls_data) and bare handshake (analyze_tls_message). */
#include "common.h"
#include "tls.h"

static const int sections[] = {P_TLS_FRAG_TCP, P_DOMAINS_PARSE, P_DOMAINS_BRUTE};

static void touch(const uint8_t *p, int len) {
	volatile uint8_t sink = 0;
	for (int i = 0; i < len; i++)
		sink ^= p[i];
	(void)sink;
}

static void check(const struct tls_verdict *v) {
	if (v->sni_len > 0)
		touch(v->sni_ptr, v->sni_len);
	if (v->target_sni && v->target_sni_len > 0)
		touch(v->target_sni_ptr, v->target_sni_len);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	harness_init();
	if (size < 1)
		return -1;

	const struct section_config_t *section = preset_section(sections[data[0] % 3]);
	parse_global_lgconf(&configs[P_TLS_FRAG_TCP]);
	uint8_t *buf = dup_input(data + 1, size - 1);
	size_t len = size - 1;

	struct tls_verdict v = analyze_tls_data(section, buf, len);
	check(&v);

	struct tls_verdict m;
	memset(&m, 0, sizeof(m));
	if (analyze_tls_message(section, buf, len, &m) == TLS_MESSAGE_ANALYZE_FOUND)
		check(&m);

	memset(&m, 0, sizeof(m));
	if (bruteforce_analyze_sni_str(section, buf, len, &m) == 0)
		check(&m);

	free(buf);
	return 0;
}
