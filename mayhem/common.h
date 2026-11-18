#ifndef MAYHEM_COMMON_H
#define MAYHEM_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "args.h"
#include "config.h"
#include "dpi.h"
#include "types.h"

static int stub_send_raw(const unsigned char *data, size_t len) {
	if (len)
		(void)*(volatile const unsigned char *)(data + len - 1);
	return (int)len;
}

static int stub_send_delayed(const unsigned char *data, size_t len, unsigned int delay_ms) {
	(void)delay_ms;
	return stub_send_raw(data, len);
}

struct instance_config_t instance_config = {
	.send_raw_packet = stub_send_raw,
	.send_delayed_packet = stub_send_delayed,
};

#define MAX_PRESET_ARGS 16

/* Option sets covering the program's attack modes; indexes are used by the harnesses. */
enum {
	P_DEFAULT, P_TLS_FRAG_TCP, P_TLS_FRAG_IP, P_DOMAINS_BRUTE, P_UDP_FAKE_PARSE, P_UDP_DROP_ALL,
	P_SECTIONS, P_TCP_ALL_IPV4, P_UDP_BRUTE, P_DOMAINS_PARSE, N_PRESETS
};

static const char *const presets[N_PRESETS][MAX_PRESET_ARGS] = {
	[P_DEFAULT] = {0},
	[P_TLS_FRAG_TCP] = {"--trace", "--sni-domains=all", "--frag=tcp", "--frag-sni-reverse=1",
		"--frag-middle-sni=1", "--seg2delay=5"},
	[P_TLS_FRAG_IP] = {"--trace", "--instaflush", "--sni-domains=all", "--frag=ip", "--fake-sni=1",
		"--faking-strategy=ttl,tcp_check,md5sum,timestamp", "--synfake=1", "--frag-sni-faked=1"},
	[P_DOMAINS_BRUTE] = {"--sni-domains=youtube.com,googlevideo.com", "--exclude-domains=music.youtube.com",
		"--sni-detection=brute", "--fake-sni=1", "--fake-sni-type=custom",
		"--fake-custom-payload=16030100040100000a", "--frag=none"},
	[P_UDP_FAKE_PARSE] = {"--trace", "--sni-domains=all", "--udp-mode=fake", "--udp-fake-seq-len=2",
		"--udp-fake-len=64", "--udp-faking-strategy=checksum", "--udp-filter-quic=parse"},
	[P_UDP_DROP_ALL] = {"--trace", "--udp-mode=drop", "--udp-filter-quic=all", "--udp-stun-filter",
		"--udp-dport-filter=443,3478-3480", "--no-dport-filter"},
	[P_SECTIONS] = {"--sni-domains=all", "--fbegin", "--tcp-dport-filter=80,8000-8100", "--frag=ip",
		"--fend", "--fbegin", "--udp-filter-quic=parse", "--udp-mode=fake", "--udp-faking-strategy=ttl",
		"--fend"},
	[P_TCP_ALL_IPV4] = {"--no-ipv6", "--tcp-match-all", "--sni-domains=all", "--frag=tcp",
		"--frag-sni-faked=1", "--fake-sni=1", "--fake-sni-type=default", "--faking-strategy=pastseq,timestamp",
		"--faking-timestamp-decrease=1000", "--fk-winsize=4", "--frag-sni-pos=3"},
	[P_UDP_BRUTE] = {"--sni-domains=youtube.com,googlevideo.com", "--sni-detection=brute",
		"--udp-filter-quic=parse", "--udp-mode=drop"},
	[P_DOMAINS_PARSE] = {"--trace", "--sni-domains=youtube.com,googlevideo.com",
		"--exclude-domains=music.youtube.com", "--frag=tcp"},
};

static struct config_t configs[N_PRESETS];
static int harness_ready;

/* Logging goes to stdout; the harnesses neither need nor want it. */
static void harness_init(void) {
	if (harness_ready)
		return;
	harness_ready = 1;

	if (!freopen("/dev/null", "w", stdout))
		abort();

	for (int i = 0; i < N_PRESETS; i++) {
		char *argv[MAX_PRESET_ARGS + 2];
		int argc = 0;
		argv[argc++] = strdup("youtubeUnblock");
		for (int j = 0; j < MAX_PRESET_ARGS && presets[i][j]; j++)
			argv[argc++] = strdup(presets[i][j]);
		argv[argc] = NULL;
		if (yparse_args(&configs[i], argc, argv) != 0) {
			fprintf(stderr, "harness: preset %d failed to parse\n", i);
			abort();
		}
	}
}

static const struct section_config_t *preset_section(int i) {
	return configs[i].last_section;
}

static void *dup_input(const uint8_t *data, size_t size) {
	void *p = malloc(size ? size : 1);
	if (!p)
		abort();
	if (size)
		memcpy(p, data, size);
	return p;
}

/* A NUL-terminated copy for string-oriented targets. */
static char *dup_input_str(const uint8_t *data, size_t size) {
	char *p = malloc(size + 1);
	if (!p)
		abort();
	if (size)
		memcpy(p, data, size);
	p[size] = '\0';
	return p;
}

#define MAX_WRAPPED_PAYLOAD 60000

/*
 * Wraps a transport payload into an IPv4/IPv6 packet carrying a TCP or UDP header to port 443,
 * so the fuzzer controls the payload bytes without having to keep the length fields consistent.
 * Returns the packet length; out must hold MAX_WRAPPED_PAYLOAD + 80 bytes.
 */
static size_t wrap_packet(int v6, int proto, const uint8_t *payload, size_t len, uint8_t *out) {
	uint8_t trans[20];
	size_t thl;
	if (len > MAX_WRAPPED_PAYLOAD)
		len = MAX_WRAPPED_PAYLOAD;

	memset(trans, 0, sizeof(trans));
	trans[0] = 0xc3; trans[1] = 0x50;			/* sport 50000 */
	trans[2] = 0x01; trans[3] = 0xbb;			/* dport 443 */
	if (proto == IPPROTO_TCP) {
		trans[4] = 0x12; trans[5] = 0x34; trans[6] = 0x56; trans[7] = 0x78;	/* seq */
		trans[8] = 0x9a; trans[9] = 0xbc; trans[10] = 0xde; trans[11] = 0xf0;	/* ack */
		trans[12] = 5 << 4;
		trans[13] = 0x18;				/* PSH|ACK */
		trans[14] = 0xff; trans[15] = 0xff;		/* window */
		thl = 20;
	} else {
		uint16_t ul = htons((uint16_t)(8 + len));
		memcpy(trans + 4, &ul, 2);
		thl = 8;
	}

	size_t ipl, total;
	if (v6) {
		ipl = 40;
		total = ipl + thl + len;
		memset(out, 0, ipl);
		out[0] = 0x60;
		uint16_t pl = htons((uint16_t)(thl + len));
		memcpy(out + 4, &pl, 2);
		out[6] = (uint8_t)proto;
		out[7] = 64;
		out[8] = 0x20; out[23] = 1;
		out[24] = 0x20; out[39] = 2;
	} else {
		ipl = 20;
		total = ipl + thl + len;
		memset(out, 0, ipl);
		out[0] = 0x45;
		uint16_t tl = htons((uint16_t)total);
		memcpy(out + 2, &tl, 2);
		out[8] = 64;
		out[9] = (uint8_t)proto;
		out[12] = 10; out[15] = 1;
		out[16] = 10; out[19] = 2;
	}
	memcpy(out + ipl, trans, thl);
	if (len)
		memcpy(out + ipl + thl, payload, len);
	return total;
}

/*
 * trace_ok = 0 caps the log level at debug. With --trace, log_packet() dereferences a NULL ip6h for
 * any packet whose version nibble is neither 4 nor 6 (mayhem/fuzz_process_packet/known-findings), so
 * the raw-packet target runs without trace and leaves the trace logger to the wrapped targets, whose
 * packets are always well-formed IP.
 */
static int run_packet(const struct config_t *cfg, const uint8_t *pkt, size_t len, int trace_ok) {
	struct packet_data pd;
	memset(&pd, 0, sizeof(pd));
	pd.payload = pkt;
	pd.payload_len = len;
	parse_global_lgconf(cfg);
	if (!trace_ok && logging_conf.verbose > VERBOSE_DEBUG)
		logging_conf.verbose = VERBOSE_DEBUG;
	return process_packet(cfg, &pd);
}

#endif
