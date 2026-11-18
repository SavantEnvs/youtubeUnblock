/* Command-line parsing: the input is split on NUL/newline into argv, then the config is printed. */
#include "common.h"

#define MAX_ARGC 48

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	harness_init();

	char *copy = dup_input_str(data, size);

	char *argv[MAX_ARGC + 2];
	int argc = 0;
	static char argv0[] = "youtubeUnblock";
	argv[argc++] = argv0;

	size_t i = 0;
	while (i <= size && argc <= MAX_ARGC) {
		size_t j = i;
		while (j < size && copy[j] != '\0' && copy[j] != '\n')
			j++;
		copy[j] = '\0';
		if (j > i)
			argv[argc++] = copy + i;
		i = j + 1;
	}
	argv[argc] = NULL;

	/* The *-file options read arbitrary paths; keep the target hermetic. */
	for (int k = 1; k < argc; k++) {
		if (strstr(argv[k], "-file")) {
			free(copy);
			return -1;
		}
	}

	struct config_t cfg;
	memset(&cfg, 0, sizeof(cfg));
	if (yparse_args(&cfg, argc, argv) == 0) {
		char out[8192];
		print_config(&cfg, out, sizeof(out));
		free_config(&cfg);
	}
	free(copy);
	return 0;
}
