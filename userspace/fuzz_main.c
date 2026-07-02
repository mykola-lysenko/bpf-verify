// SPDX-License-Identifier: GPL-2.0-only
/* Driver for userspace property-fuzzing harnesses; see fuzz.h. */
#include "fuzz.h"
#include <stdlib.h>
#include <string.h>

unsigned long khost_warn_count;

static uint64_t seed_for(uint64_t base, long iter)
{
	uint64_t z = base + 0x9e3779b97f4a7c15ULL * (uint64_t)(iter + 1);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

int main(int argc, char **argv)
{
	long iters = 5000000;
	uint64_t base = 0x1234567;
	int max_report = 5;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--iters") && i + 1 < argc)
			iters = strtol(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--seed") && i + 1 < argc)
			base = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--only") && i + 1 < argc) {
			/* replay a single iteration for debugging */
			long only = strtol(argv[++i], NULL, 0);
			iters = only + 1;
			i = argc; /* stop parsing; run [0..only] but report only 'only' */
		}
	}

	long failures = 0;
	unsigned long warns_before = 0;
	int reported = 0;
	char msg[256];

	for (long it = 0; it < iters; it++) {
		struct fuzz_input in = { .state = seed_for(base, it), .draw = 0, .iter = it };
		warns_before = khost_warn_count;
		msg[0] = 0;
		int rc = fuzz_case(&in, msg, sizeof(msg));
		int warned = (khost_warn_count != warns_before);
		if (rc || warned) {
			failures++;
			if (reported < max_report) {
				printf("FAIL %s iter=%ld seed=0x%llx: %s%s\n",
				       fuzz_name, it, (unsigned long long)base,
				       msg[0] ? msg : "(property violated)",
				       warned ? " [WARN fired]" : "");
				reported++;
			}
		}
	}

	printf("%s: %ld iters, %ld failures\n", fuzz_name, iters, failures);
	return failures ? 1 : 0;
}
