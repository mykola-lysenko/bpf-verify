// SPDX-License-Identifier: GPL-2.0-only
/*
 * Native reference driver for native-vs-BPF differential testing.
 *
 * Compiles a kernel source (DIFF_KSRC) as ordinary host code via the userspace
 * shim (khost.h), includes the shared computation (DIFF_COMPUTE), and writes
 * one u64 output per iteration to a file, seeding inputs with the SAME
 * generator (diff_seed.h) the in-UML bpf_runner uses. The two output files are
 * then diffed by tools/diff_compare.py.
 *
 * Built by tools/diff.sh with -DDIFF_KSRC / -DDIFF_COMPUTE and the target's
 * diff/<name>/native.flags.
 */
#include "khost.h"
#include "diff_seed.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long khost_warn_count; /* referenced by khost.h WARN macros */

#include DIFF_KSRC
#include DIFF_COMPUTE

int main(int argc, char **argv)
{
	long iters = 100000;
	uint64_t base = 0x1234567;
	const char *out_path = NULL;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--iters") && i + 1 < argc)
			iters = strtol(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--base") && i + 1 < argc)
			base = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--out") && i + 1 < argc)
			out_path = argv[++i];
	}
	if (!out_path) {
		fprintf(stderr, "usage: diff_native --out FILE [--iters N] [--base S]\n");
		return 2;
	}
	FILE *out = fopen(out_path, "wb");
	if (!out) {
		fprintf(stderr, "diff_native: cannot open %s\n", out_path);
		return 2;
	}
	for (long it = 0; it < iters; it++) {
		uint64_t in[DIFF_NINPUTS];
		diff_gen_inputs(base, it, in);
		uint64_t r = diff_compute(in);
		/* Same 32-bit fold as the BPF harness (result observed via the
		 * program's 32-bit return value); zero-extended for the file. */
		uint64_t folded = (uint32_t)(r ^ (r >> 32));
		fwrite(&folded, sizeof(folded), 1, out);
	}
	fclose(out);
	return 0;
}
