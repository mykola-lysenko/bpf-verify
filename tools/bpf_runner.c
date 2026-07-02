// SPDX-License-Identifier: GPL-2.0-only
/*
 * bpf_runner — execute a verified harness object with fuzzed inputs.
 *
 * Loads a .bpf.o produced by the pipeline, then repeatedly seeds its
 * `input_map` (a 4-entry BPF_MAP_TYPE_ARRAY of u64) with pseudo-random values
 * and runs the "socket" program via BPF_PROG_TEST_RUN. A harness that follows
 * the strict property contract returns 0 on success and non-zero when a
 * BPF_ASSERT fails; this tool reports the seeds that produced a non-zero
 * return so the failure can be reproduced.
 *
 * Intended to run inside the uml-veristat UML guest (hostfs=/), but works on
 * any host with a BPF-capable kernel.
 *
 * Usage: bpf_runner [--iters N] [--seed S] [--max-report M] <obj.bpf.o>...
 * Output: one JSON object per line on stdout, one per object:
 *   {"file":"...","prog":"...","loaded":true,"iters":N,"failures":F,
 *    "cases":[{"seeds":[..],"retval":R}, ...]}
 * Multiple objects run in a single process (one UML boot). Exit: 0 if every
 * object ran with zero failures; 1 if any object had a property failure;
 * 2 if any object could not be loaded/run (infrastructure error).
 */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define INPUT_MAP_ENTRIES 4

static uint64_t rng_state;
static uint64_t next_rand(void)
{
	uint64_t z = (rng_state += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

/* A few structurally interesting fixed vectors run before the random ones:
 * boundary values catch off-by-one / overflow bugs that uniform random misses. */
static const uint64_t corner_values[] = {
	0ULL, 1ULL, 2ULL, ~0ULL, ~0ULL - 1,
	0x8000000000000000ULL, 0x7fffffffffffffffULL,
	0xffffffffULL, 0x100000000ULL, 0x80000000ULL,
};
#define N_CORNERS (sizeof(corner_values) / sizeof(corner_values[0]))

static void seed_case(uint64_t out[INPUT_MAP_ENTRIES], long iter)
{
	/* First N_CORNERS^0.. iterations sweep corner values across key 0 while
	 * holding others at a corner; afterwards go fully random. */
	if (iter < (long)(N_CORNERS * N_CORNERS)) {
		out[0] = corner_values[iter % N_CORNERS];
		out[1] = corner_values[(iter / N_CORNERS) % N_CORNERS];
		out[2] = corner_values[(iter / N_CORNERS) % N_CORNERS];
		out[3] = corner_values[iter % N_CORNERS];
		return;
	}
	for (int k = 0; k < INPUT_MAP_ENTRIES; k++)
		out[k] = next_rand();
}

/* Run one object. Returns 0 (zero failures), 1 (property failures),
 * 2 (infrastructure error). Emits exactly one JSON line. */
static int run_object(const char *path, long iters, uint64_t seed, int max_report)
{
	const char *base = strrchr(path, '/');
	base = base ? base + 1 : path;
	rng_state = seed;

	struct bpf_object *obj = bpf_object__open(path);
	if (!obj) {
		printf("{\"file\":\"%s\",\"loaded\":false,\"error\":\"open failed: %d\"}\n",
		       base, errno);
		return 2;
	}
	if (bpf_object__load(obj)) {
		printf("{\"file\":\"%s\",\"loaded\":false,\"error\":\"load failed: %d\"}\n",
		       base, errno);
		bpf_object__close(obj);
		return 2;
	}

	struct bpf_program *prog = NULL, *p;
	bpf_object__for_each_program(p, obj) {
		prog = p; /* the harness has exactly one "socket" program */
		break;
	}
	struct bpf_map *map = bpf_object__find_map_by_name(obj, "input_map");
	if (!prog || !map) {
		printf("{\"file\":\"%s\",\"loaded\":false,\"error\":\"missing prog or input_map\"}\n",
		       base);
		bpf_object__close(obj);
		return 2;
	}
	int prog_fd = bpf_program__fd(prog);
	int map_fd = bpf_map__fd(map);
	const char *prog_name = bpf_program__name(prog);

	/* socket-filter test run needs a packet >= ETH_HLEN; contents are unused
	 * by our harnesses (they read only from input_map). */
	unsigned char pkt_in[64] = {0};
	unsigned char pkt_out[64];

	long failures = 0;
	int reported = 0;
	printf("{\"file\":\"%s\",\"prog\":\"%s\",\"loaded\":true,\"iters\":%ld,\"cases\":[",
	       base, prog_name, iters);

	for (long iter = 0; iter < iters; iter++) {
		uint64_t seeds[INPUT_MAP_ENTRIES];
		seed_case(seeds, iter);
		for (uint32_t k = 0; k < INPUT_MAP_ENTRIES; k++) {
			if (bpf_map_update_elem(map_fd, &k, &seeds[k], BPF_ANY)) {
				printf("],\"loaded\":true,\"error\":\"map update failed: %d\"}\n", errno);
				bpf_object__close(obj);
				return 2;
			}
		}
		struct bpf_test_run_opts opts = {
			.sz = sizeof(opts),
			.data_in = pkt_in,
			.data_size_in = sizeof(pkt_in),
			.data_out = pkt_out,
			.data_size_out = sizeof(pkt_out),
			.repeat = 1,
		};
		int err = bpf_prog_test_run_opts(prog_fd, &opts);
		if (err) {
			printf("],\"loaded\":true,\"error\":\"test_run failed: %d\"}\n", errno);
			bpf_object__close(obj);
			return 2;
		}
		if (opts.retval != 0) {
			failures++;
			if (reported < max_report) {
				printf("%s{\"seeds\":[%llu,%llu,%llu,%llu],\"retval\":%d}",
				       reported ? "," : "",
				       (unsigned long long)seeds[0], (unsigned long long)seeds[1],
				       (unsigned long long)seeds[2], (unsigned long long)seeds[3],
				       (int)opts.retval);
				reported++;
			}
		}
	}
	printf("],\"failures\":%ld}\n", failures);
	bpf_object__close(obj);
	return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
	long iters = 10000;
	uint64_t seed = 0x123456789abcdefULL;
	int max_report = 8;
	const char *paths[4096];
	int npaths = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--iters") && i + 1 < argc)
			iters = strtol(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--seed") && i + 1 < argc)
			seed = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--max-report") && i + 1 < argc)
			max_report = atoi(argv[++i]);
		else if (argv[i][0] != '-' && npaths < (int)(sizeof(paths) / sizeof(paths[0])))
			paths[npaths++] = argv[i];
	}
	if (!npaths) {
		fprintf(stderr, "usage: bpf_runner [--iters N] [--seed S] [--max-report M] <obj.bpf.o>...\n");
		return 2;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Silence libbpf's own logging; we report structured results ourselves. */
	libbpf_set_print(NULL);

	int worst = 0; /* 0 ok < 1 failure < 2 infra error, but report failures over infra */
	int any_infra = 0, any_fail = 0;
	for (int i = 0; i < npaths; i++) {
		int rc = run_object(paths[i], iters, seed, max_report);
		if (rc == 1)
			any_fail = 1;
		else if (rc == 2)
			any_infra = 1;
		fflush(stdout);
	}
	worst = any_fail ? 1 : (any_infra ? 2 : 0);
	return worst;
}
