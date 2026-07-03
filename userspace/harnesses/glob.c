// SPDX-License-Identifier: GPL-2.0-only
/*
 * ASAN/UBSan fuzzer for glob_match() (lib/glob.c) on adversarial patterns.
 *
 * glob_match(pat, str) is a hand-written shell-style matcher with '*', '?',
 * and '[...]' character classes plus backtracking. Character-class parsing and
 * backtracking over NUL-terminated buffers are exactly where an out-of-bounds
 * read would hide, and glob is far less fuzzed than the compression codecs.
 *
 * Pattern and string are heap-allocated with exact length + NUL so ASan has a
 * redzone immediately after the terminator: any read past the end traps. The
 * alphabet is biased toward glob metacharacters so the class/backtrack paths
 * are exercised, not just literal comparisons.
 */
#include "fuzz.h"
#include <stdlib.h>

#include KGLOB_SRC

/* Small alphabet heavy in metacharacters maximizes class/backtrack coverage. */
static const char glob_alpha[] = { '*', '?', '[', ']', '-', '\\', '^', '!',
				   'a', 'b', 'c', '0' };
#define GLOB_ALPHA_N (sizeof(glob_alpha) / sizeof(glob_alpha[0]))

static char *gen_str(struct fuzz_input *in, size_t len)
{
	char *s = malloc(len + 1);
	if (!s)
		return NULL;
	for (size_t i = 0; i < len; i++)
		s[i] = glob_alpha[fuzz_u64(in) % GLOB_ALPHA_N];
	s[len] = '\0';
	return s;
}

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen)
{
	(void)msg; (void)msglen;
	size_t plen = (size_t)fuzz_range(in, 0, 24);
	size_t slen = (size_t)fuzz_range(in, 0, 24);
	char *pat = gen_str(in, plen);
	char *str = gen_str(in, slen);
	if (pat && str) {
		/* Return value is irrelevant; ASan enforces the safety contract
		 * (no read past either NUL terminator). */
		volatile bool r = glob_match(pat, str);
		(void)r;
	}
	free(pat);
	free(str);
	return 0;
}

const char *fuzz_name = "glob";
