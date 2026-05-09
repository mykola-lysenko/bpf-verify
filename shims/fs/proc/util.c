/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF-compatible shim for fs/proc/util.c.
 *
 * The real file includes fs/proc/internal.h, which intentionally has no include
 * guard and pulls in broad procfs, scheduler, and MM state.  The target logic
 * here is the real name_to_int() body with only the minimal qstr type needed by
 * that function.
 */
#include <linux/types.h>

struct qstr {
	const unsigned char *name;
	u32 len;
};

unsigned name_to_int(const struct qstr *qstr)
{
	const char *name = (const char *)qstr->name;
	int len = qstr->len;
	unsigned n = 0;

	if (len > 1 && *name == '0')
		goto out;
	do {
		unsigned c = *name++ - '0';
		if (c > 9)
			goto out;
		if (n >= (~0U - 9) / 10)
			goto out;
		n *= 10;
		n += c;
	} while (--len > 0);
	return n;
out:
	return ~0U;
}
