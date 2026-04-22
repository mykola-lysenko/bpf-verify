// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: lib/ratelimit.c
 * Replaces spinlocks with no-ops, atomics with plain reads/writes,
 * and jiffies with a static variable (provided by EXTRA_PRE_INCLUDE). */

#include <linux/ratelimit.h>

int ___ratelimit(struct ratelimit_state *rs, const char *func)
{
	int interval = rs->interval;
	int burst = rs->burst;
	int ret = 0;

	if (interval <= 0 || burst <= 0) {
		ret = interval == 0 || burst > 0;
		if (!(rs->flags & RATELIMIT_INITIALIZED) || (!interval && !burst))
			return ret;
		rs->flags &= ~RATELIMIT_INITIALIZED;
		return ret;
	}

	if (!(rs->flags & RATELIMIT_INITIALIZED)) {
		rs->begin = jiffies;
		rs->flags |= RATELIMIT_INITIALIZED;
		atomic_set(&rs->rs_n_left, rs->burst);
	}

	if (time_is_before_jiffies(rs->begin + interval)) {
		atomic_set(&rs->rs_n_left, rs->burst);
		rs->begin = jiffies;
	}

	if (atomic_read(&rs->rs_n_left) > 0) {
		atomic_set(&rs->rs_n_left, atomic_read(&rs->rs_n_left) - 1);
		ret = 1;
	}

	return ret;
}
