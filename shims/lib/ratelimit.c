// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: lib/ratelimit.c
 * Replaces spinlocks with no-ops, atomics with plain reads/writes,
 * and jiffies with a static variable (provided by EXTRA_PRE_INCLUDE). */

#include <linux/ratelimit.h>

#ifndef READ_ONCE
#define READ_ONCE(x) (x)
#endif
#ifndef WARN_ONCE
#define WARN_ONCE(cond, fmt, ...) ((void)(cond))
#endif
#ifndef KERN_WARNING
#define KERN_WARNING ""
#endif
#ifndef printk_deferred
#define printk_deferred(fmt, ...) do { } while (0)
#endif
#ifndef atomic_dec_return
#define atomic_dec_return(v) (--((v)->counter))
#endif

int ___ratelimit(struct ratelimit_state *rs, const char *func)
{
	int interval = READ_ONCE(rs->interval);
	int burst = READ_ONCE(rs->burst);
	unsigned long flags;
	int ret = 0;

	if (interval <= 0 || burst <= 0) {
		WARN_ONCE(interval < 0 || burst < 0,
			  "Negative interval (%d) or burst (%d): Uninitialized ratelimit_state structure?\n",
			  interval, burst);
		ret = interval == 0 || burst > 0;
		if (!(READ_ONCE(rs->flags) & RATELIMIT_INITIALIZED) ||
		    (!interval && !burst) ||
		    !raw_spin_trylock_irqsave(&rs->lock, flags))
			goto nolock_ret;

		rs->flags &= ~RATELIMIT_INITIALIZED;
		goto unlock_ret;
	}

	if (!raw_spin_trylock_irqsave(&rs->lock, flags)) {
		if (READ_ONCE(rs->flags) & RATELIMIT_INITIALIZED &&
		    atomic_read(&rs->rs_n_left) > 0 &&
		    atomic_dec_return(&rs->rs_n_left) >= 0)
			ret = 1;
		goto nolock_ret;
	}

	if (!(rs->flags & RATELIMIT_INITIALIZED)) {
		rs->begin = jiffies;
		rs->flags |= RATELIMIT_INITIALIZED;
		atomic_set(&rs->rs_n_left, rs->burst);
	}

	if (time_is_before_jiffies(rs->begin + interval)) {
		int m;

		atomic_set(&rs->rs_n_left, rs->burst);
		rs->begin = jiffies;

		if (!(rs->flags & RATELIMIT_MSG_ON_RELEASE)) {
			m = ratelimit_state_reset_miss(rs);
			if (m)
				printk_deferred(KERN_WARNING
						"%s: %d callbacks suppressed\n",
						func, m);
		}
	}

	if (atomic_read(&rs->rs_n_left) > 0 &&
	    atomic_dec_return(&rs->rs_n_left) >= 0)
		ret = 1;

unlock_ret:
	raw_spin_unlock_irqrestore(&rs->lock, flags);

nolock_ret:
	if (!ret)
		ratelimit_state_inc_miss(rs);

	return ret;
}
