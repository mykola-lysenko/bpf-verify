/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local circular-number surface for kernel/bpf/states.c. */
#ifndef _LINUX_CNUM_H
#define _LINUX_CNUM_H

#include <linux/types.h>

#ifndef U32_MAX
#define U32_MAX			((u32)~0U)
#endif
#ifndef U64_MAX
#define U64_MAX			((u64)~0ULL)
#endif

struct cnum32 {
	u32 base;
	u32 size;
};

struct cnum64 {
	u64 base;
	u64 size;
};

#define CNUM32_UNBOUNDED	((struct cnum32){ .base = 0, .size = U32_MAX })
#define CNUM64_UNBOUNDED	((struct cnum64){ .base = 0, .size = U64_MAX })

static inline bool cnum32_is_subset(struct cnum32 old, struct cnum32 cur)
{
	if (old.size == U32_MAX)
		return true;
	if (cur.base < old.base)
		return false;
	return cur.size <= old.size - (cur.base - old.base);
}

static inline bool cnum64_is_subset(struct cnum64 old, struct cnum64 cur)
{
	if (old.size == U64_MAX)
		return true;
	if (cur.base < old.base)
		return false;
	return cur.size <= old.size - (cur.base - old.base);
}

#endif /* _LINUX_CNUM_H */
