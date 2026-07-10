/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SORT_H
#define _LINUX_SORT_H

#include <linux/types.h>

static inline void sort(void *base, size_t num, size_t size,
			int (*cmp)(const void *, const void *),
			void (*swap_func)(void *, void *, int))
{
	(void)base;
	(void)num;
	(void)size;
	(void)cmp;
	(void)swap_func;
}

#endif /* _LINUX_SORT_H */
