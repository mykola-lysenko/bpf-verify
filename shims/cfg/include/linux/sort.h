/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SORT_H
#define _LINUX_SORT_H

#include <linux/types.h>

static inline void sort(void *base, size_t num, size_t size,
			int (*cmp)(const void *, const void *),
			void (*swap_func)(void *, void *, int))
{
	u32 *items = base;
	u32 i, j;

	(void)size;
	(void)swap_func;
	for (i = 0; i < num; i++) {
		for (j = i + 1; j < num; j++) {
			if (cmp(&items[i], &items[j]) > 0) {
				u32 tmp = items[i];

				items[i] = items[j];
				items[j] = tmp;
			}
		}
	}
}

#endif /* _LINUX_SORT_H */
