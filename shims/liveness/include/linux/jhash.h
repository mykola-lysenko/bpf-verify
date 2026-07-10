/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_JHASH_H
#define _LINUX_JHASH_H

#include <linux/types.h>

static inline u32 jhash2(const u32 *k, u32 length, u32 initval)
{
	u32 hash = initval ^ (length * 0x9e3779b9U);
	u32 i;

	for (i = 0; i < length; i++)
		hash = (hash << 5) - hash + k[i];
	return hash;
}

#endif /* _LINUX_JHASH_H */
