/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BITMAP_H
#define _LINUX_BITMAP_H

#include <linux/types.h>

#define BITS_PER_LONG		64
#define BITS_TO_LONGS(nr)	(((nr) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#define DECLARE_BITMAP(name, bits) unsigned long name[BITS_TO_LONGS(bits)]

static inline void bitmap_from_u64(unsigned long *dst, u64 mask)
{
	dst[0] = mask;
}

static inline int __bpf_backtrack_next_set_bit(unsigned long *addr, int size,
					       int start)
{
	int i;

	for (i = start; i < size; i++) {
		if (addr[i / BITS_PER_LONG] & (1UL << (i % BITS_PER_LONG)))
			return i;
	}
	return size;
}

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = __bpf_backtrack_next_set_bit((addr), (size), 0); \
	     (bit) < (size); \
	     (bit) = __bpf_backtrack_next_set_bit((addr), (size), (bit) + 1))

#endif /* _LINUX_BITMAP_H */
