/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MATH64_H
#define _LINUX_MATH64_H

#include <linux/types.h>

static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = divisor ? dividend % divisor : 0;
	return divisor ? dividend / divisor : 0;
}

#endif /* _LINUX_MATH64_H */
