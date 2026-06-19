/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local kernel helpers for kernel/bpf/log.c. */
#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

#include <linux/types.h>
#include <linux/errno.h>

typedef __builtin_va_list va_list;
#define va_start(ap, last)	__builtin_va_start(ap, last)
#define va_end(ap)		__builtin_va_end(ap)

#ifndef UINT_MAX
#define UINT_MAX		((unsigned int)~0U)
#endif
#ifndef U32_MAX
#define U32_MAX			((u32)~0U)
#endif
#ifndef U16_MAX
#define U16_MAX			((u16)~0U)
#endif
#ifndef S16_MAX
#define S16_MAX			((s16)(U16_MAX >> 1))
#endif
#ifndef S16_MIN
#define S16_MIN			((s16)(-S16_MAX - 1))
#endif
#ifndef S32_MIN
#define S32_MIN			((s32)(1U << 31))
#endif
#ifndef S32_MAX
#define S32_MAX			((s32)(U32_MAX >> 1))
#endif
#ifndef S64_MIN
#define S64_MIN			((s64)(1ULL << 63))
#endif
#ifndef S64_MAX
#define S64_MAX			((s64)(~0ULL >> 1))
#endif
#ifndef U64_MAX
#define U64_MAX			((u64)~0ULL)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)		(sizeof(arr) / sizeof((arr)[0]))
#endif
#ifndef max
#define max(x, y)		((x) > (y) ? (x) : (y))
#endif
#ifndef min
#define min(x, y)		((x) < (y) ? (x) : (y))
#endif
#ifndef min_t
#define min_t(type, x, y)	((type)(x) < (type)(y) ? (type)(x) : (type)(y))
#endif
#ifndef round_up
#define round_up(x, y)		((((x) + (y) - 1) / (y)) * (y))
#endif
#ifndef offsetof
#define offsetof(type, member)	__builtin_offsetof(type, member)
#endif
#ifndef offsetofend
#define offsetofend(type, member) \
	(offsetof(type, member) + sizeof(((type *)0)->member))
#endif
#ifndef swap
#define swap(a, b) do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
#endif

#define __user
#define __printf(a, b)
#define EXPORT_SYMBOL_GPL(sym)

#define WARN_ON_ONCE(cond)	(0)
#define WARN_ONCE(cond, fmt, ...)	(0)
#define pr_err(fmt, ...)	do { } while (0)

static inline u32 __bpf_log_vscnprintf(char *buf, size_t size,
				       const char *fmt, va_list args)
{
	(void)args;
	if (!size)
		return 0;
	if (fmt && fmt[0])
		buf[0] = fmt[0];
	buf[size > 1 ? 1 : 0] = '\0';
	return fmt && fmt[0] ? 1 : 0;
}

#define vscnprintf(buf, size, fmt, args) \
	__bpf_log_vscnprintf((buf), (size), (fmt), (args))

static inline u32 __bpf_log_snprintf(char *buf, size_t size,
				     const char *fmt, ...)
{
	(void)fmt;
	if (size)
		buf[0] = '\0';
	return 0;
}

#define snprintf(buf, size, fmt, ...) \
	__bpf_log_snprintf((buf), (size), (fmt), ##__VA_ARGS__)

#endif /* _LINUX_KERNEL_H */
