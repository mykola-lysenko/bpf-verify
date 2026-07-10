/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_STRING_H
#define _LINUX_STRING_H

#include <linux/types.h>

static inline void *__bpf_log_memset(void *dst, int c, __kernel_size_t n)
{
	unsigned char *d = dst;
	__kernel_size_t i;

	for (i = 0; i < n && i < 512; i++)
		d[i] = (unsigned char)c;
	return dst;
}

static inline void *__bpf_log_memcpy(void *dst, const void *src,
				     __kernel_size_t n)
{
	unsigned char *d = dst;
	const unsigned char *s = src;
	__kernel_size_t i;

	for (i = 0; i < n && i < 512; i++)
		d[i] = s[i];
	return dst;
}

static inline char *__bpf_log_strrchr(const char *s, int c)
{
	const char *last = (void *)0;

	for (; *s; s++) {
		if (*s == (char)c)
			last = s;
	}
	return (char *)last;
}

static inline size_t __bpf_log_strscpy(char *dst, const char *src, size_t size)
{
	size_t i;

	if (!size)
		return 0;
	for (i = 0; i + 1 < size && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';
	return i;
}

static inline int isspace(int c)
{
	return c == ' ' || (c >= '\t' && c <= '\r');
}

#define memset(dst, c, n)	__bpf_log_memset((dst), (c), (n))
#define memcpy(dst, src, n)	__bpf_log_memcpy((dst), (src), (n))
#define strrchr(s, c)		__bpf_log_strrchr((s), (c))
#define strscpy(dst, src, ...)	__bpf_log_strscpy((dst), (src), sizeof(dst))

#endif /* _LINUX_STRING_H */
