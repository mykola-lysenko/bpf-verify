// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: lib/string_helpers.c
 * Keeps string_unescape + 4 static unescape helpers.
 * Drops string_escape_mem (6 args), string_get_size (snprintf/do_div),
 * and all allocator/VFS-dependent functions. */

#include <linux/types.h>
#include <linux/limits.h>
#include <linux/hex.h>

static inline int isodigit(char c)
{
	return c >= '0' && c <= '7';
}

static __always_inline bool unescape_space(char **src, char **dst)
{
	char *p = *dst, *q = *src;

	switch (*q) {
	case 'n': *p = '\n'; break;
	case 'r': *p = '\r'; break;
	case 't': *p = '\t'; break;
	case 'v': *p = '\v'; break;
	case 'f': *p = '\f'; break;
	default: return false;
	}
	*dst += 1;
	*src += 1;
	return true;
}

static __always_inline bool unescape_octal(char **src, char **dst)
{
	char *p = *dst, *q = *src;
	u8 num;

	if (isodigit(*q) == 0)
		return false;

	num = (*q++) & 7;
	while (num < 32 && isodigit(*q) && (q - *src < 3)) {
		num <<= 3;
		num += (*q++) & 7;
	}
	*p = num;
	*dst += 1;
	*src = q;
	return true;
}

static __always_inline bool unescape_hex(char **src, char **dst)
{
	char *p = *dst, *q = *src;
	int digit;
	u8 num;

	if (*q++ != 'x')
		return false;

	num = digit = hex_to_bin(*q++);
	if (digit < 0)
		return false;

	digit = hex_to_bin(*q);
	if (digit >= 0) {
		q++;
		num = (num << 4) | digit;
	}
	*p = num;
	*dst += 1;
	*src = q;
	return true;
}

static __always_inline bool unescape_special(char **src, char **dst)
{
	char *p = *dst, *q = *src;

	switch (*q) {
	case '\"': *p = '\"'; break;
	case '\\': *p = '\\'; break;
	case 'a':  *p = '\a'; break;
	case 'e':  *p = '\033'; break;
	default: return false;
	}
	*dst += 1;
	*src += 1;
	return true;
}

static __always_inline
int string_unescape(char *src, char *dst, size_t size, unsigned int flags)
{
	char *out = dst;

	if (!size)
		size = SIZE_MAX;

	while (*src && --size) {
		if (src[0] == '\\' && src[1] != '\0' && size > 1) {
			src++;
			size--;

			if (flags & UNESCAPE_SPACE &&
					unescape_space(&src, &out))
				continue;

			if (flags & UNESCAPE_OCTAL &&
					unescape_octal(&src, &out))
				continue;

			if (flags & UNESCAPE_HEX &&
					unescape_hex(&src, &out))
				continue;

			if (flags & UNESCAPE_SPECIAL &&
					unescape_special(&src, &out))
				continue;

			*out++ = '\\';
		}
		*out++ = *src++;
	}
	*out = '\0';

	return out - dst;
}
