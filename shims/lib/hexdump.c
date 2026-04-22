// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: lib/hexdump.c
 * Keeps hex_to_bin, hex2bin, bin2hex, hex_asc arrays.
 * Drops hex_dump_to_buffer (7 args, snprintf) and print_hex_dump (8 args, printk). */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/compiler.h>

const char hex_asc[] = "0123456789abcdef";
const char hex_asc_upper[] = "0123456789ABCDEF";

static inline char *hex_byte_pack(char *buf, unsigned char byte)
{
	*buf++ = hex_asc[(byte >> 4) & 0xf];
	*buf++ = hex_asc[byte & 0xf];
	return buf;
}

int hex_to_bin(unsigned char ch)
{
	unsigned char cu = ch & 0xdf;
	return -1 +
		((ch - '0' +  1) & (unsigned)((ch - '9' - 1) & ('0' - 1 - ch)) >> 8) +
		((cu - 'A' + 11) & (unsigned)((cu - 'F' - 1) & ('A' - 1 - cu)) >> 8);
}

int hex2bin(u8 *dst, const char *src, size_t count)
{
	while (count--) {
		int hi, lo;

		hi = hex_to_bin(*src++);
		if (unlikely(hi < 0))
			return -EINVAL;
		lo = hex_to_bin(*src++);
		if (unlikely(lo < 0))
			return -EINVAL;

		*dst++ = (hi << 4) | lo;
	}
	return 0;
}

char *bin2hex(char *dst, const void *src, size_t count)
{
	const unsigned char *_src = src;

	while (count--)
		dst = hex_byte_pack(dst, *_src++);
	return dst;
}
