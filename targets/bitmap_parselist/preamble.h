/* Resolve externs that bitmap-str.c references from other translation units.
 * Real implementations for the bitmap_parselist() call graph (so the program
 * reaching the verifier exercises genuine parse + bitmap-write logic); trivial
 * stubs for symbols only reached by the file's unexercised user/sysfs helpers
 * (bitmap_parse_user, bitmap_print_*). Declared extern in linux/{bitmap,string,
 * hex}.h, so these are plain (external-linkage) definitions. */

/* --- exercised: bitmap ops (linux/bitmap.h) --- */
void __bitmap_set(unsigned long *map, unsigned int start, int len)
{
	while (len-- > 0) { map[start / 64] |= 1UL << (start % 64); start++; }
}
void __bitmap_clear(unsigned long *map, unsigned int start, int len)
{
	while (len-- > 0) { map[start / 64] &= ~(1UL << (start % 64)); start++; }
}
unsigned long _find_next_bit(const unsigned long *addr, unsigned long nbits,
			     unsigned long start)
{
	while (start < nbits) {
		if (addr[start / 64] & (1UL << (start % 64)))
			return start;
		start++;
	}
	return nbits;
}

/* --- exercised: string/format helpers --- */
void *memset(void *s, int c, __kernel_size_t n)
{
	unsigned char *p = s;
	while (n--) *p++ = (unsigned char)c;
	return s;
}
__kernel_size_t strlen(const char *s)
{
	__kernel_size_t n = 0;
	while (s[n]) n++;
	return n;
}
char *strnchrnul(const char *s, __kernel_size_t count, int c)
{
	while (count-- && *s && *s != (char)c) s++;
	return (char *)s;
}
int hex_to_bin(unsigned char ch)
{
	if (ch >= '0' && ch <= '9') return ch - '0';
	ch |= 0x20;
	if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
	return -1;
}
int strncasecmp(const char *s1, const char *s2, __kernel_size_t n)
{
	while (n--) {
		unsigned char a = *s1++, b = *s2++;
		if (a >= 'A' && a <= 'Z') a += 32;
		if (b >= 'A' && b <= 'Z') b += 32;
		if (a != b || !a) return (int)a - (int)b;
	}
	return 0;
}

/* _parse_integer (bitmap_getnum's number scanner). The real one in lib/kstrtox.c
 * uses 128-bit multiply (__multi3, unavailable on BPF) purely for overflow
 * detection; a 64-bit accumulation is equivalent for the verifier's purposes
 * (bitmap-str feeds it small, bounded numeric strings). */
#ifndef KSTRTOX_OVERFLOW
#define KSTRTOX_OVERFLOW (1U << 31)
#endif
unsigned int _parse_integer(const char *s, unsigned int base, unsigned long long *res)
{
	unsigned long long val = 0;
	unsigned int count = 0;

	for (;; s++, count++) {
		unsigned char c = (unsigned char)*s;
		int d;

		if (c >= '0' && c <= '9')
			d = c - '0';
		else if (((c | 0x20) >= 'a') && ((c | 0x20) <= 'z'))
			d = (c | 0x20) - 'a' + 10;
		else
			break;
		if ((unsigned int)d >= base)
			break;
		val = val * base + (unsigned long long)d;
	}
	*res = val;
	return count;
}

/* --- unexercised-path stubs (user/sysfs helpers) --- */
void *memdup_user_nul(const void __user *u, __kernel_size_t n) { (void)u; (void)n; return (void *)0; }
__kernel_ssize_t memory_read_from_buffer(void *to, __kernel_size_t count, long long *ppos,
					 const void *from, __kernel_size_t available)
{ (void)to; (void)count; (void)ppos; (void)from; (void)available; return 0; }
