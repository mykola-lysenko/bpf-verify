/* uuid_parse: parse a canonical UUID string ("xxxxxxxx-xxxx-...") into 16
 * bytes -- format validation (uuid_is_valid) + per-nibble hex decode with the
 * uuid_index byte reordering. Hex-decode + table (ctype/hex) codegen, native
 * vs BPF. The string is built from 16 seeded bytes so every parse is a
 * well-formed accept; we fold the decoded bytes plus the return code. */
/* native: _ctype (isxdigit in uuid_is_valid) lives in lib/ctype.c; the BPF side
 * pulls it via the uuid target's extra_includes. */
#ifndef __bpf__
#include DIFF_CTYPE_C
#endif
/* native only: hex_to_bin lives in lib/hex.c (not linked on the host); the BPF
 * side already gets it from the uuid target's pre_include. */
#ifndef __bpf__
void get_random_bytes(void *buf, int nbytes) { (void)buf; (void)nbytes; }
int hex_to_bin(unsigned char ch)
{
	if (ch >= '0' && ch <= '9') return ch - '0';
	ch |= 0x20;
	if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
	return -1;
}
#endif

static __u64 diff_compute(const __u64 in[4])
{
	static const char hexd[] = "0123456789abcdef";
	unsigned char bytes[16];
	char str[37];
	uuid_t out;
	int i, j, ret;

	for (i = 0; i < 16; i++)
		bytes[i] = (unsigned char)(in[i >> 2] >> ((i & 3) * 8));

	/* canonical 8-4-4-4-12 layout with dashes at 8,13,18,23 */
	j = 0;
	for (i = 0; i < 16; i++) {
		if (j == 8 || j == 13 || j == 18 || j == 23)
			str[j++] = '-';
		str[j++] = hexd[bytes[i] >> 4];
		str[j++] = hexd[bytes[i] & 0xf];
	}
	str[36] = '\0';

	ret = uuid_parse(str, &out);
	if (ret)
		return 0xdeadULL ^ (__u64)(unsigned)ret;

	{
		__u64 lo = 0, hi = 0;
		for (i = 0; i < 8; i++) {
			lo |= (__u64)out.b[i] << (i * 8);
			hi |= (__u64)out.b[i + 8] << (i * 8);
		}
		return lo ^ (hi * 0x9e3779b97f4a7c15ULL);
	}
}
