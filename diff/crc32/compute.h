/* crc32: both byte orders of the table-driven CRC over 16 bytes with a seeded
 * initial crc. Exercises table indexing + shift/xor in le and be forms. */
static __u64 diff_compute(const __u64 in[4])
{
	__u8 buf[16];
	int i;

	for (i = 0; i < 8; i++) {
		buf[i]     = (__u8)(in[0] >> (i * 8));
		buf[i + 8] = (__u8)(in[1] >> (i * 8));
	}
	return ((__u64)crc32_le((u32)in[2], buf, sizeof(buf)) << 32) |
	       (__u64)crc32_be((u32)in[3], buf, sizeof(buf));
}
