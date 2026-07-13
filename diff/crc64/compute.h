/* crc64: 64-bit table CRC in both variants (be, nvme) over 16 bytes with a
 * seeded initial crc -- 64-bit shift/xor/table codegen. */
static __u64 diff_compute(const __u64 in[4])
{
	__u8 buf[16];
	int i;

	for (i = 0; i < 8; i++) {
		buf[i]     = (__u8)(in[0] >> (i * 8));
		buf[i + 8] = (__u8)(in[1] >> (i * 8));
	}
	return crc64_be(in[2], buf, sizeof(buf)) ^
	       crc64_nvme(in[3], buf, sizeof(buf));
}
