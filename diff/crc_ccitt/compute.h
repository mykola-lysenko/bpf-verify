/* crc_ccitt: CRC-CCITT (table-driven) over 16 bytes with a seed. */
static __u64 diff_compute(const __u64 in[4])
{
	__u8 buf[16];
	int i;
	for (i = 0; i < 8; i++) {
		buf[i]     = (__u8)(in[0] >> (i * 8));
		buf[i + 8] = (__u8)(in[1] >> (i * 8));
	}
	return (__u64)crc_ccitt((__u16)in[2], buf, sizeof(buf));
}
