/* xxh32: 32-bit xxHash -- 32-bit multiply-by-prime + rotate, complementing
 * xxh64's 64-bit multiply path. */
static __u64 diff_compute(const __u64 in[4])
{
	__u32 buf[2] = { (__u32)in[0], (__u32)in[1] };
	return xxh32(buf, sizeof(buf), (__u32)in[2]);
}
