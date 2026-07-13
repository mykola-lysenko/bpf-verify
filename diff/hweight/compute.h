/* hweight: the out-of-line software popcounts -- SWAR mask/add/multiply
 * bit tricks in 32- and 64-bit forms. */
static __u64 diff_compute(const __u64 in[4])
{
	return (__u64)__sw_hweight64(in[0]) ^
	       ((__u64)__sw_hweight32((u32)in[1]) << 8) ^
	       ((__u64)__sw_hweight64(in[2] ^ in[3]) << 16);
}
