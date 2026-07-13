/* int_log: fixed-point intlog2/intlog10 -- iterative shift/compare with
 * scaled remainders. Zero is not in the functions' domain; force nonzero. */
static __u64 diff_compute(const __u64 in[4])
{
	u32 a = (u32)in[0] | 1;
	u32 b = (u32)in[1] | 1;

	return ((__u64)intlog2(a) << 32) | (__u64)intlog10(b);
}
