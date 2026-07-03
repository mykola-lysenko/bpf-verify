/* Shared computation for the bitrev native-vs-BPF differential.
 * Both the BPF harness and the native driver include this after the real
 * kernel bitrev source, so diff_compute() calls the genuine bitrev32(). */
static __u64 diff_compute(const __u64 in[4])
{
	return (__u64)(__u32)bitrev32((__u32)in[0]);
}
