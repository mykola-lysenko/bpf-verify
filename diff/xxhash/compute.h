/* xxh64: 64-bit hash, heavy on 64-bit multiplies by magic primes -- stresses
 * the BPF backend's 64-bit multiply lowering. Hash 16 bytes with a seed. */
static __u64 diff_compute(const __u64 in[4])
{
	__u64 buf[2] = { in[0], in[1] };
	return xxh64(buf, sizeof(buf), in[2]);
}
