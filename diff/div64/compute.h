/* 64-bit division: compare the BPF-compiled div64_u64() fallback against the
 * native-compiled one (both with -U__SIZEOF_INT128__, the path BPF actually
 * takes). 64-bit division lowering is a classic BPF-backend weak spot. */
static __u64 diff_compute(const __u64 in[4])
{
	__u64 divisor = in[1] ? in[1] : 1;
	return div64_u64(in[0], divisor);
}
