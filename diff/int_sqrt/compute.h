/* int_sqrt: bit-by-bit integer square root -- fls + shift-subtract loop.
 * Inputs masked to 24/16 bits: with a fully unknown 64-bit operand the
 * verifier's exploration of the data-dependent loop blows the 1M-insn budget
 * (the coverage target only passes because its literal inputs constant-fold;
 * int_sqrt_global documents the all-inputs blow-up). 24 bits still walks the
 * loop a dozen data-dependent iterations on both sides. */
static __u64 diff_compute(const __u64 in[4])
{
	return (__u64)int_sqrt((unsigned long)(in[0] & 0xffffff)) ^
	       ((__u64)int_sqrt((unsigned long)(in[1] & 0xffff)) << 32);
}
