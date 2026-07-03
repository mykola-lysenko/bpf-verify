/* int_pow(base, exp): repeated-multiply exponentiation. Exponent is capped so
 * the loop is verifier-bounded; stresses 64-bit multiply codegen. */
static __u64 diff_compute(const __u64 in[4])
{
	return int_pow(in[0], (unsigned int)(in[1] & 15));
}
