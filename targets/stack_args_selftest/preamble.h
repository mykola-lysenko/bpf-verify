/* Self-test: a static subprogram with 6 arguments (the 6th passes on the stack).
 * Verifies only with clang 23+ (backend stack-arg support) AND .BTF.ext kept
 * (the verifier reads the subprogram arg count from func-info -- see
 * analysis/global_functions_and_inlining.md). No always_inline needed.
 * A regression here means the toolchain lost >5-arg static-subprogram support. */
static __attribute__((__noinline__)) long
bpf_stack_arg_selftest(long a, long b, long c, long d, long e, long f)
{
	return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6;
}
