/* Undef the rename macros so identifiers are clean in the harness body. */
#undef cordic_iq
#undef cordic_calc_iq
/* Alias the original struct name to the renamed tag. */
typedef struct __bpf_cordic_iq cordic_iq_t;
/* Pointer-based wrapper: calls __bpf_cordic_calc_iq (renamed, internal-linkage
 * version of cordic_calc_iq) and writes the result through a pointer,
 * avoiding StructRet in the harness body. */
static __attribute__((__noinline__))
void cordic_calc_iq_to_ptr(s32 theta, struct __bpf_cordic_iq *out)
{
    *out = __bpf_cordic_calc_iq(theta);
}
