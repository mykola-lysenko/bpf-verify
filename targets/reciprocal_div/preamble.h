/* Undef the function-rename macros so identifiers are clean in the harness body. */
#undef reciprocal_value
#undef reciprocal_value_adv
/* Alias the original struct names to the renamed tags. */
typedef struct __bpf_recip_rv  reciprocal_value_t;
typedef struct __bpf_recip_rva reciprocal_value_adv_t;
/* Pointer-based wrapper: calls __bpf_recip_rv (the renamed, internal-linkage
 * version of reciprocal_value) and writes the result through a pointer,
 * avoiding StructRet in the harness body. */
static __attribute__((__noinline__))
void reciprocal_value_to_ptr(__u32 d, struct __bpf_recip_rv *out)
{
    *out = __bpf_recip_rv(d);
}
