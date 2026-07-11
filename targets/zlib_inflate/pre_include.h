/* Block inftrees.h so inflate.c's #include "inftrees.h" is a no-op.
 * NOTE: inftrees.h was already included by inffast.c (via EXTRA_INCLUDES),
 * so 'code', 'codetype', ENOUGH, MAXD are already defined. We just need to
 * block inflate.c from including inftrees.h again (which would redefine them). */
#define INFTREES_H
/* Rename zlib_inflate_table to a hidden name (applies to both inftrees.c
 * definition and inflate.c call sites). */
#define zlib_inflate_table __bpf_zit_impl
/* The helper takes 6 arguments -> the 6th passes on the stack. clang 23 (our CI
 * toolchain) supports stack args to static subprograms, so no always_inline is
 * needed; clang 22.x rejected it ("stack arguments are not supported"). See
 * analysis/global_functions_and_inlining.md and targets/stack_args_selftest. */
static int __bpf_zit_impl(
    codetype type, unsigned short *lens, unsigned codes,
    code **table, unsigned *bits, unsigned short *work);
/* Include inftrees.c to provide the definition. */
#include "{ksrc}/lib/zlib_inflate/inftrees.c"
/* Provide memcpy as static inline to avoid extern BTF reference. */
static inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}
