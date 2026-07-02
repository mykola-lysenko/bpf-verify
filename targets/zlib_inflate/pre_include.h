/* Block inftrees.h so inflate.c's #include "inftrees.h" is a no-op.
 * NOTE: inftrees.h was already included by inffast.c (via EXTRA_INCLUDES),
 * so 'code', 'codetype', ENOUGH, MAXD are already defined. We just need to
 * block inflate.c from including inftrees.h again (which would redefine them). */
#define INFTREES_H
/* Rename zlib_inflate_table to a hidden name (applies to both inftrees.c
 * definition and inflate.c call sites). */
#define zlib_inflate_table __bpf_zit_impl
/* Static forward declaration keeps the 6-arg helper on the BPF static
 * subprogram path where stack arguments are supported. */
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
