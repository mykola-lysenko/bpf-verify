/* crypto_utils.c has a fallback alignment probe that XORs pointer values.
 * That is valid C, but the BPF verifier rejects bitwise ops on pointers.
 * The CI/kernel target is x86_64, where unaligned accesses are efficient,
 * so force the code path that skips pointer-to-integer alignment arithmetic. */
#undef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
/* Provide __ffs as static inline to avoid extern BTF reference */
static inline unsigned long __ffs(unsigned long word)
{
    unsigned long bit = 0;
    while (!(word & 1)) { word >>= 1; bit++; }
    return bit;
}
