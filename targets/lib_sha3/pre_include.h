/* SHA-3 / Keccak (lib/crypto/sha3.c). Same recipe as lib_sha256/lib_sha512:
 * -std=gnu11 (C99 for-loop decls in the source), __DISABLE_EXPORTS to skip the
 * arch header + module-export wrappers, inline mem*. We drive
 * sha3_keccakf_generic directly -- the pure 1600-bit Keccak-f permutation (24
 * rounds of theta/rho/pi/chi/iota over u64 st[25]) -- which has no absorb
 * buffering, no callbacks, and no state-reloaded loop bound. */
#define __DISABLE_EXPORTS
static inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{ unsigned char *d=dst; const unsigned char *s=src; __kernel_size_t i; for(i=0;i<n;i++) d[i]=s[i]; return dst; }
static inline void *memset(void *dst, int c, __kernel_size_t n)
{ unsigned char *d=dst; __kernel_size_t i; for(i=0;i<n;i++) d[i]=(unsigned char)c; return dst; }
