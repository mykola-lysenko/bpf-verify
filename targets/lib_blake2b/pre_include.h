/* BLAKE2b (lib/crypto/blake2b.c). Same recipe: -std=gnu11, __DISABLE_EXPORTS,
 * inline mem*. Drives blake2b_compress_generic directly (one 128-byte block) --
 * 12 rounds of the G mixing function over 16 u64 words, bypassing the streaming
 * blake2b_update partial-buffer path. */
#define __DISABLE_EXPORTS
/* blake2b's rounds loop is `unrolled_full` (linux/unroll.h) -> a 12x pragma
 * unroll that spills the m[16]/v[16] temporaries well past the 512-byte BPF
 * stack. Block unroll.h and stub the macros empty so the rounds stay a rolled
 * loop (the compression result is identical). */
#define __UNROLL_H
#define unrolled_full
#define unrolled_count(n)
#define unrolled
static inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{ unsigned char *d=dst; const unsigned char *s=src; __kernel_size_t i; for(i=0;i<n;i++) d[i]=s[i]; return dst; }
static inline void *memset(void *dst, int c, __kernel_size_t n)
{ unsigned char *d=dst; __kernel_size_t i; for(i=0;i<n;i++) d[i]=(unsigned char)c; return dst; }
