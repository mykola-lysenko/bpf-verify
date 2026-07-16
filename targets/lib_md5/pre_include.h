/* MD5 (lib/crypto/md5.c). Same recipe as the SHA targets: -std=gnu11,
 * __DISABLE_EXPORTS, inline mem*. Drives md5_block over whole 64-byte blocks,
 * bypassing the streaming md5_update partial-buffer path. (MD5 is broken for
 * security but still used for non-crypto checksums; here it is a codegen
 * target -- 64 rounds of 32-bit add/rotate/F-G-H-I.) */
#define __DISABLE_EXPORTS
/* crypto/md5.h (unlike sha2.h/sm3.h) pulls the private crypto/hash.h -> the
 * shash/ahash API (incomplete ahash_alg breaks offsetof). The lib MD5 path
 * (md5_block/init/update) does not need it; block it via its guard. */
#define _LOCAL_CRYPTO_HASH_H
static inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{ unsigned char *d=dst; const unsigned char *s=src; __kernel_size_t i; for(i=0;i<n;i++) d[i]=s[i]; return dst; }
static inline void *memset(void *dst, int c, __kernel_size_t n)
{ unsigned char *d=dst; __kernel_size_t i; for(i=0;i<n;i++) d[i]=(unsigned char)c; return dst; }
