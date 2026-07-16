/* SM3 (lib/crypto/sm3.c, GM/T 0004-2012). Same recipe as lib_sha256/512:
 * -std=gnu11, __DISABLE_EXPORTS, inline mem*. Drives sm3_block_generic over
 * whole 64-byte blocks (W[16] passed in from the map), bypassing the streaming
 * sm3_update partial-buffer path. */
#define __DISABLE_EXPORTS
static inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{ unsigned char *d=dst; const unsigned char *s=src; __kernel_size_t i; for(i=0;i<n;i++) d[i]=s[i]; return dst; }
static inline void *memset(void *dst, int c, __kernel_size_t n)
{ unsigned char *d=dst; __kernel_size_t i; for(i=0;i<n;i++) d[i]=(unsigned char)c; return dst; }
