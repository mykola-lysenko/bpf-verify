#include <linux/errno.h>
static inline
u32 __bpf_rol32(u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((0 - shift) & 31));
}
#define rol32(word, shift) __bpf_rol32((word), (shift))
#undef __alias
#define __alias(symbol)
#include "{ksrc}/crypto/sm4.c"
