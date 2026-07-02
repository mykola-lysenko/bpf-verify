/* gf128mul.c has allocation helpers for its 64k table path.  The harness only
 * exercises gf128mul_x8_ble(), but libbpf still needs emitted externs resolved. */
#define _LINUX_SLAB_H
#define GFP_KERNEL 0
static inline void *__bpf_gf128mul_kzalloc(__kernel_size_t size, unsigned int flags)
    { (void)size; (void)flags; return (void *)0; }
static inline void __bpf_gf128mul_kfree(const void *p)
    { (void)p; }
static inline void *__bpf_gf128mul_memset(void *dst, int c, __kernel_size_t n)
{
    unsigned char *d = dst;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}
#define kzalloc(size, flags) __bpf_gf128mul_kzalloc((size), (flags))
#define kfree(p) __bpf_gf128mul_kfree((p))
#define kfree_sensitive(p) __bpf_gf128mul_kfree((p))
#define kzalloc_obj(p, ...) ((typeof(&(p)))__bpf_gf128mul_kzalloc(sizeof(p), GFP_KERNEL))
#define memset(dst, c, n) __bpf_gf128mul_memset((dst), (c), (n))
