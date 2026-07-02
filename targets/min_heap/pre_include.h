/* Provide memcpy as static inline to avoid extern BTF resolution failure.
 * min_heap.c calls memcpy internally; libbpf needs BTF for all externs. */
static inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
    return dst;
}
/* File-scope callback functions for the int min-heap.
 * These are defined here (before the source include) so they are
 * available to the BPF-friendly heap operations in EXTRA_PREAMBLE. */
static bool __bpf_int_less(const void *a, const void *b, void *args) {
    return *(const int *)a < *(const int *)b;
}
static void __bpf_int_swap(void *a, void *b, void *args) {
    int t = *(int *)a;
    *(int *)a = *(int *)b;
    *(int *)b = t;
}
/* Note: __bpf_heap_push/__bpf_heap_pop are defined in EXTRA_PREAMBLE
 * (after min_heap.c is included) because they need min_heap_char which
 * is only available after linux/min_heap.h is included by min_heap.c. */
