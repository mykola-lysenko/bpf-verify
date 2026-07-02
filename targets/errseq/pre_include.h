/* BPF-safe non-atomic cmpxchg for errseq_t (u32). BPF does not support
 * 32-bit atomics; provide a plain load-compare-store instead. */
#define arch_cmpxchg(ptr, old, new) \
    ({ typeof(*(ptr)) __prev = *(ptr); \
       if (__prev == (old)) *(ptr) = (new); \
       __prev; })
