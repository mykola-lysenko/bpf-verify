/* New kernel: _find_next_bit has 3 args, no special treatment needed. */
/* Provide __bitmap_weight as a static inline so find_random_bit() compiles
 * without an unresolved extern BTF reference to __bitmap_weight. */
static inline unsigned int __bitmap_weight(const unsigned long *bitmap, unsigned int bits)
{
    unsigned int w = 0, idx;
    for (idx = 0; idx < bits / (8 * sizeof(unsigned long)); idx++)
        w += __builtin_popcountl(bitmap[idx]);
    if (bits % (8 * sizeof(unsigned long)))
        w += __builtin_popcountl(bitmap[idx] & (~0UL >> ((8 * sizeof(unsigned long)) - bits % (8 * sizeof(unsigned long)))));
    return w;
}
/* Stub get_random_u32_below: for BPF verification purposes, always return 0.
 * find_random_bit() uses it to pick a random set bit; returning 0 selects the
 * first set bit, which is a valid (deterministic) code path. */
static inline u32 get_random_u32_below(u32 ceil) { return 0; }
