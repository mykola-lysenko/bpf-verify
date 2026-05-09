// SPDX-License-Identifier: GPL-2.0
/* bloom_filter-shim.c: BPF-compatible shim for kernel/bpf/bloom_filter.c
 *
 * The original bloom_filter.c uses:
 *   - struct bpf_map (deep kernel type, not needed for core logic)
 *   - flexible array member for bitset
 *   - linux/bpf.h, linux/btf.h (deep kernel headers)
 *
 * This shim provides a self-contained bloom filter with:
 *   - A fixed-size bitset (256 bits = 4 unsigned longs on 64-bit)
 *   - The same bitset_mask/hash_seed/nr_hash_funcs metadata used upstream
 *   - jhash/jhash2 from linux/jhash.h (header-only, pure C)
 *   - BPF-verifier-friendly test_bit/set_bit replacements
 */

#include <linux/types.h>
#include <linux/jhash.h>

/* Fixed-size bloom filter: 256-bit bitset stored as 4 x u64.
 * We do NOT use linux/bitops.h test_bit/set_bit because those generate
 * variable-offset stack pointer arithmetic that the BPF verifier rejects.
 * Instead we implement our own bounded bit operations using explicit
 * array indexing (word_idx = bit >> 6, bit_mask = 1ULL << (bit & 63)).
 */
#define BLOOM_BITSET_BITS   256U
#define BLOOM_BITSET_WORDS  4U   /* 256 / 64 = 4 u64 words */
#ifndef likely
#define likely(x)           (x)
#endif

/* Minimal bpf_map stub -- only the fields bloom_filter.c actually uses */
struct bpf_map {
    u32 value_size;
};

struct bpf_bloom_filter {
    struct bpf_map   map;
    u32              bitset_mask;
    u32              hash_seed;
    u32              nr_hash_funcs;
    u64              bitset[BLOOM_BITSET_WORDS]; /* 4 x u64 = 256 bits */
};

/* Initialise a bloom filter with a fixed 256-bit bitset */
static inline
void bloom_filter_init(struct bpf_bloom_filter *bloom,
                       u32 value_size, u32 nr_hash_funcs, u32 seed)
{
    bloom->map.value_size     = value_size;
    bloom->bitset_mask        = BLOOM_BITSET_BITS - 1U;
    bloom->hash_seed          = seed;
    bloom->nr_hash_funcs      = nr_hash_funcs;
    bloom->bitset[0] = 0ULL;
    bloom->bitset[1] = 0ULL;
    bloom->bitset[2] = 0ULL;
    bloom->bitset[3] = 0ULL;
}

/* BPF-verifier-friendly bit test: word index is bounded to 0..3 */
static inline
int bloom_test_bit(u64 *bitset, u32 bit)
{
    u32 word = (bit >> 6) & 3U;  /* 0..3, compile-time bounded */
    u64 mask = 1ULL << (bit & 63U);
    return (bitset[word] & mask) != 0;
}

/* BPF-verifier-friendly bit set: word index is bounded to 0..3 */
static inline
void bloom_set_bit(u64 *bitset, u32 bit)
{
    u32 word = (bit >> 6) & 3U;  /* 0..3, compile-time bounded */
    u64 mask = 1ULL << (bit & 63U);
    bitset[word] |= mask;
}

/* -----------------------------------------------------------------------
 * Core functions adapted from kernel/bpf/bloom_filter.c. hash() is renamed to
 * bloom_hash() to avoid conflicts with library identifiers.
 * ----------------------------------------------------------------------- */

#ifndef BPF_ANY
#define BPF_ANY 0ULL
#endif
#ifndef ENOENT
#define ENOENT  2
#endif
#ifndef EINVAL
#define EINVAL  22
#endif

static __attribute__((always_inline))
u32 bloom_hash(struct bpf_bloom_filter *bloom, void *value,
               u32 value_size, u32 index)
{
    u32 h;
    if (likely(value_size % 4 == 0))
        h = jhash2(value, value_size / 4, bloom->hash_seed + index);
    else
        h = jhash(value, value_size, bloom->hash_seed + index);
    return h & bloom->bitset_mask;
}

static __attribute__((always_inline))
int bloom_map_peek_elem(struct bpf_bloom_filter *bloom, void *value)
{
    u32 i, h;
    for (i = 0; i < bloom->nr_hash_funcs; i++) {
        h = bloom_hash(bloom, value, bloom->map.value_size, i);
        if (!bloom_test_bit(bloom->bitset, h))
            return -ENOENT;
    }
    return 0;
}

static __attribute__((always_inline))
int bloom_map_push_elem(struct bpf_bloom_filter *bloom, void *value, u64 flags)
{
    u32 i, h;
    if (flags != BPF_ANY)
        return -EINVAL;
    for (i = 0; i < bloom->nr_hash_funcs; i++) {
        h = bloom_hash(bloom, value, bloom->map.value_size, i);
        bloom_set_bit(bloom->bitset, h);
    }
    return 0;
}
