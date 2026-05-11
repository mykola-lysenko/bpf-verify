// SPDX-License-Identifier: GPL-2.0-only
/* lpm_trie-shim.c: BPF-compatible self-contained shim for kernel/bpf/lpm_trie.c
 *
 * This shim is fully self-contained: it does NOT include any kernel headers
 * (which drag in spinlock, RCU, slab, vmalloc, BTF, etc. -- all incompatible
 * with BPF compilation). Instead it:
 *
 *   1. Defines all necessary types (u8, u32, u64, bool, size_t) from scratch.
 *   2. Provides inline fls/fls64 implementations.
 *   3. Defines the lpm_trie_node, lpm_trie, and bpf_lpm_trie_key_u8 structs
 *      used by the current kernel source.
 *   4. Provides no-op lock, RCU, and allocator stubs.
 *   5. Provides a static node pool (16 nodes) to replace kmalloc/kfree.
 *   6. Keeps the verifier-covered lookup/update helpers close to lpm_trie.c:
 *        - extract_bit()
 *        - longest_prefix_match()
 *        - trie_lookup_elem()
 *        - trie_update_elem()
 *        - trie_delete_elem()
 *
 * The goal is to verify the core LPM lookup and prefix-match algorithms
 * using the BPF verifier, without needing the full kernel infrastructure.
 */

#include "bpf_shim_common.h"

/* -----------------------------------------------------------------------
 * fls / fls64 (find last set bit, 1-indexed, 0 if none)
 * ----------------------------------------------------------------------- */
static inline int fls(unsigned int x)
{
    int r = 32;
    if (!x) return 0;
    if (!(x & 0xffff0000u)) { x <<= 16; r -= 16; }
    if (!(x & 0xff000000u)) { x <<= 8;  r -= 8;  }
    if (!(x & 0xf0000000u)) { x <<= 4;  r -= 4;  }
    if (!(x & 0xc0000000u)) { x <<= 2;  r -= 2;  }
    if (!(x & 0x80000000u)) { r -= 1; }
    return r;
}

static inline int fls64(u64 x)
{
    u32 hi = (u32)(x >> 32);
    if (hi) return fls(hi) + 32;
    return fls((u32)x);
}

/* -----------------------------------------------------------------------
 * Byte-order helpers (big-endian to CPU, for x86 little-endian)
 * ----------------------------------------------------------------------- */
static inline u32 be32_to_cpu(u32 x)
{
    return ((x & 0xff000000u) >> 24) | ((x & 0x00ff0000u) >> 8) |
           ((x & 0x0000ff00u) <<  8) | ((x & 0x000000ffu) << 24);
}
static inline u16 be16_to_cpu(u16 x)
{
    return (u16)((x >> 8) | (x << 8));
}
static inline u64 be64_to_cpu(u64 x)
{
    return ((u64)be32_to_cpu((u32)(x >> 32))) |
           (((u64)be32_to_cpu((u32)(x & 0xffffffffull))) << 32);
}

static inline void *__lpm_memcpy(void *d, const void *s, size_t n)
{
    u8 *dd = (u8 *)d;
    const u8 *ss = (const u8 *)s;
    size_t i;
    for (i = 0; i < n; i++) dd[i] = ss[i];
    return d;
}
#define memcpy(d, s, n)  __lpm_memcpy(d, s, n)

/* -----------------------------------------------------------------------
 * ERR_PTR / IS_ERR
 * ----------------------------------------------------------------------- */
static inline void *ERR_PTR(long error)
{ return (void *)error; }
static inline bool IS_ERR(const void *ptr)
{ return (unsigned long)ptr >= (unsigned long)-4095; }

/* -----------------------------------------------------------------------
 * bpf_lpm_trie_key_u8 (from uapi/linux/bpf.h)
 * ----------------------------------------------------------------------- */
struct bpf_lpm_trie_key_hdr {
    __u32 prefixlen;
};

struct bpf_lpm_trie_key_u8 {
    union {
        struct bpf_lpm_trie_key_hdr hdr;
        __u32 prefixlen;
    };
    __u8  data[0];
};

/* -----------------------------------------------------------------------
 * Minimal bpf_map stub (only fields lpm_trie.c accesses)
 * ----------------------------------------------------------------------- */
struct bpf_map {
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    int   numa_node;
};

struct bpf_mem_alloc {
    int dummy;
};

/* -----------------------------------------------------------------------
 * lpm_trie_node and lpm_trie
 * ----------------------------------------------------------------------- */
#define LPM_TREE_NODE_FLAG_IM BIT(0)

struct lpm_trie_node;

struct lpm_trie_node {
    struct lpm_trie_node __rcu  *child[2];
    u32                          prefixlen;
    u32                          flags;
    u8                           data[];
};

struct lpm_trie {
    struct bpf_map               map;
    struct lpm_trie_node __rcu  *root;
    struct bpf_mem_alloc         ma;
    size_t                       n_entries;
    size_t                       max_prefixlen;
    size_t                       data_size;
    rqspinlock_t                 lock;
};

/* -----------------------------------------------------------------------
 * Static node pool (replaces kmalloc/kfree -- no heap in BPF)
 *
 * Each node needs: sizeof(lpm_trie_node) + data_size + value_size.
 * For IPv4 (data_size=4) + 8-byte value: 24 + 4 + 8 = 36 bytes.
 * We use 64-byte slots to be safe.
 * ----------------------------------------------------------------------- */
#define LPM_POOL_SIZE  16
#define LPM_BPF_DATA_SIZE   4
#define LPM_BPF_VALUE_SIZE  8

static char __lpm_node_pool[LPM_POOL_SIZE][64];
static int  __lpm_pool_used[LPM_POOL_SIZE];

static struct lpm_trie_node *bpf_map_kmalloc_node(
    struct bpf_map *map, size_t size, int flags, int numa_node)
{
    int i, j;
    (void)map; (void)size; (void)flags; (void)numa_node;
    for (i = 0; i < LPM_POOL_SIZE; i++) {
        if (!__lpm_pool_used[i]) {
            __lpm_pool_used[i] = 1;
            for (j = 0; j < 64; j++) __lpm_node_pool[i][j] = 0;
            return (struct lpm_trie_node *)__lpm_node_pool[i];
        }
    }
    return NULL;
}

static void kfree(const void *ptr)
{
    int i;
    if (!ptr) return;
    for (i = 0; i < LPM_POOL_SIZE; i++) {
        if ((const void *)__lpm_node_pool[i] == ptr) {
            __lpm_pool_used[i] = 0;
            return;
        }
    }
}

static void *kmalloc_array(size_t n, size_t size, int flags)
{ (void)n; (void)size; (void)flags; return NULL; }

static void lpm_copy_data(u8 *dst, const u8 *src)
{
    int i;

    for (i = 0; i < LPM_BPF_DATA_SIZE; i++)
        dst[i] = src[i];
}

static void lpm_copy_value(u8 *dst, const void *value)
{
    const u8 *src = value;
    int i;

    for (i = 0; i < LPM_BPF_VALUE_SIZE; i++)
        dst[i] = src[i];
}

/* -----------------------------------------------------------------------
 * Core algorithm functions adapted for BPF verifier execution.
 * ----------------------------------------------------------------------- */

static inline int extract_bit(const u8 *data, size_t index)
{
    return !!(data[index / 8] & (1 << (7 - (index % 8))));
}

static size_t longest_prefix_match(const struct lpm_trie *trie,
                                   const struct lpm_trie_node *node,
                                   const struct bpf_lpm_trie_key_u8 *key)
{
    u32 limit = min(node->prefixlen, key->prefixlen);
    u32 prefixlen = 0, i = 0;

    BUILD_BUG_ON(offsetof(struct lpm_trie_node, data) % sizeof(u32));
    BUILD_BUG_ON(offsetof(struct bpf_lpm_trie_key_u8, data) % sizeof(u32));

    while (trie->data_size >= i + 4) {
        u32 diff = be32_to_cpu(*(__be32 *)&node->data[i] ^
                               *(__be32 *)&key->data[i]);

        prefixlen += 32 - fls(diff);
        if (prefixlen >= limit)
            return limit;
        if (diff)
            return prefixlen;
        i += 4;
    }

    if (trie->data_size >= i + 2) {
        u16 diff = be16_to_cpu(*(__be16 *)&node->data[i] ^
                               *(__be16 *)&key->data[i]);

        prefixlen += 16 - fls(diff);
        if (prefixlen >= limit)
            return limit;
        if (diff)
            return prefixlen;
        i += 2;
    }

    if (trie->data_size >= i + 1) {
        prefixlen += 8 - fls(node->data[i] ^ key->data[i]);

        if (prefixlen >= limit)
            return limit;
    }

    return prefixlen;
}

/* Called from syscall or from eBPF program */
static void *trie_lookup_elem(struct bpf_map *map, void *_key)
{
    struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
    struct lpm_trie_node *node, *found = NULL;
    struct bpf_lpm_trie_key_u8 *key = _key;

    if (key->prefixlen > trie->max_prefixlen)
        return NULL;

    for (node = rcu_dereference_check(trie->root, rcu_read_lock_bh_held());
         node;) {
        unsigned int next_bit;
        size_t matchlen;

        matchlen = longest_prefix_match(trie, node, key);
        if (matchlen == trie->max_prefixlen) {
            found = node;
            break;
        }

        if (matchlen < node->prefixlen)
            break;

        if (!(node->flags & LPM_TREE_NODE_FLAG_IM))
            found = node;

        next_bit = extract_bit(key->data, node->prefixlen);
        node = rcu_dereference_check(node->child[next_bit],
                                     rcu_read_lock_bh_held());
    }

    if (!found)
        return NULL;

    return found->data + trie->data_size;
}

static struct lpm_trie_node *lpm_trie_node_alloc(struct lpm_trie *trie,
                                                 const void *value)
{
    struct lpm_trie_node *node;

    node = bpf_map_kmalloc_node(&trie->map,
                                sizeof(struct lpm_trie_node) +
                                trie->data_size + trie->map.value_size,
                                GFP_NOWAIT | __GFP_NOWARN,
                                trie->map.numa_node);
    if (!node)
        return NULL;

    node->flags = 0;
    if (value)
        lpm_copy_value(node->data + LPM_BPF_DATA_SIZE, value);

    return node;
}

static int trie_check_add_elem(struct lpm_trie *trie, u64 flags)
{
    if (flags == BPF_EXIST)
        return -ENOENT;
    if (trie->n_entries == trie->map.max_entries)
        return -ENOSPC;
    trie->n_entries++;
    return 0;
}

/* Called from syscall or from eBPF program */
static int trie_update_elem(struct bpf_map *map,
                            void *_key, void *value, u64 flags)
{
    struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
    struct lpm_trie_node *node, *im_node, *new_node;
    struct lpm_trie_node *free_node = NULL;
    struct lpm_trie_node __rcu **slot;
    struct bpf_lpm_trie_key_u8 *key = _key;
    unsigned long irq_flags;
    unsigned int next_bit;
    size_t matchlen = 0;
    int ret = 0;

    if (unlikely(flags > BPF_EXIST))
        return -EINVAL;

    if (key->prefixlen > trie->max_prefixlen)
        return -EINVAL;

    new_node = lpm_trie_node_alloc(trie, value);
    if (!new_node)
        return -ENOMEM;

    im_node = NULL;
    new_node->prefixlen = key->prefixlen;
    RCU_INIT_POINTER(new_node->child[0], NULL);
    RCU_INIT_POINTER(new_node->child[1], NULL);
    lpm_copy_data(new_node->data, key->data);

    spin_lock_irqsave(&trie->lock, irq_flags);

    slot = &trie->root;

    while ((node = rcu_dereference(*slot))) {
        matchlen = longest_prefix_match(trie, node, key);

        if (node->prefixlen != matchlen ||
            node->prefixlen == key->prefixlen)
            break;

        next_bit = extract_bit(key->data, node->prefixlen);
        slot = &node->child[next_bit];
    }

    if (!node) {
        ret = trie_check_add_elem(trie, flags);
        if (ret)
            goto out;

        rcu_assign_pointer(*slot, new_node);
        goto out;
    }

    if (node->prefixlen == matchlen) {
        if (!(node->flags & LPM_TREE_NODE_FLAG_IM)) {
            if (flags == BPF_NOEXIST) {
                ret = -EEXIST;
                goto out;
            }
        } else {
            ret = trie_check_add_elem(trie, flags);
            if (ret)
                goto out;
        }

        new_node->child[0] = node->child[0];
        new_node->child[1] = node->child[1];

        rcu_assign_pointer(*slot, new_node);
        free_node = node;
        goto out;
    }

    ret = trie_check_add_elem(trie, flags);
    if (ret)
        goto out;

    if (matchlen == key->prefixlen) {
        next_bit = extract_bit(node->data, matchlen);
        rcu_assign_pointer(new_node->child[next_bit], node);
        rcu_assign_pointer(*slot, new_node);
        goto out;
    }

    im_node = lpm_trie_node_alloc(trie, NULL);
    if (!im_node) {
        trie->n_entries--;
        ret = -ENOMEM;
        goto out;
    }

    im_node->prefixlen = matchlen;
    im_node->flags |= LPM_TREE_NODE_FLAG_IM;
    lpm_copy_data(im_node->data, node->data);

    if (extract_bit(key->data, matchlen)) {
        rcu_assign_pointer(im_node->child[0], node);
        rcu_assign_pointer(im_node->child[1], new_node);
    } else {
        rcu_assign_pointer(im_node->child[0], new_node);
        rcu_assign_pointer(im_node->child[1], node);
    }
    rcu_assign_pointer(*slot, im_node);

out:
    spin_unlock_irqrestore(&trie->lock, irq_flags);

    if (ret)
        kfree(new_node);
    kfree(free_node);
    return ret;
}

/* Called from syscall or from eBPF program */
static __attribute__((always_inline))
long trie_delete_elem(struct bpf_map *map, void *_key)
{
    struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
    struct lpm_trie_node *free_node = NULL, *free_parent = NULL;
    struct bpf_lpm_trie_key_u8 *key = _key;
    struct lpm_trie_node __rcu **trim, **trim2;
    struct lpm_trie_node *node, *parent;
    unsigned long irq_flags;
    unsigned int next_bit;
    size_t matchlen = 0;
    int ret = 0;

    if (key->prefixlen > trie->max_prefixlen)
        return -EINVAL;

    spin_lock_irqsave(&trie->lock, irq_flags);

    trim = &trie->root;
    trim2 = trim;
    parent = NULL;
    while ((node = rcu_dereference(*trim))) {
        matchlen = longest_prefix_match(trie, node, key);

        if (node->prefixlen != matchlen ||
            node->prefixlen == key->prefixlen)
            break;

        parent = node;
        trim2 = trim;
        next_bit = extract_bit(key->data, node->prefixlen);
        trim = &node->child[next_bit];
    }

    if (!node || node->prefixlen != key->prefixlen ||
        node->prefixlen != matchlen ||
        (node->flags & LPM_TREE_NODE_FLAG_IM)) {
        ret = -ENOENT;
        goto out;
    }

    trie->n_entries--;

    if (rcu_access_pointer(node->child[0]) &&
        rcu_access_pointer(node->child[1])) {
        node->flags |= LPM_TREE_NODE_FLAG_IM;
        goto out;
    }

    if (parent && (parent->flags & LPM_TREE_NODE_FLAG_IM) &&
        !node->child[0] && !node->child[1]) {
        if (node == rcu_access_pointer(parent->child[0]))
            rcu_assign_pointer(*trim2, rcu_access_pointer(parent->child[1]));
        else
            rcu_assign_pointer(*trim2, rcu_access_pointer(parent->child[0]));
        free_parent = parent;
        free_node = node;
        goto out;
    }

    if (node->child[0])
        rcu_assign_pointer(*trim, rcu_access_pointer(node->child[0]));
    else if (node->child[1])
        rcu_assign_pointer(*trim, rcu_access_pointer(node->child[1]));
    else
        RCU_INIT_POINTER(*trim, NULL);
    free_node = node;

out:
    spin_unlock_irqrestore(&trie->lock, irq_flags);

    kfree(free_parent);
    kfree(free_node);
    return ret;
}

/* -----------------------------------------------------------------------
 * Helper: initialize a trie for IPv4 (32-bit prefix, 8-byte value)
 * ----------------------------------------------------------------------- */
static void lpm_trie_init(struct lpm_trie *trie, u32 max_entries)
{
    int i;
    /* Zero out the pool */
    for (i = 0; i < LPM_POOL_SIZE; i++) __lpm_pool_used[i] = 0;

    trie->map.key_size    = sizeof(struct bpf_lpm_trie_key_u8) + 4; /* IPv4 */
    trie->map.value_size  = LPM_BPF_VALUE_SIZE;
    trie->map.max_entries = max_entries;
    trie->map.map_flags   = 0;
    trie->map.numa_node   = NUMA_NO_NODE;
    trie->root            = NULL;
    trie->n_entries       = 0;
    trie->data_size       = LPM_BPF_DATA_SIZE;  /* IPv4: 4 bytes */
    trie->max_prefixlen   = 32;
    spin_lock_init(&trie->lock);
}

/* -----------------------------------------------------------------------
 * Helper: build a lookup key for an IPv4 address + prefix length
 * ----------------------------------------------------------------------- */
struct lpm_key_ipv4 {
    struct bpf_lpm_trie_key_u8 hdr;
    u8 addr[4];
};

static void lpm_key_set(struct lpm_key_ipv4 *k, u32 prefixlen,
                        u8 a, u8 b, u8 c, u8 d)
{
    k->hdr.prefixlen = prefixlen;
    k->addr[0] = a;
    k->addr[1] = b;
    k->addr[2] = c;
    k->addr[3] = d;
}
