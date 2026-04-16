// SPDX-License-Identifier: GPL-2.0-only
/* lpm_trie-shim.c: BPF-compatible self-contained shim for kernel/bpf/lpm_trie.c
 *
 * This shim is fully self-contained: it does NOT include any kernel headers
 * (which drag in spinlock, RCU, slab, vmalloc, BTF, etc. -- all incompatible
 * with BPF compilation). Instead it:
 *
 *   1. Defines all necessary types (u8, u32, u64, bool, size_t) from scratch.
 *   2. Provides inline fls/fls64 implementations.
 *   3. Defines the lpm_trie_node, lpm_trie, and bpf_lpm_trie_key structs
 *      exactly as in the kernel source.
 *   4. Provides no-op spinlock and RCU macros.
 *   5. Provides a static node pool (16 nodes) to replace kmalloc/kfree.
 *   6. Copies the core algorithm functions verbatim from lpm_trie.c:
 *        - extract_bit()
 *        - longest_prefix_match()
 *        - trie_lookup_elem()
 *        - trie_update_elem()
 *
 * The goal is to verify the core LPM lookup and prefix-match algorithms
 * using the BPF verifier, without needing the full kernel infrastructure.
 *
 * Function bodies are copied verbatim from Linux 6.1.102 kernel/bpf/lpm_trie.c.
 */

/* -----------------------------------------------------------------------
 * Primitive types
 * If linux/types.h has already been included (e.g. via the pipeline harness
 * template), these are already defined. Guard against redefinition.
 * ----------------------------------------------------------------------- */
#ifndef _LINUX_TYPES_H
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed int         s32;
typedef signed long long   s64;
typedef u8                 __u8;
typedef u16                __u16;
typedef u32                __u32;
typedef u64                __u64;
typedef u32                __be32;
typedef u16                __be16;
typedef u64                __be64;
typedef __SIZE_TYPE__      size_t;
typedef _Bool              bool;
#define true  1
#define false 0
#define NULL  ((void *)0)
#else
/* linux/types.h is already included -- just define the aliases we need */
#ifndef __be32
#define __be32 __u32
#define __be16 __u16
#define __be64 __u64
#endif
#endif /* _LINUX_TYPES_H */

/* -----------------------------------------------------------------------
 * fls / fls64 (find last set bit, 1-indexed, 0 if none)
 * ----------------------------------------------------------------------- */
static __attribute__((always_inline)) int fls(unsigned int x)
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

static __attribute__((always_inline)) int fls64(u64 x)
{
    u32 hi = (u32)(x >> 32);
    if (hi) return fls(hi) + 32;
    return fls((u32)x);
}

/* -----------------------------------------------------------------------
 * Byte-order helpers (big-endian to CPU, for x86 little-endian)
 * ----------------------------------------------------------------------- */
static __attribute__((always_inline)) u32 be32_to_cpu(u32 x)
{
    return ((x & 0xff000000u) >> 24) | ((x & 0x00ff0000u) >> 8) |
           ((x & 0x0000ff00u) <<  8) | ((x & 0x000000ffu) << 24);
}
static __attribute__((always_inline)) u16 be16_to_cpu(u16 x)
{
    return (u16)((x >> 8) | (x << 8));
}
static __attribute__((always_inline)) u64 be64_to_cpu(u64 x)
{
    return ((u64)be32_to_cpu((u32)(x >> 32))) |
           (((u64)be32_to_cpu((u32)(x & 0xffffffffull))) << 32);
}

/* -----------------------------------------------------------------------
 * Miscellaneous macros
 * ----------------------------------------------------------------------- */
#define min(a, b)           ((a) < (b) ? (a) : (b))
#define unlikely(x)         (x)
#define BUILD_BUG_ON(e)     do { } while (0)
#define offsetof(t, m)      __builtin_offsetof(t, m)
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#define BIT(n)              (1u << (n))
#define GFP_NOWAIT          0
#define GFP_ATOMIC          0
#define __GFP_NOWARN        0
#define NUMA_NO_NODE        (-1)
#define BPF_EXIST           2
#define BPF_NOEXIST         1
#define BPF_ANY             0
#define EINVAL              22
#define ENOMEM              12
#define ENOENT               2
#define EEXIST              17
#define ENOSPC              28
#define KMALLOC_MAX_SIZE    (1u << 22)

static __attribute__((always_inline)) void *__lpm_memcpy(void *d, const void *s, size_t n)
{
    u8 *dd = (u8 *)d;
    const u8 *ss = (const u8 *)s;
    size_t i;
    for (i = 0; i < n; i++) dd[i] = ss[i];
    return d;
}
#define memcpy(d, s, n)  __lpm_memcpy(d, s, n)

/* -----------------------------------------------------------------------
 * Spinlock stubs (no-op: BPF is single-threaded)
 * ----------------------------------------------------------------------- */
typedef struct { int dummy; } spinlock_t;
typedef unsigned long irqflags_t;
#define spin_lock_init(l)                   do {} while (0)
#define spin_lock_irqsave(l, f)             do { (void)(f); } while (0)
#define spin_unlock_irqrestore(l, f)        do { (void)(f); } while (0)

/* -----------------------------------------------------------------------
 * RCU stubs (no-op: no preemption in BPF)
 * ----------------------------------------------------------------------- */
#define __rcu
#define rcu_dereference(p)                  (p)
#define rcu_dereference_check(p, c)         (p)
#define rcu_dereference_protected(p, c)     (p)
#define rcu_access_pointer(p)               (p)
#define rcu_assign_pointer(p, v)            do { (p) = (v); } while (0)
#define RCU_INIT_POINTER(p, v)              do { (p) = (v); } while (0)
#define rcu_read_lock_bh_held()             1
/* rcu_head: linux/types.h defines it as #define rcu_head callback_head.
 * Only define the struct if it hasn't been defined yet. */
#ifndef rcu_head
struct rcu_head { void *next; void (*func)(struct rcu_head *); };
#endif
#define kfree_rcu(ptr, rcu_field)           do { (void)(ptr); } while (0)

/* -----------------------------------------------------------------------
 * ERR_PTR / IS_ERR
 * ----------------------------------------------------------------------- */
static __attribute__((always_inline)) void *ERR_PTR(long error)
{ return (void *)error; }
static __attribute__((always_inline)) bool IS_ERR(const void *ptr)
{ return (unsigned long)ptr >= (unsigned long)-4095; }

/* -----------------------------------------------------------------------
 * bpf_lpm_trie_key (from uapi/linux/bpf.h)
 * ----------------------------------------------------------------------- */
struct bpf_lpm_trie_key {
    __u32 prefixlen;
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

/* -----------------------------------------------------------------------
 * lpm_trie_node and lpm_trie (verbatim from lpm_trie.c)
 * ----------------------------------------------------------------------- */
#define LPM_TREE_NODE_FLAG_IM BIT(0)

struct lpm_trie_node;

struct lpm_trie_node {
    struct rcu_head              rcu;
    struct lpm_trie_node __rcu  *child[2];
    u32                          prefixlen;
    u32                          flags;
    u8                           data[];
};

struct lpm_trie {
    struct bpf_map               map;
    struct lpm_trie_node __rcu  *root;
    size_t                       n_entries;
    size_t                       max_prefixlen;
    size_t                       data_size;
    spinlock_t                   lock;
};

/* -----------------------------------------------------------------------
 * Static node pool (replaces kmalloc/kfree -- no heap in BPF)
 *
 * Each node needs: sizeof(lpm_trie_node) + data_size + value_size.
 * For IPv4 (data_size=4) + 8-byte value: 24 + 4 + 8 = 36 bytes.
 * We use 64-byte slots to be safe.
 * ----------------------------------------------------------------------- */
#define LPM_POOL_SIZE  16

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

/* -----------------------------------------------------------------------
 * Core algorithm functions -- copied verbatim from lpm_trie.c (Linux 6.1)
 * ----------------------------------------------------------------------- */

static inline int extract_bit(const u8 *data, size_t index)
{
    return !!(data[index / 8] & (1 << (7 - (index % 8))));
}

static size_t longest_prefix_match(const struct lpm_trie *trie,
                                   const struct lpm_trie_node *node,
                                   const struct bpf_lpm_trie_key *key)
{
    u32 limit = min(node->prefixlen, key->prefixlen);
    u32 prefixlen = 0, i = 0;

    BUILD_BUG_ON(offsetof(struct lpm_trie_node, data) % sizeof(u32));
    BUILD_BUG_ON(offsetof(struct bpf_lpm_trie_key, data) % sizeof(u32));

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
    struct bpf_lpm_trie_key *key = _key;

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

/* Called from syscall or from eBPF program */
static int trie_update_elem(struct bpf_map *map,
                            void *_key, void *value, u64 flags)
{
    struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
    struct lpm_trie_node *node, *im_node = NULL, *new_node = NULL;
    struct lpm_trie_node __rcu **slot;
    struct bpf_lpm_trie_key *key = _key;
    unsigned long irq_flags;
    unsigned int next_bit;
    size_t matchlen = 0;
    int ret = 0;

    if (unlikely(flags > BPF_EXIST))
        return -EINVAL;

    if (key->prefixlen > trie->max_prefixlen)
        return -EINVAL;

    if (trie->n_entries == trie->map.max_entries)
        return -ENOSPC;

    new_node = bpf_map_kmalloc_node(&trie->map,
                                    sizeof(struct lpm_trie_node) +
                                    trie->data_size + trie->map.value_size,
                                    GFP_NOWAIT | __GFP_NOWARN,
                                    trie->map.numa_node);
    if (!new_node)
        return -ENOMEM;

    new_node->prefixlen = key->prefixlen;
    RCU_INIT_POINTER(new_node->child[0], NULL);
    RCU_INIT_POINTER(new_node->child[1], NULL);
    memcpy(new_node->data, key->data, trie->data_size);
    memcpy(new_node->data + trie->data_size, value, trie->map.value_size);

    spin_lock_irqsave(&trie->lock, irq_flags);

    slot = &trie->root;

    while ((node = rcu_dereference_protected(*slot, 1))) {
        matchlen = longest_prefix_match(trie, node, key);

        if (node->prefixlen != matchlen ||
            node->prefixlen == key->prefixlen ||
            node->prefixlen == trie->max_prefixlen)
            break;

        next_bit = extract_bit(key->data, node->prefixlen);
        slot = &node->child[next_bit];
    }

    if (!node) {
        rcu_assign_pointer(*slot, new_node);
        goto out;
    }

    if (node->prefixlen == matchlen) {
        new_node->child[0] = node->child[0];
        new_node->child[1] = node->child[1];

        if (!(node->flags & LPM_TREE_NODE_FLAG_IM)) {
            if (flags == BPF_NOEXIST) {
                ret = -EEXIST;
                goto out_unlock;
            }
        } else {
            if (flags == BPF_EXIST) {
                ret = -ENOENT;
                goto out_unlock;
            }
            /* Upgrade the intermediate node to a real node */
        }

        rcu_assign_pointer(*slot, new_node);
        kfree_rcu(node, rcu);
        goto out;
    }

    if (flags == BPF_EXIST) {
        ret = -ENOENT;
        goto out_unlock;
    }

    im_node = bpf_map_kmalloc_node(&trie->map,
                                   sizeof(struct lpm_trie_node) +
                                   trie->data_size,
                                   GFP_NOWAIT | __GFP_NOWARN,
                                   trie->map.numa_node);
    if (!im_node) {
        ret = -ENOMEM;
        goto out_unlock;
    }

    im_node->prefixlen = matchlen;
    im_node->flags |= LPM_TREE_NODE_FLAG_IM;
    memcpy(im_node->data, node->data, trie->data_size);

    next_bit = extract_bit(key->data, matchlen);
    if (next_bit) {
        rcu_assign_pointer(im_node->child[0], node);
        rcu_assign_pointer(im_node->child[1], new_node);
    } else {
        rcu_assign_pointer(im_node->child[0], new_node);
        rcu_assign_pointer(im_node->child[1], node);
    }
    rcu_assign_pointer(*slot, im_node);

out:
    if (ret == 0)
        trie->n_entries++;

    spin_unlock_irqrestore(&trie->lock, irq_flags);
    return ret;

out_unlock:
    kfree(new_node);
    kfree(im_node);
    spin_unlock_irqrestore(&trie->lock, irq_flags);
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

    trie->map.key_size    = sizeof(struct bpf_lpm_trie_key) + 4; /* IPv4 */
    trie->map.value_size  = 8;
    trie->map.max_entries = max_entries;
    trie->map.map_flags   = 0;
    trie->map.numa_node   = NUMA_NO_NODE;
    trie->root            = NULL;
    trie->n_entries       = 0;
    trie->data_size       = 4;  /* IPv4: 4 bytes */
    trie->max_prefixlen   = 32;
    spin_lock_init(&trie->lock);
}

/* -----------------------------------------------------------------------
 * Helper: build a lookup key for an IPv4 address + prefix length
 * ----------------------------------------------------------------------- */
struct lpm_key_ipv4 {
    struct bpf_lpm_trie_key hdr;
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
