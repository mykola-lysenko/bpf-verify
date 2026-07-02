#include <linux/errno.h>
#define _LINUX_BPF_H 1
#define _LINUX_BTF_IDS_H 1
#define __PERCPU_FREELIST_H__ 1
#define _ASM_X86_RQSPINLOCK_H 1
#define __ASM_GENERIC_RQSPINLOCK_H 1
#ifndef NUMA_NO_NODE
#define NUMA_NO_NODE (-1)
#endif
#ifndef KMALLOC_MAX_SIZE
#define KMALLOC_MAX_SIZE (1UL << 20)
#endif
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2
#define BPF_F_NUMA_NODE (1U << 2)
#define BPF_F_RDONLY (1U << 3)
#define BPF_F_WRONLY (1U << 4)
#define BPF_F_RDONLY_PROG (1U << 7)
#define BPF_F_WRONLY_PROG (1U << 8)
#define BPF_F_ACCESS_MASK     (BPF_F_RDONLY | BPF_F_WRONLY | BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG)
#define BTF_ID_LIST_SINGLE(name, prefix, typename) static u32 name[1];
#define ERR_PTR(error) ((void *)(long)(error))
typedef struct { u32 locked; } rqspinlock_t;
static inline void raw_res_spin_lock_init(rqspinlock_t *lock)
{ lock->locked = 0; }
static inline int raw_res_spin_lock_irqsave(rqspinlock_t *lock,
                                            unsigned long flags)
{ (void)lock; (void)flags; return 0; }
static inline void raw_res_spin_unlock_irqrestore(rqspinlock_t *lock,
                                                  unsigned long flags)
{ (void)lock; (void)flags; }
union bpf_attr {
    struct {
        u32 map_type;
        u32 key_size;
        u32 value_size;
        u32 max_entries;
        u32 map_flags;
        u32 inner_map_fd;
        u32 numa_node;
    };
};
struct bpf_map {
    const struct bpf_map_ops *ops;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
    int numa_node;
};
struct bpf_map_ops {
    bool (*map_meta_equal)(const struct bpf_map *meta0,
                           const struct bpf_map *meta1);
    int (*map_alloc_check)(union bpf_attr *attr);
    struct bpf_map *(*map_alloc)(union bpf_attr *attr);
    void (*map_free)(struct bpf_map *map);
    void *(*map_lookup_elem)(struct bpf_map *map, void *key);
    long (*map_update_elem)(struct bpf_map *map, void *key, void *value,
                            u64 flags);
    long (*map_delete_elem)(struct bpf_map *map, void *key);
    long (*map_push_elem)(struct bpf_map *map, void *value, u64 flags);
    long (*map_pop_elem)(struct bpf_map *map, void *value);
    long (*map_peek_elem)(struct bpf_map *map, void *value);
    int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
    u64 (*map_mem_usage)(const struct bpf_map *map);
    const u32 *map_btf_id;
};
static inline bool bpf_map_meta_equal(const struct bpf_map *meta0,
                                      const struct bpf_map *meta1)
{ (void)meta0; (void)meta1; return true; }
static inline bool bpf_map_flags_access_ok(u32 map_flags)
{ return (map_flags & ~BPF_F_ACCESS_MASK) == 0; }
static inline int bpf_map_attr_numa_node(const union bpf_attr *attr)
{
    return (attr->map_flags & BPF_F_NUMA_NODE) ?
           (int)attr->numa_node : NUMA_NO_NODE;
}
static inline void bpf_map_init_from_attr(struct bpf_map *map,
                                          union bpf_attr *attr)
{
    map->key_size = attr->key_size;
    map->value_size = attr->value_size;
    map->max_entries = attr->max_entries;
    map->map_flags = attr->map_flags;
    map->numa_node = bpf_map_attr_numa_node(attr);
}
static void *bpf_map_area_alloc(u64 size, int numa_node);
static void bpf_map_area_free(void *base);
static __always_inline void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    size_t i;

    for (i = 0; i < 32; i++) {
        if (i >= n)
            break;
        d[i] = s[i];
    }
    return dst;
}
static __always_inline void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    size_t i;

    for (i = 0; i < 32; i++) {
        if (i >= n)
            break;
        d[i] = (unsigned char)c;
    }
    return dst;
}
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
