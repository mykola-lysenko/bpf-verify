#include <linux/errno.h>
#define _LINUX_SLAB_H 1
#define _LINUX_BPF_H 1
#define _LINUX_BTF_H 1
#define GFP_USER 0
#define CLASS(type, name) int name =
#define ERR_PTR(error) ((void *)(long)(error))
#define ERR_CAST(ptr) ((void *)(ptr))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-4095)
#undef READ_ONCE
#undef WRITE_ONCE
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) do { (x) = (v); } while (0)
#ifndef container_of
#define container_of(ptr, type, member)     ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
#endif
struct file {
    int dummy;
};
struct btf {
    u32 refs;
};
struct btf_record {
    u32 id;
};
struct bpf_map;
struct bpf_map_ops {
    bool (*map_meta_equal)(const struct bpf_map *meta0,
                           const struct bpf_map *meta1);
};
struct bpf_map {
    const struct bpf_map_ops *ops;
    struct bpf_map *inner_map_meta;
    u32 map_type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
    u32 id;
    struct btf_record *record;
    struct btf *btf;
    bool bypass_spec_v1;
    bool free_after_mult_rcu_gp;
    bool free_after_rcu_gp;
    atomic64_t sleepable_refcnt;
    char *excl_prog_sha;
};
struct bpf_array {
    struct bpf_map map;
    u32 elem_size;
    u32 index_mask;
};
static bool __bpf_map_in_map_meta_equal_stub(const struct bpf_map *meta0,
                                             const struct bpf_map *meta1);
extern const struct bpf_map_ops array_map_ops;
extern const struct bpf_map_ops percpu_array_map_ops;
extern const struct bpf_map_ops __bpf_map_in_map_no_meta_ops;
static struct bpf_map *__bpf_map_get(int fd);
static void *__bpf_map_in_map_alloc(size_t size, unsigned int flags);
static void __bpf_map_in_map_free(void *ptr);
#define kzalloc(size, flags) __bpf_map_in_map_alloc((size), (flags))
#define kfree(ptr) __bpf_map_in_map_free(ptr)
static inline struct btf_record *btf_record_dup(struct btf_record *record)
{
    return record;
}
static inline bool btf_record_equal(const struct btf_record *a,
                                    const struct btf_record *b)
{
    return a == b;
}
static inline void bpf_map_free_record(struct bpf_map *map)
{
    (void)map;
}
static inline void btf_get(struct btf *btf)
{
    (void)btf;
}
static inline void btf_put(struct btf *btf)
{
    (void)btf;
}
static inline s64 atomic64_read(const atomic64_t *v)
{
    return v->counter;
}
static inline void bpf_map_inc(struct bpf_map *map)
{
    (void)map;
}
static inline void bpf_map_put(struct bpf_map *map);
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
