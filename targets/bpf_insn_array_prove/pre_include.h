#include <linux/errno.h>
#define _LINUX_BPF_H 1
#define _LINUX_BTF_IDS_H 1
#ifndef NUMA_NO_NODE
#define NUMA_NO_NODE (-1)
#endif
#define BPF_NOEXIST 1
#define BPF_F_RDONLY_PROG (1U << 7)
#define BPF_MAP_TYPE_INSN_ARRAY 1
#define BPF_LD 0x00
#define BPF_DW 0x18
#define BPF_IMM 0x00
#define BTF_ID_LIST_SINGLE(name, prefix, typename) static u32 name[1];
#define ERR_PTR(error) ((void *)(long)(error))
#define guard(name) (void)
#ifndef DECLARE_FLEX_ARRAY
#define DECLARE_FLEX_ARRAY(type, name) struct { } __empty_##name; type name[]
#endif
#ifndef container_of
#define container_of(ptr, type, member)     ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
#endif
struct mutex {
    int dummy;
};
struct btf {
    int dummy;
};
struct btf_type {
    u32 kind;
};
struct bpf_insn {
    u8 code;
    u8 dst_reg:4;
    u8 src_reg:4;
    s16 off;
    s32 imm;
};
struct bpf_insn_array_value {
    u32 orig_off;
    u32 xlated_off;
    u32 jitted_off;
    u32 __pad;
};
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
    u32 map_type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
    int numa_node;
    struct mutex freeze_mutex;
    bool frozen;
};
struct bpf_prog_aux {
    u32 used_map_cnt;
    struct bpf_map **used_maps;
    u32 subprog_start;
};
struct bpf_prog {
    u32 len;
    struct bpf_insn *insnsi;
    struct bpf_prog_aux *aux;
};
struct bpf_map_ops {
    int (*map_alloc_check)(union bpf_attr *attr);
    struct bpf_map *(*map_alloc)(union bpf_attr *attr);
    void (*map_free)(struct bpf_map *map);
    int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
    void *(*map_lookup_elem)(struct bpf_map *map, void *key);
    long (*map_update_elem)(struct bpf_map *map, void *key, void *value,
                            u64 flags);
    long (*map_delete_elem)(struct bpf_map *map, void *key);
    int (*map_check_btf)(struct bpf_map *map, const struct btf *btf,
                         const struct btf_type *key_type,
                         const struct btf_type *value_type);
    u64 (*map_mem_usage)(const struct bpf_map *map);
    int (*map_direct_value_addr)(const struct bpf_map *map, u64 *imm,
                                 u32 off);
    const u32 *map_btf_id;
};
static inline int atomic_xchg(atomic_t *v, int i)
{
    int old = v->counter;

    v->counter = i;
    return old;
}
static inline void atomic_set(atomic_t *v, int i)
{
    v->counter = i;
}
static inline bool btf_type_is_i32(const struct btf_type *type)
{
    return type && type->kind == 32;
}
static inline bool btf_type_is_i64(const struct btf_type *type)
{
    return type && type->kind == 64;
}
static inline void bpf_map_init_from_attr(struct bpf_map *map,
                                          union bpf_attr *attr)
{
    map->key_size = attr->key_size;
    map->value_size = attr->value_size;
    map->max_entries = attr->max_entries;
    map->map_flags = attr->map_flags;
    map->numa_node = NUMA_NO_NODE;
}
static __always_inline void copy_map_value(struct bpf_map *map, void *dst,
                                           const void *src)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    u32 i;

    (void)map;
    for (i = 0; i < sizeof(struct bpf_insn_array_value); i++)
        d[i] = s[i];
}
static int bpf_array_get_next_key(struct bpf_map *map, void *key,
                                  void *next_key)
{
    u32 index = key ? *(u32 *)key + 1 : 0;

    if (index >= map->max_entries)
        return -ENOENT;
    *(u32 *)next_key = index;
    return 0;
}
static void *bpf_map_area_alloc(u64 size, int numa_node);
static void bpf_map_area_free(void *base);
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
