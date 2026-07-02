#include <linux/errno.h>
#define _LINUX_BPF_H 1
#define _LINUX_BTF_H
#define offsetof(type, member) __builtin_offsetof(type, member)
#define BTF_KIND_UNKN 0
#define BTF_KIND_INT 1
#define BTF_KIND_PTR 2
#define BTF_KIND_ARRAY 3
#define BTF_KIND_STRUCT 4
#define BTF_KIND_UNION 5
#define BTF_KIND_ENUM 6
#define BTF_KIND_FWD 7
#define BTF_KIND_TYPEDEF 8
#define BTF_KIND_VOLATILE 9
#define BTF_KIND_CONST 10
#define BTF_KIND_RESTRICT 11
#define BTF_KIND_FUNC 12
#define BTF_KIND_FUNC_PROTO 13
#define BTF_KIND_VAR 14
#define BTF_KIND_DATASEC 15
#define BTF_KIND_FLOAT 16
#define BTF_KIND_DECL_TAG 17
#define BTF_KIND_TYPE_TAG 18
#define BTF_KIND_ENUM64 19

enum btf_field_iter_kind {
    BTF_FIELD_ITER_IDS,
    BTF_FIELD_ITER_STRS,
};
struct btf_type {
    u32 name_off;
    u32 info;
    union {
        u32 size;
        u32 type;
    };
};
struct btf_array {
    u32 type;
    u32 index_type;
    u32 nelems;
};
struct btf_member {
    u32 name_off;
    u32 type;
    u32 offset;
};
struct btf_param {
    u32 name_off;
    u32 type;
};
struct btf_var_secinfo {
    u32 type;
    u32 offset;
    u32 size;
};
struct btf_enum {
    u32 name_off;
    s32 val;
};
struct btf_enum64 {
    u32 name_off;
    u32 val_lo32;
    u32 val_hi32;
};
struct btf_field_desc {
    u32 t_off_cnt;
    u32 t_offs[2];
    u32 m_sz;
    u32 m_off_cnt;
    u32 m_offs[2];
};
struct btf_field_iter {
    void *p;
    int m_idx;
    int off_idx;
    int vlen;
    struct btf_field_desc desc;
};
static inline u32 btf_kind(const struct btf_type *t)
{
    return (t->info >> 24) & 0x1f;
}
static inline u32 btf_vlen(const struct btf_type *t)
{
    return t->info & 0xffff;
}
#define btf_type_var_secinfo(t) ((void *)((struct btf_type *)(t) + 1))
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
