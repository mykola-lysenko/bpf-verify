// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: kernel/bpf/bpf_struct_ops.c metadata and state helpers.
 *
 * The real file pulls in verifier, BTF, trampoline, link, module, and RCU
 * machinery. Keep this shim scoped to helper bodies that can be verified
 * without those subsystems.
 */

#include "bpf_shim_common.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define BPF_KEEP_SCALAR(x) asm volatile("" : "+r"(x))

#define E2BIG 7
#define EBUSY 16
#define ENOTSUPP 95
#define EOPNOTSUPP 95
#define EINPROGRESS 115

#define PAGE_SIZE 4096UL
#define MAX_TRAMP_IMAGE_PAGES 8

#define BPF_F_LINK              (1U << 13)
#define BPF_F_VTYPE_BTF_OBJ_FD  (1U << 15)

#define BPF_MAP_TYPE_STRUCT_OPS 26

#define ERR_PTR(error) ((void *)(long)(error))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-4095)

#define smp_load_acquire(p) (*(p))

typedef struct {
	int refs;
} refcount_t;

struct btf {
	u32 id;
};

struct btf_type {
	u32 size;
};

struct bpf_link;
struct bpf_ksym;
struct bpf_verifier_ops;
struct btf_func_model;

union bpf_attr {
	struct {
		u32 map_type;
		u32 key_size;
		u32 value_size;
		u32 max_entries;
		u32 map_flags;
		u32 btf_vmlinux_value_type_id;
		u32 value_type_btf_obj_fd;
	};
};

struct bpf_map {
	u32 map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	u32 id;
	u32 btf_vmlinux_value_type_id;
	atomic64_t refcnt;
	atomic64_t usercnt;
};

struct bpf_map_info {
	u32 btf_vmlinux_id;
};

struct bpf_struct_ops {
	const struct bpf_verifier_ops *verifier_ops;
	int (*reg)(void *kdata, struct bpf_link *link);
	void (*unreg)(void *kdata, struct bpf_link *link);
	int (*update)(void *kdata, void *old_kdata, struct bpf_link *link);
	int (*validate)(void *kdata);
	void *cfi_stubs;
	const char *name;
};

struct bpf_struct_ops_desc {
	struct bpf_struct_ops *st_ops;
	const struct btf_type *type;
	const struct btf_type *value_type;
	u32 type_id;
	u32 value_id;
};

enum bpf_struct_ops_state {
	BPF_STRUCT_OPS_STATE_INIT,
	BPF_STRUCT_OPS_STATE_INUSE,
	BPF_STRUCT_OPS_STATE_TOBEFREE,
	BPF_STRUCT_OPS_STATE_READY,
};

struct bpf_struct_ops_common_value {
	refcount_t refcnt;
	enum bpf_struct_ops_state state;
};

struct bpf_struct_ops_value {
	struct bpf_struct_ops_common_value common;
	char data[0] __attribute__((aligned(8)));
};

struct bpf_struct_ops_map {
	struct bpf_map map;
	const struct bpf_struct_ops_desc *st_ops_desc;
	struct bpf_link **links;
	struct bpf_ksym **ksyms;
	u32 funcs_cnt;
	u32 image_pages_cnt;
	void *image_pages[MAX_TRAMP_IMAGE_PAGES];
	struct btf *btf;
	struct bpf_struct_ops_value *uvalue;
	struct bpf_struct_ops_value kvalue;
};

static __always_inline void atomic64_set(atomic64_t *v, s64 i)
{
	v->counter = i;
}

static __always_inline u32 btf_obj_id(struct btf *btf)
{
	return btf->id;
}

static __always_inline struct bpf_map *
__bpf_map_inc_not_zero(struct bpf_map *map, bool uref)
{
	(void)uref;

	if (map->refcnt.counter <= 0)
		return ERR_PTR(-ENOENT);
	map->refcnt.counter++;
	return map;
}

static __always_inline void bpf_map_put(struct bpf_map *map)
{
	map->refcnt.counter--;
}

static __always_inline int
bpf_struct_ops_supported(const struct bpf_struct_ops *st_ops, u32 moff)
{
	void *func_ptr = *(void **)(st_ops->cfi_stubs + moff);

	return func_ptr ? 0 : -ENOTSUPP;
}

static __always_inline int bpf_struct_ops_map_get_next_key(struct bpf_map *map,
							   void *key,
							   void *next_key)
{
	if (key && *(u32 *)key == 0)
		return -ENOENT;

	*(u32 *)next_key = 0;
	return 0;
}

static __always_inline void *bpf_struct_ops_map_lookup_elem(struct bpf_map *map,
							    void *key)
{
	return ERR_PTR(-EINVAL);
}

static __always_inline int bpf_struct_ops_map_alloc_check(union bpf_attr *attr)
{
	if (attr->key_size != sizeof(unsigned int) || attr->max_entries != 1 ||
	    (attr->map_flags & ~(BPF_F_LINK | BPF_F_VTYPE_BTF_OBJ_FD)) ||
	    !attr->btf_vmlinux_value_type_id)
		return -EINVAL;
	return 0;
}

static __always_inline u64 bpf_struct_ops_map_mem_usage(const struct bpf_map *map)
{
	struct bpf_struct_ops_map *st_map = (struct bpf_struct_ops_map *)map;
	const struct bpf_struct_ops_desc *st_ops_desc = st_map->st_ops_desc;
	const struct btf_type *vt = st_ops_desc->value_type;
	u64 usage;

	usage = sizeof(*st_map) +
			vt->size - sizeof(struct bpf_struct_ops_value);
	usage += vt->size;
	usage += st_map->funcs_cnt * sizeof(struct bpf_link *);
	usage += st_map->funcs_cnt * sizeof(struct bpf_ksym *);
	usage += PAGE_SIZE;
	return usage;
}

static __always_inline bool bpf_struct_ops_get(const void *kdata)
{
	struct bpf_struct_ops_value *kvalue;
	struct bpf_struct_ops_map *st_map;
	struct bpf_map *map;

	kvalue = container_of(kdata, struct bpf_struct_ops_value, data);
	st_map = container_of(kvalue, struct bpf_struct_ops_map, kvalue);

	map = __bpf_map_inc_not_zero(&st_map->map, false);
	return !IS_ERR(map);
}

static __always_inline void bpf_struct_ops_put(const void *kdata)
{
	struct bpf_struct_ops_value *kvalue;
	struct bpf_struct_ops_map *st_map;

	kvalue = container_of(kdata, struct bpf_struct_ops_value, data);
	st_map = container_of(kvalue, struct bpf_struct_ops_map, kvalue);

	bpf_map_put(&st_map->map);
}

static __always_inline u32 bpf_struct_ops_id(const void *kdata)
{
	struct bpf_struct_ops_value *kvalue;
	struct bpf_struct_ops_map *st_map;

	kvalue = container_of(kdata, struct bpf_struct_ops_value, data);
	st_map = container_of(kvalue, struct bpf_struct_ops_map, kvalue);

	return st_map->map.id;
}

static __always_inline bool bpf_struct_ops_valid_to_reg(struct bpf_map *map)
{
	struct bpf_struct_ops_map *st_map = (struct bpf_struct_ops_map *)map;

	return map->map_type == BPF_MAP_TYPE_STRUCT_OPS &&
		map->map_flags & BPF_F_LINK &&
		/* Pair with smp_store_release() during map_update */
		smp_load_acquire(&st_map->kvalue.common.state) == BPF_STRUCT_OPS_STATE_READY;
}

static __always_inline void bpf_map_struct_ops_info_fill(struct bpf_map_info *info,
							 struct bpf_map *map)
{
	struct bpf_struct_ops_map *st_map = (struct bpf_struct_ops_map *)map;

	info->btf_vmlinux_id = btf_obj_id(st_map->btf);
}
