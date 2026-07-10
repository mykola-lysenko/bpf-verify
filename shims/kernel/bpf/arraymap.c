// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: kernel/bpf/arraymap.c guard and direct-value helpers.
 *
 * The real file continues into percpu, mmap, fd-array, BTF, iterator, and
 * map-ops machinery. Keep this shim scoped to the helper bodies verified by
 * arraymap_prove.
 */

#include "bpf_shim_common.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define BPF_KEEP_SCALAR(x) asm volatile("" : "+r"(x))

#define INT_MAX 2147483647
#define U32_MAX ((u32)~0U)
#define E2BIG 7
#define ENOTSUPP 95

#define BPF_F_NUMA_NODE       (1U << 2)
#define BPF_F_RDONLY         (1U << 3)
#define BPF_F_WRONLY         (1U << 4)
#define BPF_F_RDONLY_PROG    (1U << 7)
#define BPF_F_WRONLY_PROG    (1U << 8)
#define BPF_F_MMAPABLE       (1U << 10)
#define BPF_F_PRESERVE_ELEMS (1U << 11)
#define BPF_F_INNER_MAP      (1U << 12)

#define BPF_F_ACCESS_MASK \
	(BPF_F_RDONLY | BPF_F_RDONLY_PROG | BPF_F_WRONLY | BPF_F_WRONLY_PROG)

#define ARRAY_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_MMAPABLE | BPF_F_ACCESS_MASK | \
	 BPF_F_PRESERVE_ELEMS | BPF_F_INNER_MAP)

#define PCPU_MIN_UNIT_SIZE (32U << 10)

#ifndef round_up
#define round_up(x, y) ((((x) + (y) - 1) / (y)) * (y))
#endif

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
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

struct btf_record {
	u32 id;
};

struct bpf_map_ops;

struct bpf_map {
	const struct bpf_map_ops *ops;
	u32 map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	int numa_node;
	struct btf_record *record;
};

struct bpf_array_aux;

struct bpf_array {
	struct bpf_map map;
	u32 elem_size;
	u32 index_mask;
	struct bpf_array_aux *aux;
	union {
		char value[0] __attribute__((aligned(8)));
		void *ptrs[0] __attribute__((aligned(8)));
		void *pptrs[0] __attribute__((aligned(8)));
	};
};

static __always_inline bool btf_record_equal(const struct btf_record *a,
					     const struct btf_record *b)
{
	return a == b;
}

static __always_inline bool bpf_map_meta_equal(const struct bpf_map *meta0,
					       const struct bpf_map *meta1)
{
	/* No need to compare ops because it is covered by map_type */
	return meta0->map_type == meta1->map_type &&
		meta0->key_size == meta1->key_size &&
		meta0->value_size == meta1->value_size &&
		meta0->map_flags == meta1->map_flags &&
		btf_record_equal(meta0->record, meta1->record);
}

static __always_inline bool bpf_map_flags_access_ok(u32 access_flags)
{
	return (access_flags & (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG)) !=
	       (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG);
}

static __always_inline int bpf_map_attr_numa_node(const union bpf_attr *attr)
{
	return (attr->map_flags & BPF_F_NUMA_NODE) ?
	       (int)attr->numa_node : NUMA_NO_NODE;
}

/* Called from syscall */
static __always_inline int array_map_alloc_check(union bpf_attr *attr)
{
	bool percpu = attr->map_type == BPF_MAP_TYPE_PERCPU_ARRAY;
	int numa_node = bpf_map_attr_numa_node(attr);

	/* check sanity of attributes */
	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    attr->value_size == 0 ||
	    attr->map_flags & ~ARRAY_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags) ||
	    (percpu && numa_node != NUMA_NO_NODE))
		return -EINVAL;

	if (attr->map_type != BPF_MAP_TYPE_ARRAY &&
	    attr->map_flags & (BPF_F_MMAPABLE | BPF_F_INNER_MAP))
		return -EINVAL;

	if (attr->map_type != BPF_MAP_TYPE_PERF_EVENT_ARRAY &&
	    attr->map_flags & BPF_F_PRESERVE_ELEMS)
		return -EINVAL;

	/* avoid overflow on round_up(map->value_size) */
	if (attr->value_size > INT_MAX)
		return -E2BIG;
	/* percpu map value size is bound by PCPU_MIN_UNIT_SIZE */
	if (percpu && round_up(attr->value_size, 8) > PCPU_MIN_UNIT_SIZE)
		return -E2BIG;

	return 0;
}

static __always_inline void *array_map_elem_ptr(struct bpf_array *array,
						u32 index)
{
	return array->value + (u64)array->elem_size * index;
}

/* Called from syscall or from eBPF program */
static __always_inline void *array_map_lookup_elem(struct bpf_map *map,
						   void *key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;

	if (unlikely(index >= array->map.max_entries))
		return NULL;

	return array->value + (u64)array->elem_size * (index & array->index_mask);
}

static __always_inline int array_map_direct_value_addr(const struct bpf_map *map,
						       u64 *imm, u32 off)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);

	if (map->max_entries != 1)
		return -ENOTSUPP;
	if (off >= map->value_size)
		return -EINVAL;

	*imm = (unsigned long)array->value;
	return 0;
}

static __always_inline int array_map_direct_value_meta(const struct bpf_map *map,
						       u64 imm, u32 *off)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u64 base = (unsigned long)array->value;
	u64 range = array->elem_size;

	if (map->max_entries != 1)
		return -ENOTSUPP;
	if (imm < base || imm >= base + range)
		return -ENOENT;

	*off = imm - base;
	return 0;
}

/* Called from syscall */
static __always_inline int bpf_array_get_next_key(struct bpf_map *map,
						  void *key, void *next_key)
{
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (index >= map->max_entries) {
		*next = 0;
		return 0;
	}

	if (index == map->max_entries - 1)
		return -ENOENT;

	*next = index + 1;
	return 0;
}

static __always_inline bool array_map_meta_equal(const struct bpf_map *meta0,
						 const struct bpf_map *meta1)
{
	if (!bpf_map_meta_equal(meta0, meta1))
		return false;
	return meta0->map_flags & BPF_F_INNER_MAP ? true :
	       meta0->max_entries == meta1->max_entries;
}
