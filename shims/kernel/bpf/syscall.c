// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: kernel/bpf/syscall.c map/prog guard helpers.
 *
 * The real syscall translation unit pulls in fd tables, idr, tokens, map ops,
 * and program loading. Keep this shim scoped to small syscall-side predicates
 * and copied helper bodies that can be proved without those subsystems.
 */

#include "bpf_shim_common.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define BPF_KEEP_SCALAR(x) asm volatile("" : "+r"(x))

#ifndef ERANGE
#define ERANGE 34
#endif
#ifndef ENOTSUPP
#define ENOTSUPP 95
#endif

#define SYSCALL_TEST_NR_CPUS 4

#define BPF_F_LOCK	4
#define BPF_F_CPU	8
#define BPF_F_ALL_CPUS	16

#define BPF_F_NUMA_NODE	(1U << 2)
#define BPF_F_RDONLY	(1U << 3)
#define BPF_F_WRONLY	(1U << 4)

#define BPF_SPIN_LOCK	BIT(0)

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
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_XSKMAP,
	BPF_MAP_TYPE_SOCKHASH,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_CGROUP_STORAGE = BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE =
		BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_SK_STORAGE,
	BPF_MAP_TYPE_DEVMAP_HASH,
	BPF_MAP_TYPE_STRUCT_OPS,
	BPF_MAP_TYPE_RINGBUF,
	BPF_MAP_TYPE_INODE_STORAGE,
	BPF_MAP_TYPE_TASK_STORAGE,
	BPF_MAP_TYPE_BLOOM_FILTER,
	BPF_MAP_TYPE_USER_RINGBUF,
	BPF_MAP_TYPE_CGRP_STORAGE,
	BPF_MAP_TYPE_ARENA,
	BPF_MAP_TYPE_INSN_ARRAY,
	BPF_MAP_TYPE_RHASH,
	__MAX_BPF_MAP_TYPE
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
	BPF_PROG_TYPE_CGROUP_SYSCTL,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	BPF_PROG_TYPE_CGROUP_SOCKOPT,
	BPF_PROG_TYPE_TRACING,
	BPF_PROG_TYPE_STRUCT_OPS,
	BPF_PROG_TYPE_EXT,
	BPF_PROG_TYPE_LSM,
	BPF_PROG_TYPE_SK_LOOKUP,
	BPF_PROG_TYPE_SYSCALL,
	BPF_PROG_TYPE_NETFILTER,
	__MAX_BPF_PROG_TYPE
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
		u64 map_extra;
	};
};

struct btf_record {
	u32 fields;
};

struct bpf_map {
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	int numa_node;
	u64 map_extra;
	struct btf_record *record;
};

#define IS_FD_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY || \
			  (map)->map_type == BPF_MAP_TYPE_CGROUP_ARRAY || \
			  (map)->map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS)
#define IS_FD_PROG_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PROG_ARRAY)
#define IS_FD_HASH(map) ((map)->map_type == BPF_MAP_TYPE_HASH_OF_MAPS)
#define IS_FD_MAP(map) (IS_FD_ARRAY(map) || IS_FD_PROG_ARRAY(map) || \
			IS_FD_HASH(map))

static __always_inline unsigned int num_possible_cpus(void)
{
	return SYSCALL_TEST_NR_CPUS;
}

static __always_inline int bpf_map_attr_numa_node(const union bpf_attr *attr)
{
	return (attr->map_flags & BPF_F_NUMA_NODE) ?
	       (int)attr->numa_node : NUMA_NO_NODE;
}

static __always_inline bool btf_record_has_field(const struct btf_record *rec,
						 u32 field)
{
	return rec && (rec->fields & field);
}

static __always_inline u32 bpf_map_value_size(const struct bpf_map *map,
					      u64 flags)
{
	if (flags & (BPF_F_CPU | BPF_F_ALL_CPUS))
		return map->value_size;
	else if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
		 map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
		 map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
		 map->map_type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE)
		return round_up(map->value_size, 8) * num_possible_cpus();
	else if (IS_FD_MAP(map))
		return sizeof(u32);
	else
		return  map->value_size;
}

static __always_inline u32 bpf_map_flags_retain_permanent(u32 flags)
{
	/* Some map creation flags are not tied to the map object but
	 * rather to the map fd instead, so they have no meaning upon
	 * map object inspection since multiple file descriptors with
	 * different (access) properties can exist here. Thus, given
	 * this has zero meaning for the map itself, lets clear these
	 * from here.
	 */
	return flags & ~(BPF_F_RDONLY | BPF_F_WRONLY);
}

static __always_inline void bpf_map_init_from_attr(struct bpf_map *map,
						  union bpf_attr *attr)
{
	map->map_type = attr->map_type;
	map->key_size = attr->key_size;
	map->value_size = attr->value_size;
	map->max_entries = attr->max_entries;
	map->map_flags = bpf_map_flags_retain_permanent(attr->map_flags);
	map->numa_node = bpf_map_attr_numa_node(attr);
	map->map_extra = attr->map_extra;
}

static __always_inline bool bpf_map_supports_cpu_flags(enum bpf_map_type map_type)
{
	switch (map_type) {
	case BPF_MAP_TYPE_PERCPU_ARRAY:
	case BPF_MAP_TYPE_PERCPU_HASH:
	case BPF_MAP_TYPE_LRU_PERCPU_HASH:
	case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
		return true;
	default:
		return false;
	}
}

static __always_inline int bpf_map_check_op_flags(struct bpf_map *map, u64 flags,
						  u64 allowed_flags)
{
	u32 cpu;

	if ((u32)flags & ~allowed_flags)
		return -EINVAL;

	if ((flags & BPF_F_LOCK) &&
	    !btf_record_has_field(map->record, BPF_SPIN_LOCK))
		return -EINVAL;

	if (!(flags & BPF_F_CPU) && flags >> 32)
		return -EINVAL;

	if (flags & (BPF_F_CPU | BPF_F_ALL_CPUS)) {
		if (!bpf_map_supports_cpu_flags(map->map_type))
			return -EINVAL;
		if ((flags & BPF_F_CPU) && (flags & BPF_F_ALL_CPUS))
			return -EINVAL;

		cpu = flags >> 32;
		if ((flags & BPF_F_CPU) && cpu >= num_possible_cpus())
			return -ERANGE;
	}

	return 0;
}

static __always_inline bool is_net_admin_prog_type(enum bpf_prog_type prog_type)
{
	switch (prog_type) {
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
	case BPF_PROG_TYPE_XDP:
	case BPF_PROG_TYPE_LWT_IN:
	case BPF_PROG_TYPE_LWT_OUT:
	case BPF_PROG_TYPE_LWT_XMIT:
	case BPF_PROG_TYPE_LWT_SEG6LOCAL:
	case BPF_PROG_TYPE_SK_SKB:
	case BPF_PROG_TYPE_SK_MSG:
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_SOCK_OPS:
	case BPF_PROG_TYPE_EXT: /* extends any prog */
	case BPF_PROG_TYPE_NETFILTER:
		return true;
	case BPF_PROG_TYPE_CGROUP_SKB:
		/* always unpriv */
	case BPF_PROG_TYPE_SK_REUSEPORT:
		/* equivalent to SOCKET_FILTER. need CAP_BPF only */
	default:
		return false;
	}
}

static __always_inline bool is_perfmon_prog_type(enum bpf_prog_type prog_type)
{
	switch (prog_type) {
	case BPF_PROG_TYPE_KPROBE:
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
	case BPF_PROG_TYPE_TRACING:
	case BPF_PROG_TYPE_LSM:
	case BPF_PROG_TYPE_STRUCT_OPS: /* has access to struct sock */
	case BPF_PROG_TYPE_EXT: /* extends any prog */
		return true;
	default:
		return false;
	}
}

enum syscall_map_cap {
	SYSCALL_MAP_CAP_UNPRIV,
	SYSCALL_MAP_CAP_BPF,
	SYSCALL_MAP_CAP_NET_ADMIN,
	SYSCALL_MAP_CAP_UNSUPPORTED,
};

/* Extracted from map_create_alloc()'s map-type capability switch. */
static __always_inline enum syscall_map_cap
syscall_map_create_cap(enum bpf_map_type map_type)
{
	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
	case BPF_MAP_TYPE_PERCPU_ARRAY:
	case BPF_MAP_TYPE_PROG_ARRAY:
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
	case BPF_MAP_TYPE_CGROUP_ARRAY:
	case BPF_MAP_TYPE_ARRAY_OF_MAPS:
	case BPF_MAP_TYPE_HASH:
	case BPF_MAP_TYPE_RHASH:
	case BPF_MAP_TYPE_PERCPU_HASH:
	case BPF_MAP_TYPE_HASH_OF_MAPS:
	case BPF_MAP_TYPE_RINGBUF:
	case BPF_MAP_TYPE_USER_RINGBUF:
	case BPF_MAP_TYPE_CGROUP_STORAGE:
	case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
		return SYSCALL_MAP_CAP_UNPRIV;
	case BPF_MAP_TYPE_SK_STORAGE:
	case BPF_MAP_TYPE_INODE_STORAGE:
	case BPF_MAP_TYPE_TASK_STORAGE:
	case BPF_MAP_TYPE_CGRP_STORAGE:
	case BPF_MAP_TYPE_BLOOM_FILTER:
	case BPF_MAP_TYPE_LPM_TRIE:
	case BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:
	case BPF_MAP_TYPE_STACK_TRACE:
	case BPF_MAP_TYPE_QUEUE:
	case BPF_MAP_TYPE_STACK:
	case BPF_MAP_TYPE_LRU_HASH:
	case BPF_MAP_TYPE_LRU_PERCPU_HASH:
	case BPF_MAP_TYPE_STRUCT_OPS:
	case BPF_MAP_TYPE_CPUMAP:
	case BPF_MAP_TYPE_ARENA:
	case BPF_MAP_TYPE_INSN_ARRAY:
		return SYSCALL_MAP_CAP_BPF;
	case BPF_MAP_TYPE_SOCKMAP:
	case BPF_MAP_TYPE_SOCKHASH:
	case BPF_MAP_TYPE_DEVMAP:
	case BPF_MAP_TYPE_DEVMAP_HASH:
	case BPF_MAP_TYPE_XSKMAP:
		return SYSCALL_MAP_CAP_NET_ADMIN;
	default:
		return SYSCALL_MAP_CAP_UNSUPPORTED;
	}
}
