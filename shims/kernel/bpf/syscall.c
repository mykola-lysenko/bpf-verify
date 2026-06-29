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
#ifndef EPERM
#define EPERM 1
#endif

#ifndef WARN_ON
#define WARN_ON(c) (0)
#endif
#ifndef fallthrough
#define fallthrough
#endif

#define SYSCALL_TEST_NR_CPUS 4
#define BTF_MAX_TYPE 0x000fffff

#define BPF_F_LOCK	4
#define BPF_F_CPU	8
#define BPF_F_ALL_CPUS	16

#define BPF_F_NUMA_NODE	(1U << 2)
#define BPF_F_RDONLY	(1U << 3)
#define BPF_F_WRONLY	(1U << 4)
#define BPF_F_RDONLY_PROG	(1U << 7)
#define BPF_F_WRONLY_PROG	(1U << 8)

#define O_RDONLY	0
#define O_WRONLY	1
#define O_RDWR		2

#define CAP_NET_ADMIN	12
#define CAP_SYS_ADMIN	21

#define BPF_SPIN_LOCK	BIT(0)
#define BPF_OBJ_NAME_LEN 16U

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

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS,
	BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE,
	BPF_CGROUP_SOCK_OPS,
	BPF_SK_SKB_STREAM_PARSER,
	BPF_SK_SKB_STREAM_VERDICT,
	BPF_CGROUP_DEVICE,
	BPF_SK_MSG_VERDICT,
	BPF_CGROUP_INET4_BIND,
	BPF_CGROUP_INET6_BIND,
	BPF_CGROUP_INET4_CONNECT,
	BPF_CGROUP_INET6_CONNECT,
	BPF_CGROUP_INET4_POST_BIND,
	BPF_CGROUP_INET6_POST_BIND,
	BPF_CGROUP_UDP4_SENDMSG,
	BPF_CGROUP_UDP6_SENDMSG,
	BPF_LIRC_MODE2,
	BPF_FLOW_DISSECTOR,
	BPF_CGROUP_SYSCTL,
	BPF_CGROUP_UDP4_RECVMSG,
	BPF_CGROUP_UDP6_RECVMSG,
	BPF_CGROUP_GETSOCKOPT,
	BPF_CGROUP_SETSOCKOPT,
	BPF_TRACE_RAW_TP,
	BPF_TRACE_FENTRY,
	BPF_TRACE_FEXIT,
	BPF_MODIFY_RETURN,
	BPF_LSM_MAC,
	BPF_TRACE_ITER,
	BPF_CGROUP_INET4_GETPEERNAME,
	BPF_CGROUP_INET6_GETPEERNAME,
	BPF_CGROUP_INET4_GETSOCKNAME,
	BPF_CGROUP_INET6_GETSOCKNAME,
	BPF_XDP_DEVMAP,
	BPF_CGROUP_INET_SOCK_RELEASE,
	BPF_XDP_CPUMAP,
	BPF_SK_LOOKUP,
	BPF_XDP,
	BPF_SK_SKB_VERDICT,
	BPF_SK_REUSEPORT_SELECT,
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
	BPF_PERF_EVENT,
	BPF_TRACE_KPROBE_MULTI,
	BPF_LSM_CGROUP,
	BPF_STRUCT_OPS,
	BPF_NETFILTER,
	BPF_TCX_INGRESS,
	BPF_TCX_EGRESS,
	BPF_TRACE_UPROBE_MULTI,
	BPF_CGROUP_UNIX_CONNECT,
	BPF_CGROUP_UNIX_SENDMSG,
	BPF_CGROUP_UNIX_RECVMSG,
	BPF_CGROUP_UNIX_GETPEERNAME,
	BPF_CGROUP_UNIX_GETSOCKNAME,
	BPF_NETKIT_PRIMARY,
	BPF_NETKIT_PEER,
	BPF_TRACE_KPROBE_SESSION,
	BPF_TRACE_UPROBE_SESSION,
	BPF_TRACE_FSESSION,
	BPF_TRACE_FENTRY_MULTI,
	BPF_TRACE_FEXIT_MULTI,
	BPF_TRACE_FSESSION_MULTI,
	__MAX_BPF_ATTACH_TYPE
};

enum bpf_link_type {
	BPF_LINK_TYPE_UNSPEC = 0,
	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
	BPF_LINK_TYPE_TRACING = 2,
	BPF_LINK_TYPE_CGROUP = 3,
	BPF_LINK_TYPE_ITER = 4,
	BPF_LINK_TYPE_NETNS = 5,
	BPF_LINK_TYPE_XDP = 6,
	BPF_LINK_TYPE_PERF_EVENT = 7,
	BPF_LINK_TYPE_KPROBE_MULTI = 8,
	BPF_LINK_TYPE_STRUCT_OPS = 9,
	BPF_LINK_TYPE_NETFILTER = 10,
	BPF_LINK_TYPE_TCX = 11,
	BPF_LINK_TYPE_UPROBE_MULTI = 12,
	BPF_LINK_TYPE_NETKIT = 13,
	BPF_LINK_TYPE_SOCKMAP = 14,
	BPF_LINK_TYPE_TRACING_MULTI = 15,
	__MAX_BPF_LINK_TYPE,
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
		u32 prog_type;
		u32 expected_attach_type;
	};
};

struct btf_record {
	u32 fields;
};

struct btf {
	u32 id;
};

struct bpf_token {
	u32 cap_net_admin;
	u32 cap_sys_admin;
};

struct bpf_prog_aux {
	struct bpf_token *token;
};

struct bpf_prog {
	enum bpf_prog_type type;
	enum bpf_attach_type expected_attach_type;
	bool enforce_expected_attach_type;
	struct bpf_prog_aux *aux;
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

struct bpf_link;

struct bpf_link_ops {
	void (*dealloc)(struct bpf_link *link);
	void (*dealloc_deferred)(struct bpf_link *link);
	int (*update_prog)(struct bpf_link *link, struct bpf_prog *new_prog,
			   struct bpf_prog *old_prog);
	int (*update_map)(struct bpf_link *link, struct bpf_map *new_map,
			  struct bpf_map *old_map);
};

struct bpf_link {
	atomic64_t refcnt;
	enum bpf_link_type type;
	bool sleepable;
	u32 id;
	const struct bpf_link_ops *ops;
	struct bpf_prog *prog;
	enum bpf_attach_type attach_type;
};

struct bpf_tramp_link {
	struct bpf_link link;
	struct {
		struct bpf_link *link;
		u64 cookie;
	} node;
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

static __always_inline bool syscall_isalnum(char c)
{
	return (c >= '0' && c <= '9') ||
	       (c >= 'A' && c <= 'Z') ||
	       (c >= 'a' && c <= 'z');
}

/* dst and src must have at least "size" number of bytes.
 * Return strlen on success and < 0 on error.
 */
static __always_inline int bpf_obj_name_cpy(char *dst, const char *src,
					    unsigned int size)
{
	const char *end = src + size;
	const char *orig_src = src;
	unsigned int i;

	for (i = 0; i < size; i++)
		dst[i] = 0;

	/* Copy all isalnum(), '_' and '.' chars. */
	while (src < end && *src) {
		if (!syscall_isalnum(*src) &&
		    *src != '_' && *src != '.')
			return -EINVAL;
		*dst++ = *src++;
	}

	/* No '\0' found in "size" number of bytes */
	if (src == end)
		return -EINVAL;

	return src - orig_src;
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

static __always_inline int bpf_get_file_flag(int flags)
{
	if ((flags & BPF_F_RDONLY) && (flags & BPF_F_WRONLY))
		return -EINVAL;
	if (flags & BPF_F_RDONLY)
		return O_RDONLY;
	if (flags & BPF_F_WRONLY)
		return O_WRONLY;
	return O_RDWR;
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

static __always_inline void atomic64_set(atomic64_t *v, s64 i)
{
	v->counter = i;
}

static __always_inline bool bpf_token_capable(const struct bpf_token *token,
					      int cap)
{
	if (token && token->cap_sys_admin)
		return true;
	if (cap == CAP_NET_ADMIN)
		return token && token->cap_net_admin;
	return false;
}

/* Initially all BPF programs could be loaded w/o specifying
 * expected_attach_type. Later for some of them specifying expected_attach_type
 * at load time became required so that program could be validated properly.
 * Programs of types that are allowed to be loaded both w/ and w/o (for
 * backward compatibility) expected_attach_type, should have the default attach
 * type assigned to expected_attach_type for the latter case, so that it can be
 * validated later at attach time.
 *
 * bpf_prog_load_fixup_attach_type() sets expected_attach_type in @attr if
 * prog type requires it but has some attach types that have to be backward
 * compatible.
 */
static __always_inline void bpf_prog_load_fixup_attach_type(union bpf_attr *attr)
{
	switch (attr->prog_type) {
	case BPF_PROG_TYPE_CGROUP_SOCK:
		/* Unfortunately BPF_ATTACH_TYPE_UNSPEC enumeration doesn't
		 * exist so checking for non-zero is the way to go here.
		 */
		if (!attr->expected_attach_type)
			attr->expected_attach_type =
				BPF_CGROUP_INET_SOCK_CREATE;
		break;
	case BPF_PROG_TYPE_SK_REUSEPORT:
		if (!attr->expected_attach_type)
			attr->expected_attach_type =
				BPF_SK_REUSEPORT_SELECT;
		break;
	}
}

static __always_inline int
bpf_prog_load_check_attach(enum bpf_prog_type prog_type,
			   enum bpf_attach_type expected_attach_type,
			   struct btf *attach_btf, u32 btf_id,
			   struct bpf_prog *dst_prog,
			   bool multi_func)
{
	if (btf_id) {
		if (btf_id > BTF_MAX_TYPE)
			return -EINVAL;

		if (!attach_btf && !dst_prog)
			return -EINVAL;

		switch (prog_type) {
		case BPF_PROG_TYPE_TRACING:
		case BPF_PROG_TYPE_LSM:
		case BPF_PROG_TYPE_STRUCT_OPS:
		case BPF_PROG_TYPE_EXT:
			break;
		default:
			return -EINVAL;
		}
	}

	if (multi_func) {
		if (prog_type != BPF_PROG_TYPE_TRACING)
			return -EINVAL;
		if (!attach_btf || btf_id)
			return -EINVAL;
		return 0;
	}

	if (attach_btf && (!btf_id || dst_prog))
		return -EINVAL;

	if (dst_prog && prog_type != BPF_PROG_TYPE_TRACING &&
	    prog_type != BPF_PROG_TYPE_EXT)
		return -EINVAL;

	switch (prog_type) {
	case BPF_PROG_TYPE_CGROUP_SOCK:
		switch (expected_attach_type) {
		case BPF_CGROUP_INET_SOCK_CREATE:
		case BPF_CGROUP_INET_SOCK_RELEASE:
		case BPF_CGROUP_INET4_POST_BIND:
		case BPF_CGROUP_INET6_POST_BIND:
			return 0;
		default:
			return -EINVAL;
		}
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
		switch (expected_attach_type) {
		case BPF_CGROUP_INET4_BIND:
		case BPF_CGROUP_INET6_BIND:
		case BPF_CGROUP_INET4_CONNECT:
		case BPF_CGROUP_INET6_CONNECT:
		case BPF_CGROUP_UNIX_CONNECT:
		case BPF_CGROUP_INET4_GETPEERNAME:
		case BPF_CGROUP_INET6_GETPEERNAME:
		case BPF_CGROUP_UNIX_GETPEERNAME:
		case BPF_CGROUP_INET4_GETSOCKNAME:
		case BPF_CGROUP_INET6_GETSOCKNAME:
		case BPF_CGROUP_UNIX_GETSOCKNAME:
		case BPF_CGROUP_UDP4_SENDMSG:
		case BPF_CGROUP_UDP6_SENDMSG:
		case BPF_CGROUP_UNIX_SENDMSG:
		case BPF_CGROUP_UDP4_RECVMSG:
		case BPF_CGROUP_UDP6_RECVMSG:
		case BPF_CGROUP_UNIX_RECVMSG:
			return 0;
		default:
			return -EINVAL;
		}
	case BPF_PROG_TYPE_CGROUP_SKB:
		switch (expected_attach_type) {
		case BPF_CGROUP_INET_INGRESS:
		case BPF_CGROUP_INET_EGRESS:
			return 0;
		default:
			return -EINVAL;
		}
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		switch (expected_attach_type) {
		case BPF_CGROUP_SETSOCKOPT:
		case BPF_CGROUP_GETSOCKOPT:
			return 0;
		default:
			return -EINVAL;
		}
	case BPF_PROG_TYPE_SK_LOOKUP:
		if (expected_attach_type == BPF_SK_LOOKUP)
			return 0;
		return -EINVAL;
	case BPF_PROG_TYPE_SK_REUSEPORT:
		switch (expected_attach_type) {
		case BPF_SK_REUSEPORT_SELECT:
		case BPF_SK_REUSEPORT_SELECT_OR_MIGRATE:
			return 0;
		default:
			return -EINVAL;
		}
	case BPF_PROG_TYPE_NETFILTER:
		if (expected_attach_type == BPF_NETFILTER)
			return 0;
		return -EINVAL;
	case BPF_PROG_TYPE_SYSCALL:
	case BPF_PROG_TYPE_EXT:
		if (expected_attach_type)
			return -EINVAL;
		fallthrough;
	default:
		return 0;
	}
}

static __always_inline enum bpf_prog_type
attach_type_to_prog_type(enum bpf_attach_type attach_type)
{
	switch (attach_type) {
	case BPF_CGROUP_INET_INGRESS:
	case BPF_CGROUP_INET_EGRESS:
		return BPF_PROG_TYPE_CGROUP_SKB;
	case BPF_CGROUP_INET_SOCK_CREATE:
	case BPF_CGROUP_INET_SOCK_RELEASE:
	case BPF_CGROUP_INET4_POST_BIND:
	case BPF_CGROUP_INET6_POST_BIND:
		return BPF_PROG_TYPE_CGROUP_SOCK;
	case BPF_CGROUP_INET4_BIND:
	case BPF_CGROUP_INET6_BIND:
	case BPF_CGROUP_INET4_CONNECT:
	case BPF_CGROUP_INET6_CONNECT:
	case BPF_CGROUP_UNIX_CONNECT:
	case BPF_CGROUP_INET4_GETPEERNAME:
	case BPF_CGROUP_INET6_GETPEERNAME:
	case BPF_CGROUP_UNIX_GETPEERNAME:
	case BPF_CGROUP_INET4_GETSOCKNAME:
	case BPF_CGROUP_INET6_GETSOCKNAME:
	case BPF_CGROUP_UNIX_GETSOCKNAME:
	case BPF_CGROUP_UDP4_SENDMSG:
	case BPF_CGROUP_UDP6_SENDMSG:
	case BPF_CGROUP_UNIX_SENDMSG:
	case BPF_CGROUP_UDP4_RECVMSG:
	case BPF_CGROUP_UDP6_RECVMSG:
	case BPF_CGROUP_UNIX_RECVMSG:
		return BPF_PROG_TYPE_CGROUP_SOCK_ADDR;
	case BPF_CGROUP_SOCK_OPS:
		return BPF_PROG_TYPE_SOCK_OPS;
	case BPF_CGROUP_DEVICE:
		return BPF_PROG_TYPE_CGROUP_DEVICE;
	case BPF_SK_MSG_VERDICT:
		return BPF_PROG_TYPE_SK_MSG;
	case BPF_SK_SKB_STREAM_PARSER:
	case BPF_SK_SKB_STREAM_VERDICT:
	case BPF_SK_SKB_VERDICT:
		return BPF_PROG_TYPE_SK_SKB;
	case BPF_LIRC_MODE2:
		return BPF_PROG_TYPE_LIRC_MODE2;
	case BPF_FLOW_DISSECTOR:
		return BPF_PROG_TYPE_FLOW_DISSECTOR;
	case BPF_CGROUP_SYSCTL:
		return BPF_PROG_TYPE_CGROUP_SYSCTL;
	case BPF_CGROUP_GETSOCKOPT:
	case BPF_CGROUP_SETSOCKOPT:
		return BPF_PROG_TYPE_CGROUP_SOCKOPT;
	case BPF_TRACE_ITER:
	case BPF_TRACE_RAW_TP:
	case BPF_TRACE_FENTRY:
	case BPF_TRACE_FEXIT:
	case BPF_TRACE_FSESSION:
	case BPF_TRACE_FSESSION_MULTI:
	case BPF_TRACE_FENTRY_MULTI:
	case BPF_TRACE_FEXIT_MULTI:
	case BPF_MODIFY_RETURN:
		return BPF_PROG_TYPE_TRACING;
	case BPF_LSM_MAC:
		return BPF_PROG_TYPE_LSM;
	case BPF_SK_LOOKUP:
		return BPF_PROG_TYPE_SK_LOOKUP;
	case BPF_XDP:
		return BPF_PROG_TYPE_XDP;
	case BPF_LSM_CGROUP:
		return BPF_PROG_TYPE_LSM;
	case BPF_TCX_INGRESS:
	case BPF_TCX_EGRESS:
	case BPF_NETKIT_PRIMARY:
	case BPF_NETKIT_PEER:
		return BPF_PROG_TYPE_SCHED_CLS;
	default:
		return BPF_PROG_TYPE_UNSPEC;
	}
}

static __always_inline int
bpf_prog_attach_check_attach_type(const struct bpf_prog *prog,
				  enum bpf_attach_type attach_type)
{
	enum bpf_prog_type ptype;

	switch (prog->type) {
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_SK_LOOKUP:
		return attach_type == prog->expected_attach_type ? 0 : -EINVAL;
	case BPF_PROG_TYPE_CGROUP_SKB:
		if (!bpf_token_capable(prog->aux->token, CAP_NET_ADMIN))
			/* cg-skb progs can be loaded by unpriv user.
			 * check permissions at attach time.
			 */
			return -EPERM;

		ptype = attach_type_to_prog_type(attach_type);
		if (prog->type != ptype)
			return -EINVAL;

		return prog->enforce_expected_attach_type &&
			prog->expected_attach_type != attach_type ?
			-EINVAL : 0;
	case BPF_PROG_TYPE_EXT:
		return 0;
	case BPF_PROG_TYPE_NETFILTER:
		if (attach_type != BPF_NETFILTER)
			return -EINVAL;
		return 0;
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_TRACEPOINT:
		if (attach_type != BPF_PERF_EVENT)
			return -EINVAL;
		return 0;
	case BPF_PROG_TYPE_KPROBE:
		if (prog->expected_attach_type == BPF_TRACE_KPROBE_MULTI &&
		    attach_type != BPF_TRACE_KPROBE_MULTI)
			return -EINVAL;
		if (prog->expected_attach_type == BPF_TRACE_KPROBE_SESSION &&
		    attach_type != BPF_TRACE_KPROBE_SESSION)
			return -EINVAL;
		if (prog->expected_attach_type == BPF_TRACE_UPROBE_MULTI &&
		    attach_type != BPF_TRACE_UPROBE_MULTI)
			return -EINVAL;
		if (prog->expected_attach_type == BPF_TRACE_UPROBE_SESSION &&
		    attach_type != BPF_TRACE_UPROBE_SESSION)
			return -EINVAL;
		if (attach_type != BPF_PERF_EVENT &&
		    attach_type != BPF_TRACE_KPROBE_MULTI &&
		    attach_type != BPF_TRACE_KPROBE_SESSION &&
		    attach_type != BPF_TRACE_UPROBE_MULTI &&
		    attach_type != BPF_TRACE_UPROBE_SESSION)
			return -EINVAL;
		return 0;
	case BPF_PROG_TYPE_SCHED_CLS:
		if (attach_type != BPF_TCX_INGRESS &&
		    attach_type != BPF_TCX_EGRESS &&
		    attach_type != BPF_NETKIT_PRIMARY &&
		    attach_type != BPF_NETKIT_PEER)
			return -EINVAL;
		return 0;
	default:
		ptype = attach_type_to_prog_type(attach_type);
		if (ptype == BPF_PROG_TYPE_UNSPEC || ptype != prog->type)
			return -EINVAL;
		return 0;
	}
}

static __always_inline bool is_cgroup_prog_type(enum bpf_prog_type ptype,
						enum bpf_attach_type atype,
						bool check_atype)
{
	switch (ptype) {
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_SOCK_OPS:
		return true;
	case BPF_PROG_TYPE_LSM:
		return check_atype ? atype == BPF_LSM_CGROUP : true;
	default:
		return false;
	}
}

/* bpf_link_init_sleepable() allows to specify whether BPF link itself has
 * "sleepable" semantics, which normally would mean that BPF link's attach
 * hook can dereference link or link's underlying program for some time after
 * detachment due to RCU Tasks Trace-based lifetime protection scheme.
 * BPF program itself can be non-sleepable, yet, because it's transitively
 * reachable through BPF link, its freeing has to be delayed until after RCU
 * Tasks Trace GP.
 */
static __always_inline void
bpf_link_init_sleepable(struct bpf_link *link, enum bpf_link_type type,
			const struct bpf_link_ops *ops, struct bpf_prog *prog,
			enum bpf_attach_type attach_type, bool sleepable)
{
	WARN_ON(ops->dealloc && ops->dealloc_deferred);
	atomic64_set(&link->refcnt, 1);
	link->type = type;
	link->sleepable = sleepable;
	link->id = 0;
	link->ops = ops;
	link->prog = prog;
	link->attach_type = attach_type;
}

static __always_inline void
bpf_link_init(struct bpf_link *link, enum bpf_link_type type,
	      const struct bpf_link_ops *ops, struct bpf_prog *prog,
	      enum bpf_attach_type attach_type)
{
	bpf_link_init_sleepable(link, type, ops, prog, attach_type, false);
}

static __always_inline void
bpf_tramp_link_init(struct bpf_tramp_link *link, enum bpf_link_type type,
		    const struct bpf_link_ops *ops, struct bpf_prog *prog,
		    enum bpf_attach_type attach_type, u64 cookie)
{
	bpf_link_init(&link->link, type, ops, prog, attach_type);
	link->node.link = &link->link;
	link->node.cookie = cookie;
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
