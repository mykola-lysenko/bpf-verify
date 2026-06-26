// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: kernel/bpf/helpers.c prototype and guard helpers.
 *
 * The real file contains timers, dynptrs, kfuncs, bprintf parsing, and many
 * subsystem callbacks. Keep this shim scoped to base helper prototype metadata
 * and small guard helpers that can be proved without those subsystems.
 */

#include "bpf_shim_common.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define BPF_KEEP_SCALAR(x) asm volatile("" : "+r"(x))

#ifndef EFAULT
#define EFAULT 14
#endif
#ifndef EBUSY
#define EBUSY 16
#endif

#define CAP_PERFMON 38
#define CAP_BPF 39
#define LOCKDOWN_BPF_READ_KERNEL 0
#define HELPERS_TEST_NR_CPUS 4

#define BPF_BASE_TYPE_BITS 8
#define BPF_BASE_TYPE_MASK ((1U << BPF_BASE_TYPE_BITS) - 1)
#define BPF_F_INDEX_MASK 0xffffffffULL

#ifndef round_up
#define round_up(x, y) ((((x) + (y) - 1) / (y)) * (y))
#endif

enum bpf_type_flag {
	PTR_MAYBE_NULL		= BIT(0 + BPF_BASE_TYPE_BITS),
	MEM_RDONLY		= BIT(1 + BPF_BASE_TYPE_BITS),
	MEM_UNINIT		= BIT(7 + BPF_BASE_TYPE_BITS),
	MEM_WRITE		= BIT(18 + BPF_BASE_TYPE_BITS),
	MEM_ALIGNED		= BIT(17 + BPF_BASE_TYPE_BITS),
	OBJ_RELEASE		= BIT(5 + BPF_BASE_TYPE_BITS),
};

enum bpf_arg_type {
	ARG_DONTCARE = 0,
	ARG_CONST_MAP_PTR,
	ARG_PTR_TO_MAP_KEY,
	ARG_PTR_TO_MAP_VALUE,
	ARG_PTR_TO_MEM,
	ARG_PTR_TO_CTX,
	ARG_ANYTHING,
	ARG_PTR_TO_SPIN_LOCK,
	ARG_CONST_SIZE,
	ARG_CONST_SIZE_OR_ZERO,
	ARG_PTR_TO_FIXED_SIZE_MEM,
	ARG_PTR_TO_CONST_STR,
	ARG_PTR_TO_UNINIT_MEM = MEM_UNINIT | MEM_WRITE | ARG_PTR_TO_MEM,
	ARG_PTR_TO_MEM_OR_NULL = PTR_MAYBE_NULL | ARG_PTR_TO_MEM,
	ARG_PTR_TO_PERCPU_BTF_ID,
	ARG_PTR_TO_BTF_ID,
	ARG_PTR_TO_BTF_ID_OR_NULL = PTR_MAYBE_NULL | ARG_PTR_TO_BTF_ID,
	ARG_PTR_TO_DYNPTR,
	ARG_PTR_TO_TIMER,
	ARG_PTR_TO_FUNC,
	ARG_CONST_ALLOC_SIZE_OR_ZERO,
	ARG_KPTR_XCHG_DEST,
};

enum bpf_return_type {
	RET_INTEGER,
	RET_VOID,
	RET_PTR_TO_MAP_VALUE_OR_NULL,
	RET_PTR_TO_MEM_OR_BTF_ID,
	RET_PTR_TO_BTF_ID_OR_NULL,
	RET_PTR_TO_DYNPTR_MEM_OR_NULL,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
};

enum bpf_func_id {
	BPF_FUNC_unspec = 0,
	BPF_FUNC_map_lookup_elem = 1,
	BPF_FUNC_map_update_elem = 2,
	BPF_FUNC_map_delete_elem = 3,
	BPF_FUNC_ktime_get_ns = 5,
	BPF_FUNC_trace_printk = 6,
	BPF_FUNC_get_prandom_u32 = 7,
	BPF_FUNC_get_smp_processor_id = 8,
	BPF_FUNC_tail_call = 12,
	BPF_FUNC_get_current_pid_tgid = 14,
	BPF_FUNC_get_current_uid_gid = 15,
	BPF_FUNC_get_current_comm = 16,
	BPF_FUNC_perf_event_read = 22,
	BPF_FUNC_get_current_task = 35,
	BPF_FUNC_get_numa_node_id = 42,
	BPF_FUNC_current_task_under_cgroup = 37,
	BPF_FUNC_map_push_elem = 87,
	BPF_FUNC_map_pop_elem = 88,
	BPF_FUNC_map_peek_elem = 89,
	BPF_FUNC_spin_lock = 93,
	BPF_FUNC_spin_unlock = 94,
	BPF_FUNC_strtol = 105,
	BPF_FUNC_strtoul = 106,
	BPF_FUNC_send_signal = 109,
	BPF_FUNC_probe_read_user = 112,
	BPF_FUNC_probe_read_kernel = 113,
	BPF_FUNC_probe_read_user_str = 114,
	BPF_FUNC_probe_read_kernel_str = 115,
	BPF_FUNC_send_signal_thread = 117,
	BPF_FUNC_jiffies64 = 118,
	BPF_FUNC_get_ns_current_pid_tgid = 120,
	BPF_FUNC_get_current_ancestor_cgroup_id = 123,
	BPF_FUNC_ktime_get_boot_ns = 125,
	BPF_FUNC_ringbuf_output = 130,
	BPF_FUNC_ringbuf_reserve = 131,
	BPF_FUNC_ringbuf_submit = 132,
	BPF_FUNC_ringbuf_discard = 133,
	BPF_FUNC_ringbuf_query = 134,
	BPF_FUNC_get_task_stack = 141,
	BPF_FUNC_copy_from_user = 148,
	BPF_FUNC_snprintf_btf = 149,
	BPF_FUNC_per_cpu_ptr = 153,
	BPF_FUNC_this_cpu_ptr = 154,
	BPF_FUNC_task_storage_get = 156,
	BPF_FUNC_task_storage_delete = 157,
	BPF_FUNC_get_current_task_btf = 158,
	BPF_FUNC_get_current_cgroup_id = 80,
	BPF_FUNC_for_each_map_elem = 164,
	BPF_FUNC_snprintf = 165,
	BPF_FUNC_timer_init = 169,
	BPF_FUNC_timer_set_callback = 170,
	BPF_FUNC_timer_start = 171,
	BPF_FUNC_timer_cancel = 172,
	BPF_FUNC_task_pt_regs = 175,
	BPF_FUNC_get_branch_snapshot = 176,
	BPF_FUNC_trace_vprintk = 177,
	BPF_FUNC_find_vma = 180,
	BPF_FUNC_loop = 181,
	BPF_FUNC_strncmp = 182,
	BPF_FUNC_copy_from_user_task = 191,
	BPF_FUNC_kptr_xchg = 194,
	BPF_FUNC_map_lookup_percpu_elem = 195,
	BPF_FUNC_dynptr_from_mem = 197,
	BPF_FUNC_ringbuf_reserve_dynptr = 198,
	BPF_FUNC_ringbuf_submit_dynptr = 199,
	BPF_FUNC_ringbuf_discard_dynptr = 200,
	BPF_FUNC_dynptr_read = 201,
	BPF_FUNC_dynptr_write = 202,
	BPF_FUNC_dynptr_data = 203,
	BPF_FUNC_ktime_get_tai_ns = 208,
	BPF_FUNC_user_ringbuf_drain = 209,
	BPF_FUNC_cgrp_storage_get = 210,
	BPF_FUNC_cgrp_storage_delete = 211,
};

struct bpf_token {
	u64 caps;
};

struct bpf_prog_aux {
	struct bpf_token *token;
};

struct bpf_prog {
	struct bpf_prog_aux *aux;
	bool sleepable;
};

struct bpf_map;
struct bpf_map_ops {
	void *(*map_lookup_elem)(struct bpf_map *map, void *key);
	long (*map_update_elem)(struct bpf_map *map, void *key, void *value,
				u64 flags);
	long (*map_delete_elem)(struct bpf_map *map, void *key);
	long (*map_push_elem)(struct bpf_map *map, void *value, u64 flags);
	long (*map_pop_elem)(struct bpf_map *map, void *value);
	long (*map_peek_elem)(struct bpf_map *map, void *value);
	void *(*map_lookup_percpu_elem)(struct bpf_map *map, void *key,
					u32 cpu);
};

struct bpf_map {
	const struct bpf_map_ops *ops;
	enum bpf_map_type map_type;
	u32 key_size;
};

struct bpf_array {
	struct bpf_map map;
	u32 elem_size;
	char *value;
};

struct task_struct {
	int dummy;
};

struct bpf_func_proto {
	void *func;
	bool gpl_only;
	bool pkt_access;
	bool might_sleep;
	bool allow_fastcall;
	enum bpf_return_type ret_type;
	enum bpf_arg_type arg1_type;
	enum bpf_arg_type arg2_type;
	enum bpf_arg_type arg3_type;
	enum bpf_arg_type arg4_type;
	enum bpf_arg_type arg5_type;
	u32 arg4_size;
	u32 *arg4_btf_id;
};

static __always_inline bool bpf_rcu_lock_held(void)
{
	return true;
}

static __always_inline bool bpf_token_capable(const struct bpf_token *token,
					      int cap)
{
	return token && (token->caps & (1ULL << cap));
}

static __always_inline int security_locked_down(int what)
{
	(void)what;
	return 0;
}

static __always_inline int bpf_event_output(struct bpf_map *map, u64 flags,
					    void *data, u64 size, void *x,
					    int y, void *z)
{
	(void)map;
	(void)flags;
	(void)data;
	(void)size;
	(void)x;
	(void)y;
	(void)z;
	return 0;
}

static __always_inline int access_process_vm(struct task_struct *tsk,
					     unsigned long addr, void *buf,
					     int len, int write)
{
	(void)tsk;
	(void)addr;
	(void)buf;
	(void)write;
	return len == 3 ? 1 : len;
}

static __always_inline void *memset(void *dst, int c, size_t n)
{
	unsigned char *d = dst;
	size_t i;

	for (i = 0; i < 32; i++) {
		if (i >= n)
			break;
		d[i] = (unsigned char)c;
	}
	return dst;
}

static __always_inline unsigned int nr_cpu_ids_value(void)
{
	return HELPERS_TEST_NR_CPUS;
}

#define nr_cpu_ids nr_cpu_ids_value()

static __always_inline void *per_cpu_ptr(const void *ptr, u32 cpu)
{
	(void)cpu;
	return (void *)ptr;
}

static __always_inline void *this_cpu_ptr(const void *ptr)
{
	return (void *)ptr;
}

static __always_inline u64 helpers_map_lookup_elem(struct bpf_map *map,
						   void *key)
{
	WARN_ON_ONCE(!bpf_rcu_lock_held());
	return (unsigned long)map->ops->map_lookup_elem(map, key);
}

static __always_inline u64 helpers_map_update_elem(struct bpf_map *map,
						   void *key, void *value,
						   u64 flags)
{
	WARN_ON_ONCE(!bpf_rcu_lock_held());
	return map->ops->map_update_elem(map, key, value, flags);
}

static __always_inline u64 helpers_map_delete_elem(struct bpf_map *map,
						   void *key)
{
	WARN_ON_ONCE(!bpf_rcu_lock_held());
	return map->ops->map_delete_elem(map, key);
}

static __always_inline u64 helpers_map_push_elem(struct bpf_map *map,
						 void *value, u64 flags)
{
	return map->ops->map_push_elem(map, value, flags);
}

static __always_inline u64 helpers_map_pop_elem(struct bpf_map *map, void *value)
{
	return map->ops->map_pop_elem(map, value);
}

static __always_inline u64 helpers_map_peek_elem(struct bpf_map *map, void *value)
{
	return map->ops->map_peek_elem(map, value);
}

static __always_inline u64 helpers_map_lookup_percpu_elem(struct bpf_map *map,
							  void *key, u32 cpu)
{
	WARN_ON_ONCE(!bpf_rcu_lock_held());
	return (unsigned long)map->ops->map_lookup_percpu_elem(map, key, cpu);
}

static __always_inline u64 bpf_event_output_data(void *ctx,
						 struct bpf_map *map,
						 u64 flags, void *data,
						 u64 size)
{
	(void)ctx;

	if (unlikely(flags & ~(BPF_F_INDEX_MASK)))
		return -EINVAL;

	return bpf_event_output(map, flags, data, size, NULL, 0, NULL);
}

static __always_inline u64 bpf_copy_from_user_task(void *dst, u32 size,
						   const void *user_ptr,
						   struct task_struct *tsk,
						   u64 flags)
{
	int ret;

	/* flags is not used yet */
	if (unlikely(flags))
		return -EINVAL;

	if (unlikely(!size))
		return 0;

	ret = access_process_vm(tsk, (unsigned long)user_ptr, dst, size, 0);
	if (ret == size)
		return 0;

	memset(dst, 0, size);
	/* Return -EFAULT for partial read */
	return ret < 0 ? ret : -EFAULT;
}

static __always_inline u64 bpf_per_cpu_ptr(const void *ptr, u32 cpu)
{
	if (cpu >= nr_cpu_ids)
		return (unsigned long)NULL;

	return (unsigned long)per_cpu_ptr(ptr, cpu);
}

static __always_inline u64 bpf_this_cpu_ptr(const void *percpu_ptr)
{
	return (unsigned long)this_cpu_ptr(percpu_ptr);
}

static __always_inline void *map_key_from_value(struct bpf_map *map,
						void *value, u32 *arr_idx)
{
	if (map->map_type == BPF_MAP_TYPE_ARRAY) {
		struct bpf_array *array = container_of(map, struct bpf_array, map);

		*arr_idx = ((char *)value - array->value) / array->elem_size;
		return arr_idx;
	}
	return (void *)value - round_up(map->key_size, 8);
}

const struct bpf_func_proto bpf_map_lookup_elem_proto = {
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

const struct bpf_func_proto bpf_map_update_elem_proto = {
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE,
	.arg4_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_map_delete_elem_proto = {
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

const struct bpf_func_proto bpf_map_push_elem_proto = {
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE,
	.arg3_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_map_pop_elem_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE | MEM_UNINIT | MEM_WRITE,
};

const struct bpf_func_proto bpf_map_peek_elem_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE | MEM_UNINIT | MEM_WRITE,
};

const struct bpf_func_proto bpf_map_lookup_percpu_elem_proto = {
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_get_prandom_u32_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

const struct bpf_func_proto bpf_get_raw_smp_processor_id_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

const struct bpf_func_proto bpf_get_numa_node_id_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

const struct bpf_func_proto bpf_ktime_get_ns_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

const struct bpf_func_proto bpf_ktime_get_boot_ns_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

const struct bpf_func_proto bpf_ktime_get_tai_ns_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

const struct bpf_func_proto bpf_get_current_pid_tgid_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

const struct bpf_func_proto bpf_get_current_uid_gid_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

const struct bpf_func_proto bpf_get_current_comm_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};

const struct bpf_func_proto bpf_spin_lock_proto = {
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_SPIN_LOCK,
};

const struct bpf_func_proto bpf_spin_unlock_proto = {
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_SPIN_LOCK,
};

const struct bpf_func_proto bpf_jiffies64_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

const struct bpf_func_proto bpf_get_current_cgroup_id_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

const struct bpf_func_proto bpf_get_current_ancestor_cgroup_id_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_strtol_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_FIXED_SIZE_MEM | MEM_UNINIT | MEM_WRITE | MEM_ALIGNED,
	.arg4_size	= sizeof(s64),
};

const struct bpf_func_proto bpf_strtoul_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_FIXED_SIZE_MEM | MEM_UNINIT | MEM_WRITE | MEM_ALIGNED,
	.arg4_size	= sizeof(u64),
};

static const struct bpf_func_proto bpf_strncmp_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_PTR_TO_CONST_STR,
};

const struct bpf_func_proto bpf_get_ns_current_pid_tgid_proto = {
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

const struct bpf_func_proto bpf_event_output_data_proto = {
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

const struct bpf_func_proto bpf_copy_from_user_proto = {
	.gpl_only	= false,
	.might_sleep	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

u32 btf_tracing_ids[1];

const struct bpf_func_proto bpf_copy_from_user_task_proto = {
	.gpl_only	= true,
	.might_sleep	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_BTF_ID,
	.arg4_btf_id	= &btf_tracing_ids[0],
	.arg5_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_per_cpu_ptr_proto = {
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MEM_OR_BTF_ID | PTR_MAYBE_NULL | MEM_RDONLY,
	.arg1_type	= ARG_PTR_TO_PERCPU_BTF_ID,
	.arg2_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_this_cpu_ptr_proto = {
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MEM_OR_BTF_ID | MEM_RDONLY,
	.arg1_type	= ARG_PTR_TO_PERCPU_BTF_ID,
};

const struct bpf_func_proto bpf_snprintf_proto = {
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM_OR_NULL | MEM_WRITE,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_CONST_STR,
	.arg4_type	= ARG_PTR_TO_MEM | PTR_MAYBE_NULL | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

#define SIMPLE_INTEGER_PROTO(name) \
	const struct bpf_func_proto name = { .ret_type = RET_INTEGER }
#define SIMPLE_VOID_PROTO(name) \
	const struct bpf_func_proto name = { .ret_type = RET_VOID }

SIMPLE_VOID_PROTO(bpf_tail_call_proto);
SIMPLE_INTEGER_PROTO(bpf_ringbuf_output_proto);
SIMPLE_INTEGER_PROTO(bpf_ringbuf_reserve_proto);
SIMPLE_INTEGER_PROTO(bpf_ringbuf_submit_proto);
SIMPLE_INTEGER_PROTO(bpf_ringbuf_discard_proto);
SIMPLE_INTEGER_PROTO(bpf_ringbuf_query_proto);
SIMPLE_INTEGER_PROTO(bpf_timer_init_proto);
SIMPLE_INTEGER_PROTO(bpf_timer_set_callback_proto);
SIMPLE_INTEGER_PROTO(bpf_timer_start_proto);
SIMPLE_INTEGER_PROTO(bpf_timer_cancel_proto);
SIMPLE_INTEGER_PROTO(bpf_for_each_map_elem_proto);
SIMPLE_INTEGER_PROTO(bpf_loop_proto);
SIMPLE_INTEGER_PROTO(bpf_user_ringbuf_drain_proto);
SIMPLE_INTEGER_PROTO(bpf_ringbuf_reserve_dynptr_proto);
SIMPLE_INTEGER_PROTO(bpf_ringbuf_submit_dynptr_proto);
SIMPLE_INTEGER_PROTO(bpf_ringbuf_discard_dynptr_proto);
SIMPLE_INTEGER_PROTO(bpf_dynptr_from_mem_proto);
SIMPLE_INTEGER_PROTO(bpf_dynptr_read_proto);
SIMPLE_INTEGER_PROTO(bpf_dynptr_write_proto);
SIMPLE_INTEGER_PROTO(bpf_dynptr_data_proto);
SIMPLE_INTEGER_PROTO(bpf_cgrp_storage_get_proto);
SIMPLE_INTEGER_PROTO(bpf_cgrp_storage_delete_proto);
SIMPLE_INTEGER_PROTO(bpf_current_task_under_cgroup_proto);
SIMPLE_INTEGER_PROTO(bpf_task_storage_get_proto);
SIMPLE_INTEGER_PROTO(bpf_task_storage_delete_proto);
SIMPLE_INTEGER_PROTO(bpf_get_current_task_proto);
SIMPLE_INTEGER_PROTO(bpf_get_current_task_btf_proto);
SIMPLE_INTEGER_PROTO(bpf_probe_read_user_proto);
SIMPLE_INTEGER_PROTO(bpf_probe_read_user_str_proto);
SIMPLE_INTEGER_PROTO(bpf_probe_read_kernel_proto);
SIMPLE_INTEGER_PROTO(bpf_probe_read_kernel_str_proto);
SIMPLE_INTEGER_PROTO(bpf_task_pt_regs_proto);
SIMPLE_INTEGER_PROTO(bpf_perf_event_read_proto);
SIMPLE_INTEGER_PROTO(bpf_send_signal_proto);
SIMPLE_INTEGER_PROTO(bpf_send_signal_thread_proto);
SIMPLE_INTEGER_PROTO(bpf_get_task_stack_sleepable_proto);
SIMPLE_INTEGER_PROTO(bpf_get_task_stack_proto);
SIMPLE_INTEGER_PROTO(bpf_get_branch_snapshot_proto);
SIMPLE_INTEGER_PROTO(bpf_snprintf_btf_proto);
SIMPLE_INTEGER_PROTO(bpf_find_vma_proto);

const struct bpf_func_proto bpf_kptr_xchg_proto = {
	.ret_type	= RET_PTR_TO_BTF_ID_OR_NULL,
	.arg1_type	= ARG_KPTR_XCHG_DEST,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL | OBJ_RELEASE,
};

static __always_inline const struct bpf_func_proto *bpf_get_trace_printk_proto(void)
{
	return &bpf_probe_read_user_proto;
}

static __always_inline const struct bpf_func_proto *bpf_get_trace_vprintk_proto(void)
{
	return &bpf_probe_read_user_str_proto;
}

static __always_inline const struct bpf_func_proto *
bpf_get_perf_event_read_value_proto(void)
{
	return &bpf_perf_event_read_proto;
}

static __always_inline const struct bpf_func_proto *
bpf_base_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_map_push_elem:
		return &bpf_map_push_elem_proto;
	case BPF_FUNC_map_pop_elem:
		return &bpf_map_pop_elem_proto;
	case BPF_FUNC_map_peek_elem:
		return &bpf_map_peek_elem_proto;
	case BPF_FUNC_map_lookup_percpu_elem:
		return &bpf_map_lookup_percpu_elem_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_raw_smp_processor_id_proto;
	case BPF_FUNC_get_numa_node_id:
		return &bpf_get_numa_node_id_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_ktime_get_boot_ns:
		return &bpf_ktime_get_boot_ns_proto;
	case BPF_FUNC_ktime_get_tai_ns:
		return &bpf_ktime_get_tai_ns_proto;
	case BPF_FUNC_ringbuf_output:
		return &bpf_ringbuf_output_proto;
	case BPF_FUNC_ringbuf_reserve:
		return &bpf_ringbuf_reserve_proto;
	case BPF_FUNC_ringbuf_submit:
		return &bpf_ringbuf_submit_proto;
	case BPF_FUNC_ringbuf_discard:
		return &bpf_ringbuf_discard_proto;
	case BPF_FUNC_ringbuf_query:
		return &bpf_ringbuf_query_proto;
	case BPF_FUNC_strncmp:
		return &bpf_strncmp_proto;
	case BPF_FUNC_strtol:
		return &bpf_strtol_proto;
	case BPF_FUNC_strtoul:
		return &bpf_strtoul_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_get_ns_current_pid_tgid:
		return &bpf_get_ns_current_pid_tgid_proto;
	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;
	default:
		break;
	}

	if (!bpf_token_capable(prog->aux->token, CAP_BPF))
		return NULL;

	switch (func_id) {
	case BPF_FUNC_spin_lock:
		return &bpf_spin_lock_proto;
	case BPF_FUNC_spin_unlock:
		return &bpf_spin_unlock_proto;
	case BPF_FUNC_jiffies64:
		return &bpf_jiffies64_proto;
	case BPF_FUNC_per_cpu_ptr:
		return &bpf_per_cpu_ptr_proto;
	case BPF_FUNC_this_cpu_ptr:
		return &bpf_this_cpu_ptr_proto;
	case BPF_FUNC_timer_init:
		return &bpf_timer_init_proto;
	case BPF_FUNC_timer_set_callback:
		return &bpf_timer_set_callback_proto;
	case BPF_FUNC_timer_start:
		return &bpf_timer_start_proto;
	case BPF_FUNC_timer_cancel:
		return &bpf_timer_cancel_proto;
	case BPF_FUNC_kptr_xchg:
		return &bpf_kptr_xchg_proto;
	case BPF_FUNC_for_each_map_elem:
		return &bpf_for_each_map_elem_proto;
	case BPF_FUNC_loop:
		return &bpf_loop_proto;
	case BPF_FUNC_user_ringbuf_drain:
		return &bpf_user_ringbuf_drain_proto;
	case BPF_FUNC_ringbuf_reserve_dynptr:
		return &bpf_ringbuf_reserve_dynptr_proto;
	case BPF_FUNC_ringbuf_submit_dynptr:
		return &bpf_ringbuf_submit_dynptr_proto;
	case BPF_FUNC_ringbuf_discard_dynptr:
		return &bpf_ringbuf_discard_dynptr_proto;
	case BPF_FUNC_dynptr_from_mem:
		return &bpf_dynptr_from_mem_proto;
	case BPF_FUNC_dynptr_read:
		return &bpf_dynptr_read_proto;
	case BPF_FUNC_dynptr_write:
		return &bpf_dynptr_write_proto;
	case BPF_FUNC_dynptr_data:
		return &bpf_dynptr_data_proto;
	case BPF_FUNC_cgrp_storage_get:
		return &bpf_cgrp_storage_get_proto;
	case BPF_FUNC_cgrp_storage_delete:
		return &bpf_cgrp_storage_delete_proto;
	case BPF_FUNC_get_current_cgroup_id:
		return &bpf_get_current_cgroup_id_proto;
	case BPF_FUNC_get_current_ancestor_cgroup_id:
		return &bpf_get_current_ancestor_cgroup_id_proto;
	case BPF_FUNC_current_task_under_cgroup:
		return &bpf_current_task_under_cgroup_proto;
	case BPF_FUNC_task_storage_get:
		return &bpf_task_storage_get_proto;
	case BPF_FUNC_task_storage_delete:
		return &bpf_task_storage_delete_proto;
	default:
		break;
	}

	if (!bpf_token_capable(prog->aux->token, CAP_PERFMON))
		return NULL;

	switch (func_id) {
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	case BPF_FUNC_get_current_task:
		return &bpf_get_current_task_proto;
	case BPF_FUNC_get_current_task_btf:
		return &bpf_get_current_task_btf_proto;
	case BPF_FUNC_get_current_comm:
		return &bpf_get_current_comm_proto;
	case BPF_FUNC_probe_read_user:
		return &bpf_probe_read_user_proto;
	case BPF_FUNC_probe_read_kernel:
		return security_locked_down(LOCKDOWN_BPF_READ_KERNEL) < 0 ?
		       NULL : &bpf_probe_read_kernel_proto;
	case BPF_FUNC_probe_read_user_str:
		return &bpf_probe_read_user_str_proto;
	case BPF_FUNC_probe_read_kernel_str:
		return security_locked_down(LOCKDOWN_BPF_READ_KERNEL) < 0 ?
		       NULL : &bpf_probe_read_kernel_str_proto;
	case BPF_FUNC_copy_from_user:
		return &bpf_copy_from_user_proto;
	case BPF_FUNC_copy_from_user_task:
		return &bpf_copy_from_user_task_proto;
	case BPF_FUNC_snprintf_btf:
		return &bpf_snprintf_btf_proto;
	case BPF_FUNC_snprintf:
		return &bpf_snprintf_proto;
	case BPF_FUNC_task_pt_regs:
		return &bpf_task_pt_regs_proto;
	case BPF_FUNC_trace_vprintk:
		return bpf_get_trace_vprintk_proto();
	case BPF_FUNC_perf_event_read:
		return &bpf_perf_event_read_proto;
	case BPF_FUNC_send_signal:
		return &bpf_send_signal_proto;
	case BPF_FUNC_send_signal_thread:
		return &bpf_send_signal_thread_proto;
	case BPF_FUNC_get_task_stack:
		return prog->sleepable ? &bpf_get_task_stack_sleepable_proto
				       : &bpf_get_task_stack_proto;
	case BPF_FUNC_get_branch_snapshot:
		return &bpf_get_branch_snapshot_proto;
	case BPF_FUNC_find_vma:
		return &bpf_find_vma_proto;
	default:
		return NULL;
	}
}
