/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local verifier surface for kernel/bpf/cfg.c. */
#ifndef _LINUX_BPF_VERIFIER_H
#define _LINUX_BPF_VERIFIER_H

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>

#ifndef BIT
#define BIT(nr)			(1UL << (nr))
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)		(sizeof(arr) / sizeof((arr)[0]))
#endif
#ifndef IS_ERR
#define IS_ERR(ptr)		((unsigned long)(void *)(ptr) > (unsigned long)-4096)
#endif
#ifndef PTR_ERR
#define PTR_ERR(ptr)		((long)(ptr))
#endif
#ifndef ERR_PTR
#define ERR_PTR(error)		((void *)(long)(error))
#endif
#ifndef min
#define min(x, y)		((x) < (y) ? (x) : (y))
#endif
#ifndef U32_MAX
#define U32_MAX			((u32)~0U)
#endif

#define MAX_USED_MAPS		4
#define GFP_KERNEL_ACCOUNT	0

struct bpf_iarray {
	int cnt;
	u32 items[4];
};

struct bpf_insn_aux_data {
	struct bpf_iarray *jt;
	u32 jmp_point:1;
	u32 prune_point:1;
	u32 force_checkpoint:1;
	u32 calls_callback:1;
	u32 scc;
};

struct bpf_subprog_info {
	u32 start;
	u32 postorder_start;
	u32 exit_idx;
	bool changes_pkt_data;
	bool might_sleep;
	bool might_throw;
};

struct bpf_verifier_log {
	u32 level;
};

struct bpf_scc_info;

struct bpf_verifier_env {
	struct bpf_prog *prog;
	struct bpf_map *insn_array_maps[MAX_USED_MAPS];
	u32 insn_array_map_cnt;
	bool bpf_capable;
	int exception_callback_subprog;
	struct bpf_insn_aux_data *insn_aux_data;
	struct bpf_verifier_log log;
	struct bpf_subprog_info subprog_info[BPF_MAX_SUBPROGS + 2];
	struct {
		int *insn_state;
		int *insn_stack;
		int *insn_postorder;
		int cur_stack;
		int cur_postorder;
	} cfg;
	u32 subprog_cnt;
	struct bpf_scc_info **scc_info;
	u32 scc_cnt;
	struct bpf_iarray **succ;
};

static noinline
int push_insn(int t, int w, int e, struct bpf_verifier_env *env);
static noinline
int visit_func_call_insn(int t, struct bpf_insn *insns,
			 struct bpf_verifier_env *env, bool visit_callee);
static noinline
int visit_abnormal_return_insn(struct bpf_verifier_env *env, int t);
static noinline
struct bpf_iarray *__bpf_cfg_iarray_realloc(struct bpf_iarray *old,
					    size_t n_elem);
static noinline
int __bpf_cfg_copy_insn_array_uniq(struct bpf_map *map, u32 start,
				   u32 end, u32 *off);
static noinline
int __bpf_cfg_check_cfg(struct bpf_verifier_env *env);
static noinline
int __bpf_cfg_compute_postorder(struct bpf_verifier_env *env);
static noinline
int __bpf_cfg_compute_scc(struct bpf_verifier_env *env);

#define bpf_iarray_realloc		__bpf_cfg_iarray_realloc
#define bpf_copy_insn_array_uniq	__bpf_cfg_copy_insn_array_uniq
#define bpf_check_cfg			__bpf_cfg_check_cfg
#define bpf_compute_postorder		__bpf_cfg_compute_postorder
#define bpf_compute_scc			__bpf_cfg_compute_scc

static unsigned char __bpf_cfg_alloc_slots[24][256];

static inline void *__bpf_cfg_zalloc_slot(int slot, __kernel_size_t size)
{
	if (slot < 0 || slot >= ARRAY_SIZE(__bpf_cfg_alloc_slots))
		return (void *)0;
	if (size > sizeof(__bpf_cfg_alloc_slots[0]))
		return (void *)0;
	return __bpf_cfg_alloc_slots[slot];
}

#define kvzalloc_objs(type, count, flags) \
	((typeof(type) *)__bpf_cfg_zalloc_slot(__COUNTER__, sizeof(typeof(type)) * (count)))
#define kvcalloc(count, size, flags) \
	__bpf_cfg_zalloc_slot(__COUNTER__, (count) * (size))
#define kvrealloc(old, size, flags) \
	__bpf_cfg_zalloc_slot(__COUNTER__, (size))
#define kvfree(ptr)		do { (void)(ptr); } while (0)

static inline void *__bpf_cfg_memcpy(void *dst, const void *src,
				     __kernel_size_t n)
{
	unsigned char *d = dst;
	const unsigned char *s = src;
	__kernel_size_t i;

	for (i = 0; i < n && i < 64; i++)
		d[i] = s[i];
	return dst;
}

#define memcpy(dst, src, n)	__bpf_cfg_memcpy((dst), (src), (n))

#define bpf_verifier_log_write(env, fmt, ...)	do { (void)(env); } while (0)
#define verbose_linfo(env, off, fmt, ...)	do { (void)(env); (void)(off); } while (0)
#define bpf_log(log, fmt, ...)			do { (void)(log); } while (0)
#define verifier_bug(env, fmt, ...)		do { (void)(env); } while (0)

static inline void mark_prune_point(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].prune_point = true;
}

static inline void mark_force_checkpoint(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].force_checkpoint = true;
}

static inline void mark_calls_callback(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].calls_callback = true;
}

static inline bool bpf_calls_callback(struct bpf_verifier_env *env, int idx)
{
	return env->insn_aux_data[idx].calls_callback;
}

static inline void mark_jmp_point(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].jmp_point = true;
}

static inline bool bpf_helper_call(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) && insn->src_reg == 0;
}

static inline bool bpf_pseudo_call(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == BPF_PSEUDO_CALL;
}

static inline struct bpf_subprog_info *
bpf_find_containing_subprog(struct bpf_verifier_env *env, int off)
{
	u32 i;

	for (i = 1; i <= env->subprog_cnt; i++) {
		if (off < env->subprog_info[i].start)
			return &env->subprog_info[i - 1];
	}
	return &env->subprog_info[0];
}

static inline struct bpf_iarray *bpf_insn_successors(struct bpf_verifier_env *env,
						     u32 idx)
{
	return env->succ[idx];
}

static inline bool bpf_is_async_callback_calling_insn(struct bpf_insn *insn)
{
	(void)insn;
	return false;
}

static inline bool bpf_is_sync_callback_calling_insn(struct bpf_insn *insn)
{
	(void)insn;
	return false;
}

static inline bool bpf_helper_changes_pkt_data(enum bpf_func_id func_id)
{
	(void)func_id;
	return false;
}

static inline int bpf_get_helper_proto(struct bpf_verifier_env *env, int func_id,
				       const struct bpf_func_proto **fp)
{
	static struct bpf_func_proto proto;

	(void)env;
	(void)func_id;
	proto.might_sleep = false;
	*fp = &proto;
	return 0;
}

static inline int bpf_fetch_kfunc_arg_meta(struct bpf_verifier_env *env,
					   s32 func_id, s16 offset,
					   struct bpf_kfunc_call_arg_meta *meta)
{
	(void)env;
	(void)func_id;
	(void)offset;
	(void)meta;
	return -EINVAL;
}

static inline bool bpf_is_iter_next_kfunc(const struct bpf_kfunc_call_arg_meta *meta)
{
	(void)meta;
	return false;
}

static inline bool bpf_is_kfunc_sleepable(const struct bpf_kfunc_call_arg_meta *meta)
{
	(void)meta;
	return false;
}

static inline bool bpf_is_kfunc_pkt_changing(const struct bpf_kfunc_call_arg_meta *meta)
{
	(void)meta;
	return false;
}

static inline bool bpf_is_throw_kfunc(struct bpf_insn *insn)
{
	(void)insn;
	return false;
}

static inline bool bpf_is_may_goto_insn(struct bpf_insn *insn)
{
	(void)insn;
	return false;
}

#endif /* _LINUX_BPF_VERIFIER_H */
