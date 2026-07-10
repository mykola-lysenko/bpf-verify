/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local verifier surface for kernel/bpf/liveness.c. */
#ifndef _LINUX_BPF_VERIFIER_H
#define _LINUX_BPF_VERIFIER_H

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/types.h>

#define BPF_LOG_LEVEL2		2
#define TMP_STR_BUF_LEN		64
#define BPF_REG_SIZE		8
#define BPF_HALF_REG_SIZE	4
#define STACK_SLOT_SZ		4
#define STACK_SLOTS		(MAX_BPF_STACK / BPF_HALF_REG_SIZE)
#define MAX_CALL_FRAMES		3
#define MAX_STACK_ARG_SLOTS	(MAX_BPF_FUNC_ARGS - MAX_BPF_FUNC_REG_ARGS)

typedef u64 spis_t;

#define SPIS_ZERO		((spis_t)0)
#define SPIS_ALL		((spis_t)~0ULL)

static inline spis_t spis_or(spis_t a, spis_t b) { return a | b; }
static inline spis_t spis_and(spis_t a, spis_t b) { return a & b; }
static inline spis_t spis_not(spis_t a) { return ~a; }
static inline bool spis_equal(spis_t a, spis_t b) { return a == b; }
static inline bool spis_is_zero(spis_t a) { return a == 0; }
static inline bool spis_test_bit(spis_t a, u32 bit) { return a & BIT_ULL(bit); }

static inline void spis_or_range(spis_t *mask, u32 lo, u32 hi)
{
	u32 i;

	for (i = lo; i <= hi && i < 64; i++)
		*mask |= BIT_ULL(i);
}

struct arg_track;
struct bpf_liveness;

struct bpf_iarray {
	int cnt;
	u32 items[4];
};

struct bpf_subprog_info {
	u32 start;
	u32 postorder_start;
	const char *name;
	bool is_global;
};

struct bpf_insn_aux_data {
	struct bpf_iarray *jt;
	u32 scc;
	u16 live_regs_before;
	u16 const_reg_subprog_mask;
	s32 const_reg_vals[MAX_BPF_REG];
	u32 calls_callback:1;
};

struct bpf_verifier_log {
	u32 level;
	u32 end_pos;
};

struct bpf_func_state {
	u32 subprogno;
	int callsite;
};

struct bpf_verifier_state {
	struct bpf_func_state *frame[MAX_CALL_FRAMES];
	u32 curframe;
	u32 insn_idx;
};

struct bpf_call_summary {
	int num_params;
};

struct bpf_verifier_env {
	struct bpf_prog *prog;
	struct bpf_insn_aux_data *insn_aux_data;
	struct bpf_subprog_info subprog_info[BPF_MAX_SUBPROGS + 2];
	int subprog_topo_order[BPF_MAX_SUBPROGS + 2];
	int subprog_cnt;
	struct {
		int *insn_postorder;
		int cur_postorder;
	} cfg;
	struct bpf_verifier_log log;
	char tmp_str_buf[TMP_STR_BUF_LEN];
	struct bpf_liveness *liveness;
	struct bpf_iarray *succ;
	struct arg_track **callsite_at_stack;
};

#ifndef IS_ERR
#define IS_ERR(ptr)		((unsigned long)(void *)(ptr) > (unsigned long)-4096)
#endif
#ifndef PTR_ERR
#define PTR_ERR(ptr)		((long)(ptr))
#endif
#ifndef ERR_PTR
#define ERR_PTR(error)		((void *)(long)(error))
#endif
#ifndef IS_ERR_OR_NULL
#define IS_ERR_OR_NULL(ptr)	(!(ptr) || IS_ERR(ptr))
#endif

#define __diag_push()
#define __diag_pop()
#define __diag_ignore_all(option, comment)
#define inline inline

static inline bool check_add_overflow(s16 a, s16 b, s16 *out)
{
	s32 r = (s32)a + (s32)b;

	*out = (s16)r;
	return r != (s32)*out;
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

static inline bool bpf_pseudo_kfunc_call(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == BPF_PSEUDO_KFUNC_CALL;
}

static inline bool bpf_calls_callback(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data && env->insn_aux_data[insn_idx].calls_callback;
}

static inline bool bpf_subprog_is_global(const struct bpf_verifier_env *env, int subprog)
{
	return env->subprog_info[subprog].is_global;
}

static inline int bpf_find_subprog(struct bpf_verifier_env *env, int off)
{
	int i;

	for (i = 1; i <= env->subprog_cnt; i++)
		if (off < env->subprog_info[i].start)
			return i - 1;
	return 0;
}

static inline bool bpf_get_call_summary(struct bpf_verifier_env *env,
					struct bpf_insn *call,
					struct bpf_call_summary *cs)
{
	(void)env;
	(void)call;
	cs->num_params = MAX_BPF_FUNC_REG_ARGS;
	return true;
}

static inline s64 bpf_helper_stack_access_bytes(struct bpf_verifier_env *env,
						struct bpf_insn *insn,
						int arg_idx, int insn_idx)
{
	(void)env;
	(void)insn;
	(void)arg_idx;
	(void)insn_idx;
	return 0;
}

static inline s64 bpf_kfunc_stack_access_bytes(struct bpf_verifier_env *env,
					       struct bpf_insn *insn,
					       int arg_idx, int insn_idx)
{
	(void)env;
	(void)insn;
	(void)arg_idx;
	(void)insn_idx;
	return 0;
}

static inline void bpf_verbose_insn(struct bpf_verifier_env *env,
				    struct bpf_insn *insn)
{
	(void)env;
	(void)insn;
}

static inline void bpf_vlog_reset(struct bpf_verifier_log *log, u32 pos)
{
	log->end_pos = pos;
}

static inline int bpf_vlog_alignment(u64 pos)
{
	(void)pos;
	return 0;
}

#define bpf_verifier_log_write(env, fmt, ...) do { (void)(env); } while (0)
#define scnprintf(buf, size, fmt, ...)	(0)
#define snprintf(buf, size, fmt, ...)	(0)
#define need_resched()			(0)
#define cond_resched()			do { } while (0)

#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)

#endif /* _LINUX_BPF_VERIFIER_H */
