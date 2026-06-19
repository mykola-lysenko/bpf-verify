/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local verifier surface for kernel/bpf/backtrack.c. */
#ifndef _LINUX_BPF_VERIFIER_H
#define _LINUX_BPF_VERIFIER_H

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/types.h>

#ifndef BIT
#define BIT(nr)			(1UL << (nr))
#endif
#ifndef BIT_ULL
#define BIT_ULL(nr)		(1ULL << (nr))
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)		(sizeof(arr) / sizeof((arr)[0]))
#endif

#define BPF_LOG_LEVEL2		0
#define TMP_STR_BUF_LEN		16
#define BPF_REG_SIZE		8
#define MAX_CALL_FRAMES		2
#define MAX_STACK_ARG_SLOTS	(MAX_BPF_FUNC_ARGS - MAX_BPF_FUNC_REG_ARGS)
#define BPF_MAIN_FUNC		(-1)
#define GFP_KERNEL_ACCOUNT	0
#define BPF_REGMASK_ARGS	((1 << BPF_REG_1) | (1 << BPF_REG_2) | \
				 (1 << BPF_REG_3) | (1 << BPF_REG_4) | \
				 (1 << BPF_REG_5))

enum bpf_stack_slot_type {
	STACK_INVALID,
	STACK_SPILL,
	STACK_MISC,
	STACK_ZERO,
};

struct bpf_reg_state {
	enum bpf_reg_type type;
	bool precise;
};

struct bpf_stack_state {
	struct bpf_reg_state spilled_ptr;
	u8 slot_type[BPF_REG_SIZE];
};

struct bpf_func_state {
	struct bpf_reg_state regs[MAX_BPF_REG];
	int subprogno;
	int callsite;
	struct bpf_stack_state *stack;
	int allocated_stack;
	u16 out_stack_arg_cnt;
	struct bpf_reg_state *stack_arg_regs;
};

enum {
	INSN_F_STACK_ACCESS = BIT(0),
	INSN_F_DST_REG_STACK = BIT(1),
	INSN_F_SRC_REG_STACK = BIT(2),
	INSN_F_STACK_ARG_ACCESS = BIT(3),
};

struct bpf_jmp_history_entry {
	u32 idx : 20;
	u32 frame : 4;
	u32 spi : 6;
	u32 : 2;
	u32 prev_idx : 20;
	u32 flags : 4;
	u32 : 8;
	u64 linked_regs;
};

struct bpf_verifier_state {
	struct bpf_func_state *frame[MAX_CALL_FRAMES];
	struct bpf_verifier_state *parent;
	u32 insn_idx;
	u32 curframe;
	u32 first_insn_idx;
	u32 last_insn_idx;
	struct bpf_jmp_history_entry *jmp_history;
	u32 jmp_history_cnt;
};

struct bpf_verifier_log {
	u32 level;
};

struct bpf_verifier_env;

struct backtrack_state {
	struct bpf_verifier_env *env;
	u32 frame;
	u32 reg_masks[MAX_CALL_FRAMES];
	u64 stack_masks[MAX_CALL_FRAMES];
	u8 stack_arg_masks[MAX_CALL_FRAMES];
};

struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;
	bool bpf_capable;
	struct bpf_verifier_state *cur_state;
	struct bpf_verifier_log log;
	struct backtrack_state bt;
	struct bpf_jmp_history_entry *cur_hist_ent;
	char tmp_str_buf[TMP_STR_BUF_LEN];
};

static noinline int bpf_push_jmp_history(struct bpf_verifier_env *env,
					 struct bpf_verifier_state *cur,
					 int insn_flags, int spi, int frame,
					 u64 linked_regs);
static __attribute__((always_inline)) int
get_prev_insn_idx(struct bpf_verifier_state *st, int i, u32 *history);
static __attribute__((always_inline)) struct bpf_jmp_history_entry *
get_jmp_hist_entry(struct bpf_verifier_state *st, u32 hist_end, int insn_idx);
static noinline int backtrack_insn(struct bpf_verifier_env *env, int idx,
				   int subseq_idx,
				   struct bpf_jmp_history_entry *hist,
				   struct backtrack_state *bt);
static __attribute__((always_inline)) void
bpf_mark_all_scalars_precise(struct bpf_verifier_env *env,
			     struct bpf_verifier_state *st);

static struct bpf_jmp_history_entry __bpf_backtrack_history[8];

static inline size_t size_mul(size_t a, size_t b)
{
	return a * b;
}

static inline size_t kmalloc_size_roundup(size_t size)
{
	return size;
}

static inline void *krealloc(void *ptr, size_t size, int flags)
{
	(void)ptr;
	(void)flags;
	if (size > sizeof(__bpf_backtrack_history))
		return (void *)0;
	return __bpf_backtrack_history;
}

static inline void *__bpf_backtrack_memset(void *dst, int c, __kernel_size_t n)
{
	unsigned char *d = dst;
	__kernel_size_t i;

	for (i = 0; i < n && i < 512; i++)
		d[i] = (unsigned char)c;
	return dst;
}

#define memset(dst, c, n)	__bpf_backtrack_memset((dst), (c), (n))
#define snprintf(buf, size, fmt, ...)	(0)

#define bpf_verifier_log_write(env, fmt, ...)	do { (void)(env); } while (0)
#define bpf_verbose_insn(env, insn)		do { (void)(env); (void)(insn); } while (0)
#define print_verifier_state(env, st, fr, verbose) \
	do { (void)(env); (void)(st); (void)(fr); (void)(verbose); } while (0)
#define verifier_bug(env, fmt, ...)		do { (void)(env); } while (0)
#define verifier_bug_if(cond, env, fmt, ...)	({ bool __c = (cond); (void)(env); __c; })

static inline bool bpf_is_spilled_reg(const struct bpf_stack_state *stack)
{
	return stack->slot_type[BPF_REG_SIZE - 1] == STACK_SPILL;
}

static inline bool bpf_is_spilled_scalar_reg(const struct bpf_stack_state *stack)
{
	return bpf_is_spilled_reg(stack) &&
	       stack->spilled_ptr.type == SCALAR_VALUE;
}

static inline void bpf_bt_set_frame_reg(struct backtrack_state *bt, u32 frame,
					u32 reg)
{
	bt->reg_masks[frame] |= 1U << reg;
}

static inline void bpf_bt_set_frame_slot(struct backtrack_state *bt, u32 frame,
					 u32 slot)
{
	bt->stack_masks[frame] |= 1ULL << slot;
}

static inline void bt_set_frame_stack_arg_slot(struct backtrack_state *bt,
					       u32 frame, u32 slot)
{
	bt->stack_arg_masks[frame] |= 1U << slot;
}

static inline bool bt_is_frame_reg_set(struct backtrack_state *bt, u32 frame,
				       u32 reg)
{
	return bt->reg_masks[frame] & (1U << reg);
}

static inline bool bt_is_frame_slot_set(struct backtrack_state *bt, u32 frame,
					u32 slot)
{
	return bt->stack_masks[frame] & (1ULL << slot);
}

static inline void bpf_bt_sync_linked_regs(struct backtrack_state *bt,
					   struct bpf_jmp_history_entry *hist)
{
	(void)bt;
	(void)hist;
}

static inline int bpf_find_subprog(struct bpf_verifier_env *env, int off)
{
	(void)env;
	(void)off;
	return 0;
}

static inline bool bpf_subprog_is_global(const struct bpf_verifier_env *env,
					 int subprog)
{
	(void)env;
	(void)subprog;
	return false;
}

static inline bool bpf_is_sync_callback_calling_insn(struct bpf_insn *insn)
{
	(void)insn;
	return false;
}

static inline bool bpf_calls_callback(struct bpf_verifier_env *env, int insn_idx)
{
	(void)env;
	(void)insn_idx;
	return false;
}

#endif /* _LINUX_BPF_VERIFIER_H */
