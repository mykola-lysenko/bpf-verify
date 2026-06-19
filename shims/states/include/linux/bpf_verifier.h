/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local verifier surface for kernel/bpf/states.c. */
#ifndef _LINUX_BPF_VERIFIER_H
#define _LINUX_BPF_VERIFIER_H

#include <linux/bpf.h>
#include <linux/cnum.h>
#include <linux/errno.h>
#include <linux/types.h>

#define BPF_COMPLEXITY_LIMIT_JMP_SEQ	8192
#define BPF_ID_MAP_SIZE			4
#define BPF_LOG_LEVEL2			2
#define BPF_REG_SIZE			8
#define MAX_CALL_FRAMES			1
#define TMP_STR_BUF_LEN			8

#define BPF_ADD_CONST64			(1U << 31)
#define BPF_ADD_CONST32			(1U << 30)
#define BPF_ADD_CONST			(BPF_ADD_CONST64 | BPF_ADD_CONST32)

#define LIST_HEAD_INIT(name)		{ &(name), &(name) }
#define LIST_HEAD(name)			struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *node, struct list_head *prev,
			      struct list_head *next)
{
	next->prev = node;
	node->next = next;
	node->prev = prev;
	prev->next = node;
}

static inline void list_add(struct list_head *node, struct list_head *head)
{
	__list_add(node, head, head->next);
}

static inline void list_del(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
	entry->next = entry;
	entry->prev = entry;
}

#define list_for_each_safe(pos, n, head)				\
	for (pos = (head)->next, n = pos->next; pos != (head);	\
	     pos = n, n = pos->next)

struct tnum {
	u64 value;
	u64 mask;
};

static inline bool tnum_in(struct tnum old, struct tnum cur)
{
	if (cur.mask & ~old.mask)
		return false;
	cur.value &= ~old.mask;
	return old.value == cur.value;
}

enum bpf_dynptr_type {
	BPF_DYNPTR_TYPE_LOCAL = 0,
};

enum bpf_iter_state {
	BPF_ITER_STATE_INVALID,
	BPF_ITER_STATE_ACTIVE,
	BPF_ITER_STATE_DRAINED,
};

enum bpf_stack_slot_type {
	STACK_INVALID,
	STACK_SPILL,
	STACK_MISC,
	STACK_ZERO,
	STACK_DYNPTR,
	STACK_ITER,
	STACK_IRQ_FLAG,
	STACK_POISON,
};

struct bpf_reg_state {
	enum bpf_reg_type type;
	s32 delta;
	union {
		int range;
		struct {
			struct bpf_map *map_ptr;
			u32 map_uid;
		};
		struct {
			struct btf *btf;
			u32 btf_id;
		};
		struct {
			u32 mem_size;
		};
		struct {
			enum bpf_dynptr_type type;
			bool first_slot;
		} dynptr;
		struct {
			const struct btf *btf;
			u32 btf_id;
			enum bpf_iter_state state;
			int depth;
		} iter;
		struct {
			u32 kfunc_class;
		} irq;
		u32 subprogno;
	};
	struct tnum var_off;
	struct cnum64 r64;
	struct cnum32 r32;
	u32 id;
	u32 parent_id;
	u32 frameno;
	s32 subreg_def;
	bool precise;
};

struct bpf_stack_state {
	struct bpf_reg_state spilled_ptr;
	u8 slot_type[BPF_REG_SIZE];
};

struct bpf_func_state {
	struct bpf_reg_state regs[MAX_BPF_REG];
	int callsite;
	u32 frameno;
	u32 subprogno;
	u32 async_entry_cnt;
	bool in_callback_fn;
	bool in_async_callback_fn;
	bool no_stack_arg_load;
	u32 callback_depth;
	struct bpf_stack_state *stack;
	int allocated_stack;
	u16 out_stack_arg_cnt;
	struct bpf_reg_state *stack_arg_regs;
};

enum bpf_reference_type {
	REF_TYPE_PTR = 1 << 1,
	REF_TYPE_IRQ = 1 << 2,
	REF_TYPE_LOCK = 1 << 3,
	REF_TYPE_RES_LOCK = 1 << 4,
	REF_TYPE_RES_LOCK_IRQ = 1 << 5,
};

struct bpf_reference_state {
	enum bpf_reference_type type;
	int id;
	int insn_idx;
	union {
		int parent_id;
		void *ptr;
	};
};

struct bpf_jmp_history_entry {
	u32 idx;
};

struct bpf_verifier_state {
	struct bpf_func_state *frame[MAX_CALL_FRAMES];
	struct bpf_verifier_state *parent;
	struct bpf_verifier_state *equal_state;
	struct bpf_reference_state refs[1];
	u32 branches;
	u32 insn_idx;
	u32 curframe;
	u32 acquired_refs;
	u32 active_locks;
	u32 active_preempt_locks;
	u32 active_rcu_locks;
	u32 active_irq_id;
	u32 active_lock_id;
	void *active_lock_ptr;
	bool speculative;
	bool in_sleepable;
	u32 first_insn_idx;
	u32 last_insn_idx;
	struct bpf_jmp_history_entry *jmp_history;
	u32 jmp_history_cnt;
	u32 dfs_depth;
	u32 callback_unroll_depth;
	u32 may_goto_depth;
};

struct bpf_verifier_state_list {
	struct bpf_verifier_state state;
	struct list_head node;
	u32 miss_cnt;
	u32 hit_cnt:31;
	u32 in_free_list:1;
};

struct bpf_insn_aux_data {
	bool is_iter_next;
	u32 scc;
	u16 live_regs_before;
	u32 prune_point:1;
	u32 force_checkpoint:1;
	u32 calls_callback:1;
	u32 jmp_point:1;
};

struct bpf_verifier_log {
	u32 level;
};

struct bpf_id_pair {
	u32 old;
	u32 cur;
};

struct bpf_idmap {
	u32 tmp_id_gen;
	u32 cnt;
	struct bpf_id_pair map[BPF_ID_MAP_SIZE];
};

struct bpf_scc_callchain {
	u32 callsites[MAX_CALL_FRAMES];
	u32 scc;
};

struct bpf_scc_backedge {
	struct bpf_scc_backedge *next;
	struct bpf_verifier_state state;
};

struct bpf_scc_visit {
	struct bpf_scc_callchain callchain;
	struct bpf_verifier_state *entry_state;
	struct bpf_scc_backedge *backedges;
	u32 num_backedges;
};

struct bpf_scc_info {
	u32 num_visits;
	struct bpf_scc_visit visits[4];
};

struct backtrack_state {
	u32 reg_masks[MAX_CALL_FRAMES];
	u64 stack_masks[MAX_CALL_FRAMES];
};

struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;
	bool test_state_freq;
	bool explore_alu_limits;
	bool allow_uninit_stack;
	bool bpf_capable;
	struct bpf_verifier_state *cur_state;
	struct list_head *explored_states;
	struct list_head free_list;
	u32 id_gen;
	struct bpf_insn_aux_data *insn_aux_data;
	struct bpf_verifier_log log;
	struct bpf_idmap idmap_scratch;
	struct backtrack_state bt;
	u32 prev_insn_processed;
	u32 insn_processed;
	u32 prev_jmps_processed;
	u32 jmps_processed;
	u32 max_states_per_insn;
	u32 total_states;
	u32 peak_states;
	u32 free_list_size;
	u32 explored_states_size;
	u32 num_backedges;
	char tmp_str_buf[TMP_STR_BUF_LEN];
	struct bpf_scc_callchain callchain_buf;
	struct bpf_scc_info **scc_info;
	u32 scc_cnt;
};

static struct bpf_verifier_state_list __bpf_states_state_list_pool;
static struct bpf_scc_backedge __bpf_states_backedge_pool;
static struct bpf_scc_info __bpf_states_scc_info_pool;
static LIST_HEAD(__bpf_states_empty_head);

static __always_inline void *__bpf_states_memset(void *dst, int c,
						 __kernel_size_t n)
{
	unsigned char *d = dst;
	__kernel_size_t i;

	for (i = 0; i < n && i < 2048; i++)
		d[i] = (unsigned char)c;
	return dst;
}

static __always_inline void *__bpf_states_memcpy(void *dst, const void *src,
						__kernel_size_t n)
{
	unsigned char *d = dst;
	const unsigned char *s = src;
	__kernel_size_t i;

	for (i = 0; i < n && i < 2048; i++)
		d[i] = s[i];
	return dst;
}

static __always_inline int __bpf_states_memcmp(const void *a, const void *b,
					      __kernel_size_t n)
{
	const unsigned char *x = a;
	const unsigned char *y = b;
	__kernel_size_t i;

	for (i = 0; i < n && i < 512; i++) {
		if (x[i] != y[i])
			return x[i] - y[i];
	}
	return 0;
}

static __always_inline void *__bpf_states_alloc(__kernel_size_t size)
{
	if (size <= sizeof(__bpf_states_state_list_pool))
		return &__bpf_states_state_list_pool;
	if (size <= sizeof(__bpf_states_backedge_pool))
		return &__bpf_states_backedge_pool;
	return &__bpf_states_scc_info_pool;
}

#define memset(dst, c, n)	__bpf_states_memset((dst), (c), (n))
#define memcpy(dst, src, n)	__bpf_states_memcpy((dst), (src), (n))
#define memcmp(a, b, n)		__bpf_states_memcmp((a), (b), (n))
#define snprintf(buf, size, fmt, ...)	(0)
#define kzalloc_obj(obj, flags)	((typeof(obj) *)__bpf_states_alloc(sizeof(obj)))
#define kvrealloc(old, size, flags)	({ (void)(old); __bpf_states_alloc(size); })
#define kfree(ptr)		do { (void)(ptr); } while (0)
#define kvfree(ptr)		do { (void)(ptr); } while (0)

#define bpf_verifier_log_write(env, fmt, ...)	do { (void)(env); } while (0)
#define verbose_linfo(env, off, fmt, ...)	do { (void)(env); (void)(off); } while (0)
#define print_verifier_state(env, st, fr, verbose) \
	do { (void)(env); (void)(st); (void)(fr); (void)(verbose); } while (0)
#define verifier_bug(env, fmt, ...)		do { (void)(env); } while (0)
#define verifier_bug_if(cond, env, fmt, ...)	({ bool __c = (cond); (void)(env); __c; })

static inline u32 bpf_frame_insn_idx(const struct bpf_verifier_state *st, int frame)
{
	if (frame == st->curframe)
		return st->insn_idx;
	if (frame + 1 <= st->curframe && st->frame[frame + 1])
		return st->frame[frame + 1]->callsite;
	if (st->frame[frame])
		return st->frame[frame]->callsite;
	return 0;
}

static inline bool bpf_register_is_null(const struct bpf_reg_state *reg)
{
	return reg->type == SCALAR_VALUE && reg->var_off.mask == 0 &&
	       reg->var_off.value == 0;
}

static inline int bpf_live_stack_query_init(struct bpf_verifier_env *env,
					    struct bpf_verifier_state *st)
{
	(void)env;
	(void)st;
	return 0;
}

static inline bool bpf_stack_slot_alive(struct bpf_verifier_env *env, int frame,
					int half_spi)
{
	return env->bt.stack_masks[frame] & BIT_ULL(half_spi);
}

static inline void bpf_mark_reg_not_init(struct bpf_verifier_env *env,
					 struct bpf_reg_state *reg)
{
	(void)env;
	reg->type = NOT_INIT;
	reg->id = 0;
	reg->parent_id = 0;
	reg->precise = false;
}

static inline void bpf_mark_reg_unknown_imprecise(struct bpf_reg_state *reg)
{
	reg->type = SCALAR_VALUE;
	reg->id = 0;
	reg->parent_id = 0;
	reg->precise = false;
	reg->var_off.value = 0;
	reg->var_off.mask = U64_MAX;
	reg->r64 = CNUM64_UNBOUNDED;
	reg->r32 = CNUM32_UNBOUNDED;
}

static inline bool bpf_is_spilled_reg(const struct bpf_stack_state *stack)
{
	return stack->slot_type[BPF_REG_SIZE - 1] == STACK_SPILL;
}

static inline void bpf_bt_set_frame_reg(struct backtrack_state *bt, u32 frame,
					u32 reg)
{
	if (frame < MAX_CALL_FRAMES)
		bt->reg_masks[frame] |= BIT(reg);
}

static inline void bpf_bt_set_frame_slot(struct backtrack_state *bt, u32 frame,
					 u32 slot)
{
	if (frame < MAX_CALL_FRAMES)
		bt->stack_masks[frame] |= BIT_ULL(slot);
}

static inline int bpf_mark_chain_precision(struct bpf_verifier_env *env,
					   struct bpf_verifier_state *cur,
					   int regno, bool *changed)
{
	(void)env;
	(void)cur;
	(void)regno;
	if (changed)
		*changed = false;
	return 0;
}

static inline void bpf_mark_all_scalars_precise(struct bpf_verifier_env *env,
						struct bpf_verifier_state *st)
{
	(void)env;
	(void)st;
}

static inline void bpf_free_backedges(struct bpf_scc_visit *visit)
{
	visit->backedges = NULL;
	visit->num_backedges = 0;
}

static inline void bpf_free_verifier_state(struct bpf_verifier_state *state,
					   bool free_self)
{
	(void)state;
	(void)free_self;
}

static inline int bpf_copy_verifier_state(struct bpf_verifier_state *dst,
					  const struct bpf_verifier_state *src)
{
	memcpy(dst, src, sizeof(*dst));
	return 0;
}

static inline void bpf_clear_singular_ids(struct bpf_verifier_env *env,
					  struct bpf_verifier_state *state)
{
	(void)env;
	(void)state;
}

static inline void bpf_clear_jmp_history(struct bpf_verifier_state *state)
{
	state->jmp_history = NULL;
	state->jmp_history_cnt = 0;
}

static inline int bpf_push_jmp_history(struct bpf_verifier_env *env,
				       struct bpf_verifier_state *cur,
				       int insn_flags, int spi, int frame,
				       u64 linked_regs)
{
	(void)env;
	(void)cur;
	(void)insn_flags;
	(void)spi;
	(void)frame;
	(void)linked_regs;
	return 0;
}

static inline bool bpf_is_jmp_point(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data && env->insn_aux_data[insn_idx].jmp_point;
}

static inline bool bpf_is_force_checkpoint(struct bpf_verifier_env *env,
					   int insn_idx)
{
	return env->insn_aux_data && env->insn_aux_data[insn_idx].force_checkpoint;
}

static inline bool bpf_calls_callback(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data && env->insn_aux_data[insn_idx].calls_callback;
}

static inline struct list_head *bpf_explored_state(struct bpf_verifier_env *env,
						   int insn_idx)
{
	if (env->explored_states)
		return &env->explored_states[insn_idx];
	return &__bpf_states_empty_head;
}

static inline int bpf_get_spi(s64 off)
{
	return (int)((-off - 1) / BPF_REG_SIZE);
}

static inline struct bpf_func_state *bpf_func(struct bpf_verifier_env *env,
					      const struct bpf_reg_state *reg)
{
	if (!env->cur_state || reg->frameno >= MAX_CALL_FRAMES)
		return NULL;
	return env->cur_state->frame[reg->frameno];
}

#endif /* _LINUX_BPF_VERIFIER_H */
