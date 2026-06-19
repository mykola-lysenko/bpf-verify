/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local verifier surface for kernel/bpf/log.c. */
#ifndef _LINUX_BPF_VERIFIER_H
#define _LINUX_BPF_VERIFIER_H

#include <uapi/linux/btf.h>
#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/types.h>

#define MAX_BPF_REG			11
#define BPF_REG_SIZE			8
#define MAX_CALL_FRAMES			2
#define BPF_DYNPTR_NR_SLOTS		2
#define TMP_STR_BUF_LEN			320
#define ITER_PREFIX			"bpf_iter_"
#define BPF_VERIFIER_TMP_LOG_SIZE	128

#define BPF_LOG_LEVEL1			1
#define BPF_LOG_LEVEL2			2
#define BPF_LOG_STATS			4
#define BPF_LOG_FIXED			8
#define BPF_LOG_LEVEL			(BPF_LOG_LEVEL1 | BPF_LOG_LEVEL2)
#define BPF_LOG_MASK			(BPF_LOG_LEVEL | BPF_LOG_STATS | BPF_LOG_FIXED)
#define BPF_LOG_KERNEL			(BPF_LOG_MASK + 1)
#define BPF_LOG_MIN_ALIGNMENT		8U
#define BPF_LOG_ALIGNMENT		40U

#define BPF_ADD_CONST64			(1U << 31)
#define BPF_ADD_CONST32			(1U << 30)
#define BPF_ADD_CONST			(BPF_ADD_CONST64 | BPF_ADD_CONST32)

enum bpf_iter_state {
	BPF_ITER_STATE_INVALID,
	BPF_ITER_STATE_ACTIVE,
	BPF_ITER_STATE_DRAINED,
};

struct tnum {
	u64 value;
	u64 mask;
};

static inline bool tnum_is_const(struct tnum t)
{
	return t.mask == 0;
}

static inline bool tnum_is_unknown(struct tnum t)
{
	return t.value == 0 && t.mask == U64_MAX;
}

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
		} dynptr;
		struct {
			const struct btf *btf;
			u32 btf_id;
			enum bpf_iter_state state;
			int depth;
		} iter;
	};
	struct tnum var_off;
	s64 smin_value;
	s64 smax_value;
	u64 umin_value;
	u64 umax_value;
	s32 s32_min_value;
	s32 s32_max_value;
	u32 u32_min_value;
	u32 u32_max_value;
	u32 id;
	u32 parent_id;
	u32 frameno;
	bool precise;
};

static inline s64 reg_smin(const struct bpf_reg_state *reg)
{
	return reg->smin_value;
}

static inline s64 reg_smax(const struct bpf_reg_state *reg)
{
	return reg->smax_value;
}

static inline u64 reg_umin(const struct bpf_reg_state *reg)
{
	return reg->umin_value;
}

static inline u64 reg_umax(const struct bpf_reg_state *reg)
{
	return reg->umax_value;
}

static inline s32 reg_s32_min(const struct bpf_reg_state *reg)
{
	return reg->s32_min_value;
}

static inline s32 reg_s32_max(const struct bpf_reg_state *reg)
{
	return reg->s32_max_value;
}

static inline u32 reg_u32_min(const struct bpf_reg_state *reg)
{
	return reg->u32_min_value;
}

static inline u32 reg_u32_max(const struct bpf_reg_state *reg)
{
	return reg->u32_max_value;
}

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

struct bpf_stack_state {
	struct bpf_reg_state spilled_ptr;
	u8 slot_type[BPF_REG_SIZE];
};

struct bpf_func_state {
	struct bpf_reg_state regs[MAX_BPF_REG];
	struct bpf_stack_state *stack;
	int allocated_stack;
	u32 frameno;
	bool in_callback_fn;
	bool in_async_callback_fn;
};

struct bpf_reference_state {
	int id;
};

struct bpf_verifier_state {
	struct bpf_func_state *frame[MAX_CALL_FRAMES];
	u32 acquired_refs;
	struct bpf_reference_state refs[4];
};

struct bpf_verifier_log {
	u64 start_pos;
	u64 end_pos;
	char __user *ubuf;
	u32 level;
	u32 len_total;
	u32 len_max;
	char kbuf[BPF_VERIFIER_TMP_LOG_SIZE];
};

static inline bool bpf_verifier_log_needed(const struct bpf_verifier_log *log)
{
	return log && log->level;
}

struct bpf_verifier_env {
	struct bpf_verifier_log log;
	struct bpf_prog *prog;
	const struct bpf_line_info *prev_linfo;
	u64 prev_log_pos;
	u32 prev_insn_print_pos;
	u32 insn_idx;
	char tmp_str_buf[TMP_STR_BUF_LEN];
};

struct bpf_line_info {
	u32 line_off;
	u32 file_name_off;
	u32 line_col;
};

#define BPF_LINE_INFO_LINE_NUM(line_col)	((line_col) >> 10)

static inline const struct bpf_line_info *
bpf_find_linfo(const struct bpf_prog *prog, u32 insn_off)
{
	(void)prog;
	(void)insn_off;
	return (void *)0;
}

struct btf {
	int dummy;
};

static inline const char *btf_name_by_offset(const struct btf *btf, u32 off)
{
	(void)btf;
	return off ? "kernel/bpf/log.c" : "bpf_iter_num";
}

static inline const struct btf_type *btf_type_by_id(const struct btf *btf,
						    u32 id)
{
	static struct btf_type type;

	(void)btf;
	type.name_off = id ? 0 : 1;
	return &type;
}

static inline bool type_is_non_owning_ref(enum bpf_reg_type type)
{
	(void)type;
	return false;
}

static inline bool type_is_pkt_pointer(enum bpf_reg_type type)
{
	type = base_type(type);
	return type == PTR_TO_PACKET || type == PTR_TO_PACKET_META;
}

static inline bool reg_scratched(struct bpf_verifier_env *env, int regno)
{
	(void)env;
	(void)regno;
	return true;
}

static inline bool stack_slot_scratched(struct bpf_verifier_env *env, int spi)
{
	(void)env;
	(void)spi;
	return true;
}

static inline void mark_verifier_state_clean(struct bpf_verifier_env *env)
{
	(void)env;
}

typedef struct {
	void *ptr;
} bpfptr_t;

struct bpf_common_attr {
	u64 log_buf;
	u32 log_size;
	u32 log_level;
	u32 log_true_size;
};

struct bpf_log_attr {
	char __user *ubuf;
	u32 size;
	u32 level;
	u32 offsetof_true_size;
	bpfptr_t uattr;
};

#define GFP_KERNEL	0

static struct bpf_verifier_log __bpf_log_alloc;

static inline void *__bpf_log_zalloc(size_t size)
{
	unsigned char *p = (unsigned char *)&__bpf_log_alloc;
	size_t i;

	if (size > sizeof(__bpf_log_alloc))
		return (void *)0;
	for (i = 0; i < sizeof(__bpf_log_alloc); i++)
		p[i] = 0;
	return &__bpf_log_alloc;
}

#define kzalloc_obj(obj, flags) \
	((typeof(&(obj)))__bpf_log_zalloc(sizeof(obj)))
#define kfree(ptr)	do { (void)(ptr); } while (0)

#define ERR_PTR(err)	((void *)(long)(err))

static inline char __user *u64_to_user_ptr(u64 addr)
{
	return (char __user *)(unsigned long)addr;
}

static inline int copy_to_user(char __user *dst, const void *src, size_t len)
{
	(void)dst;
	(void)src;
	(void)len;
	return 0;
}

static inline int copy_from_user(void *dst, const char __user *src, size_t len)
{
	unsigned char *d = dst;
	size_t i;

	(void)src;
	for (i = 0; i < len && i < 512; i++)
		d[i] = 0;
	return 0;
}

#define put_user(val, ptr)	({ *(ptr) = (val); 0; })

static inline int copy_to_bpfptr_offset(bpfptr_t dst, u32 off,
					const void *src, size_t len)
{
	(void)dst;
	(void)off;
	(void)src;
	(void)len;
	return 0;
}

#endif /* _LINUX_BPF_VERIFIER_H */
