/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local shim for kernel/bpf/const_fold.c. */
#ifndef _LINUX_BPF_VERIFIER_H
#define _LINUX_BPF_VERIFIER_H

#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/filter.h>

#ifndef BIT
#define BIT(nr)		(1UL << (nr))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef ENOMEM
#define ENOMEM		12
#endif
#ifndef EFAULT
#define EFAULT		14
#endif

#define GFP_KERNEL_ACCOUNT	0
#define BPF_MAX_SUBPROGS	8
#define MAX_USED_MAPS		8

struct bpf_iarray {
	int cnt;
	u32 items[2];
};

struct bpf_insn_aux_data {
	union {
		struct {
			u32 map_index;
			u32 map_off;
		};
	};
	u64 const_reg_vals[MAX_BPF_REG];
	u16 const_reg_mask;
	u16 const_reg_map_mask;
	u16 const_reg_subprog_mask;
};

struct bpf_subprog_info {
	int start;
};

struct bpf_prog {
	struct bpf_insn *insnsi;
	int len;
};

struct bpf_map;

struct bpf_map_ops {
	int (*map_direct_value_addr)(const struct bpf_map *map, u64 *addr,
				     u32 off);
};

struct bpf_map {
	const struct bpf_map_ops *ops;
	enum bpf_map_type map_type;
	u32 value_size;
	bool rdonly;
};

struct bpf_verifier_log {
	u32 level;
};

struct bpf_verifier_env {
	struct bpf_prog *prog;
	struct bpf_insn_aux_data *insn_aux_data;
	struct bpf_map **used_maps;
	struct bpf_subprog_info *subprog_info;
	u32 subprog_cnt;
	struct bpf_verifier_log log;
	struct {
		int *insn_postorder;
		int cur_postorder;
	} cfg;
	struct bpf_iarray **succ;
};

#define memcpy(dst, src, n)	__builtin_memcpy((dst), (src), (n))

static inline void *__bpf_const_fold_zalloc(__kernel_size_t size)
{
	static unsigned char storage[4096];

	if (size > sizeof(storage))
		return (void *)0;
	for (__kernel_size_t i = 0; i < sizeof(storage); i++)
		storage[i] = 0;
	return storage;
}

#define kvzalloc_objs(ptr, count, flags) \
	((typeof(ptr) *)__bpf_const_fold_zalloc(sizeof(typeof(ptr)) * (count)))
#define kvfree(ptr)	do { (void)(ptr); } while (0)

static inline int bpf_size_to_bytes(u8 size)
{
	switch (size) {
	case BPF_B: return 1;
	case BPF_H: return 2;
	case BPF_W: return 4;
	case BPF_DW: return 8;
	default: return -1;
	}
}

static inline bool bpf_map_is_rdonly(const struct bpf_map *map)
{
	return map && map->rdonly;
}

static inline int bpf_map_direct_read(const struct bpf_map *map, u64 off,
				      int size, u64 *val, bool is_ldsx)
{
	(void)map;
	(void)off;
	(void)size;
	(void)is_ldsx;
	*val = 0;
	return -EFAULT;
}

static inline int bpf_find_subprog(struct bpf_verifier_env *env, int off)
{
	for (u32 i = 0; i < env->subprog_cnt; i++) {
		if (env->subprog_info[i].start == off)
			return i;
	}
	return -1;
}

static inline struct bpf_iarray *bpf_insn_successors(struct bpf_verifier_env *env,
						     u32 idx)
{
	return env->succ[idx];
}

static inline bool is_stack_arg_st(const struct bpf_insn *insn)
{
	(void)insn;
	return false;
}

static inline bool is_stack_arg_stx(const struct bpf_insn *insn)
{
	(void)insn;
	return false;
}

static inline bool is_stack_arg_ldx(const struct bpf_insn *insn)
{
	(void)insn;
	return false;
}

static inline bool bpf_insn_is_cond_jump(u8 code)
{
	u8 op = BPF_OP(code);

	if (BPF_CLASS(code) != BPF_JMP && BPF_CLASS(code) != BPF_JMP32)
		return false;
	return op != BPF_JA && op != BPF_CALL && op != BPF_EXIT;
}

static inline bool bpf_is_may_goto_insn(const struct bpf_insn *insn)
{
	(void)insn;
	return false;
}

static inline void bpf_log(struct bpf_verifier_log *log, const char *fmt, ...)
{
	(void)log;
	(void)fmt;
}

static inline int bpf_compute_postorder(struct bpf_verifier_env *env)
{
	(void)env;
	return 0;
}

#define BPF_JMP_A(OFF) \
	((struct bpf_insn){ .code = BPF_JMP | BPF_JA, .off = (OFF) })

#endif /* _LINUX_BPF_VERIFIER_H */
