/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF surface for kernel/bpf/liveness.c. */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H

#include <linux/errno.h>
#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/filter.h>

#ifndef NULL
#define NULL ((void *)0)
#endif
#ifndef BIT
#define BIT(nr)			(1UL << (nr))
#endif
#ifndef BIT_ULL
#define BIT_ULL(nr)		(1ULL << (nr))
#endif
#ifndef GENMASK
#define GENMASK(h, l) \
	(((~0U) - (1U << (l)) + 1) & (~0U >> (31 - (h))))
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)		(sizeof(arr) / sizeof((arr)[0]))
#endif
#ifndef offsetof
#define offsetof(TYPE, MEMBER)	__builtin_offsetof(TYPE, MEMBER)
#endif
#ifndef container_of
#define container_of(ptr, type, member) ({				\
	const typeof(((type *)0)->member) *__mptr = (ptr);		\
	(type *)((char *)__mptr - offsetof(type, member)); })
#endif
#ifndef max
#define max(x, y)		((x) > (y) ? (x) : (y))
#endif
#ifndef min
#define min(x, y)		((x) < (y) ? (x) : (y))
#endif
#ifndef max_t
#define max_t(type, x, y)	((type)(x) > (type)(y) ? (type)(x) : (type)(y))
#endif
#ifndef min_t
#define min_t(type, x, y)	((type)(x) < (type)(y) ? (type)(x) : (type)(y))
#endif

#ifndef U32_MAX
#define U32_MAX			((u32)~0U)
#endif
#ifndef S64_MIN
#define S64_MIN			((s64)(1ULL << 63))
#endif

#define BPF_MAX_SUBPROGS	4
#define MAX_BPF_STACK		512
#define MAX_BPF_REG		11
#define MAX_BPF_FUNC_ARGS	12
#define MAX_BPF_FUNC_REG_ARGS	5
#define BPF_REG_PARAMS		MAX_BPF_REG
#define CALLER_SAVED_REGS	6

#ifndef BPF_REG_FP
#define BPF_REG_FP		BPF_REG_10
#endif

struct bpf_map;
struct btf;
struct bpf_verifier_env;

struct bpf_prog_aux {
	bool dummy;
};

struct bpf_prog {
	struct bpf_insn *insnsi;
	int len;
	struct bpf_prog_aux *aux;
};

static inline bool bpf_is_ldimm64(const struct bpf_insn *insn)
{
	return insn->code == (BPF_LD | BPF_IMM | BPF_DW);
}

static inline u32 bpf_size_to_bytes(u32 bpf_size)
{
	return bpf_size == BPF_DW ? 8 :
	       bpf_size == BPF_W  ? 4 :
	       bpf_size == BPF_H  ? 2 : 1;
}

static inline bool is_stack_arg_ldx(const struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_LDX &&
	       insn->src_reg == BPF_REG_PARAMS;
}

static inline bool is_stack_arg_st(const struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_ST &&
	       insn->dst_reg == BPF_REG_PARAMS;
}

static inline bool is_stack_arg_stx(const struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_STX &&
	       insn->dst_reg == BPF_REG_PARAMS;
}

#endif /* _LINUX_BPF_H */
