/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF surface for kernel/bpf/states.c. */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H

#include <linux/errno.h>
#include <linux/types.h>

#ifndef NULL
#define NULL ((void *)0)
#endif
#ifndef BIT
#define BIT(nr)			(1UL << (nr))
#endif
#ifndef BIT_ULL
#define BIT_ULL(nr)		(1ULL << (nr))
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

#ifndef __init
#define __init
#endif
#ifndef late_initcall
#define late_initcall(fn)
#endif

#define GFP_KERNEL_ACCOUNT	0

#define MAX_BPF_REG		11
#define MAX_BPF_STACK		512
#define MAX_BPF_FUNC_ARGS	12
#define MAX_BPF_FUNC_REG_ARGS	5

enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};

#ifndef BPF_REG_FP
#define BPF_REG_FP		BPF_REG_10
#endif

enum bpf_reg_type {
	NOT_INIT = 0,
	SCALAR_VALUE,
	PTR_TO_CTX,
	CONST_PTR_TO_MAP,
	PTR_TO_MAP_VALUE,
	PTR_TO_MAP_KEY,
	PTR_TO_STACK,
	PTR_TO_PACKET_META,
	PTR_TO_PACKET,
	PTR_TO_PACKET_END,
	PTR_TO_FLOW_KEYS,
	PTR_TO_SOCKET,
	PTR_TO_SOCK_COMMON,
	PTR_TO_TCP_SOCK,
	PTR_TO_TP_BUFFER,
	PTR_TO_XDP_SOCK,
	PTR_TO_BTF_ID,
	PTR_TO_MEM,
	PTR_TO_BUF,
	PTR_TO_FUNC,
	PTR_TO_MAP_VALUE_OR_NULL,
	PTR_TO_ARENA,
	PTR_TO_INSN,
	CONST_PTR_TO_DYNPTR,
	PTR_TO_BUF_OR_NULL,
};

#define PTR_MAYBE_NULL		((enum bpf_reg_type)(1U << 31))
#define MEM_RDONLY		((enum bpf_reg_type)(1U << 30))
#define MEM_ALLOC		((enum bpf_reg_type)(1U << 29))
#define MEM_USER		((enum bpf_reg_type)(1U << 28))
#define MEM_PERCPU		((enum bpf_reg_type)(1U << 27))
#define PTR_UNTRUSTED		((enum bpf_reg_type)(1U << 26))
#define PTR_TRUSTED		((enum bpf_reg_type)(1U << 25))

#define BPF_TYPE_MODIFIER_MASK	(PTR_MAYBE_NULL | MEM_RDONLY | MEM_ALLOC | \
				 MEM_USER | MEM_PERCPU | PTR_UNTRUSTED | \
				 PTR_TRUSTED)

static inline enum bpf_reg_type base_type(enum bpf_reg_type type)
{
	return type & ~BPF_TYPE_MODIFIER_MASK;
}

struct bpf_map;
struct btf;

struct bpf_insn {
	u8 code;
	u8 dst_reg:4;
	u8 src_reg:4;
	s16 off;
	s32 imm;
};

struct bpf_prog {
	struct bpf_insn *insnsi;
	u32 len;
};

static inline bool bpf_is_may_goto_insn(const struct bpf_insn *insn)
{
	(void)insn;
	return false;
}

#endif /* _LINUX_BPF_H */
