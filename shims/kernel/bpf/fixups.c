// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: kernel/bpf/fixups.c instruction classifiers.
 *
 * The real kernel/bpf/fixups.c pulls in the full verifier patch/JIT fixup
 * surface after these helpers. Keep this shim scoped to the classifier logic
 * we verify here, while preserving the helper bodies from the kernel source.
 */

#include "bpf_shim_common.h"

#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_LD          0x00
#define BPF_LDX         0x01
#define BPF_ST          0x02
#define BPF_STX         0x03
#define BPF_ALU         0x04
#define BPF_JMP         0x05
#define BPF_JMP32       0x06
#define BPF_ALU64       0x07

#define BPF_SIZE(code)  ((code) & 0x18)
#define BPF_W           0x00
#define BPF_H           0x08
#define BPF_B           0x10
#define BPF_DW          0x18

#define BPF_MODE(code)  ((code) & 0xe0)
#define BPF_IMM         0x00
#define BPF_MEM         0x60
#define BPF_MEMSX       0x80
#define BPF_ATOMIC      0xc0
#define BPF_PROBE_ATOMIC 0xe0

#define BPF_OP(code)    ((code) & 0xf0)
#define BPF_ADD         0x00
#define BPF_MOV         0xb0
#define BPF_JA          0x00
#define BPF_JEQ         0x10
#define BPF_CALL        0x80
#define BPF_EXIT        0x90
#define BPF_JCOND       0xe0

#define BPF_SRC(code)   ((code) & 0x08)
#define BPF_K           0x00
#define BPF_X           0x08

#define BPF_FETCH       0x01
#define BPF_CMPXCHG     (0xf0 | BPF_FETCH)
#define BPF_LOAD_ACQ    0x100

#define BPF_REG_0       0
#define BPF_REG_1       1
#define BPF_REG_2       2
#define BPF_REG_3       3

#define DST_OP          1
#define BPF_KEEP_SCALAR(x) asm volatile("" : "+r"(x))

struct bpf_insn {
	u8 code;
	u8 dst_reg:4;
	u8 src_reg:4;
	s16 off;
	s32 imm;
};

#define BPF_ALU32_REG(OP, DST, SRC) \
	((struct bpf_insn){ .code = BPF_ALU | BPF_OP(OP) | BPF_X, \
			    .dst_reg = DST, .src_reg = SRC })
#define BPF_ALU64_REG(OP, DST, SRC) \
	((struct bpf_insn){ .code = BPF_ALU64 | BPF_OP(OP) | BPF_X, \
			    .dst_reg = DST, .src_reg = SRC })
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) \
	((struct bpf_insn){ .code = BPF_LDX | BPF_MEM | BPF_SIZE(SIZE), \
			    .dst_reg = DST, .src_reg = SRC, .off = OFF })
#define BPF_STX_ATOMIC(SIZE, DST, SRC, OFF, IMM) \
	((struct bpf_insn){ .code = BPF_STX | BPF_ATOMIC | BPF_SIZE(SIZE), \
			    .dst_reg = DST, .src_reg = SRC, .off = OFF, \
			    .imm = IMM })
#define BPF_JMP_IMM(OP, DST, IMM, OFF) \
	((struct bpf_insn){ .code = BPF_JMP | BPF_OP(OP) | BPF_K, \
			    .dst_reg = DST, .off = OFF, .imm = IMM })
#define BPF_JMP32_IMM(OP, DST, IMM, OFF) \
	((struct bpf_insn){ .code = BPF_JMP32 | BPF_OP(OP) | BPF_K, \
			    .dst_reg = DST, .off = OFF, .imm = IMM })

static __always_inline bool bpf_is_reg64(struct bpf_insn *insn, u32 regno,
					 void *reg, int type)
{
	(void)regno;
	(void)reg;
	(void)type;

	if (BPF_CLASS(insn->code) == BPF_ALU64)
		return true;
	if (BPF_CLASS(insn->code) == BPF_LD)
		return BPF_SIZE(insn->code) == BPF_DW;
	if (BPF_CLASS(insn->code) == BPF_LDX)
		return BPF_SIZE(insn->code) == BPF_DW;
	if (BPF_CLASS(insn->code) == BPF_STX &&
	    (BPF_MODE(insn->code) == BPF_ATOMIC ||
	     BPF_MODE(insn->code) == BPF_PROBE_ATOMIC))
		return BPF_SIZE(insn->code) == BPF_DW;
	return false;
}

static __always_inline bool is_cmpxchg_insn(const struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_STX &&
	       BPF_MODE(insn->code) == BPF_ATOMIC &&
	       insn->imm == BPF_CMPXCHG;
}

/* Return the regno defined by the insn, or -1. */
static __always_inline int insn_def_regno(const struct bpf_insn *insn)
{
	switch (BPF_CLASS(insn->code)) {
	case BPF_JMP:
	case BPF_JMP32:
	case BPF_ST:
		return -1;
	case BPF_STX:
		if (BPF_MODE(insn->code) == BPF_ATOMIC ||
		    BPF_MODE(insn->code) == BPF_PROBE_ATOMIC) {
			if (insn->imm == BPF_CMPXCHG)
				return BPF_REG_0;
			else if (insn->imm == BPF_LOAD_ACQ)
				return insn->dst_reg;
			else if (insn->imm & BPF_FETCH)
				return insn->src_reg;
		}
		return -1;
	default:
		return insn->dst_reg;
	}
}

/* Return TRUE if INSN has defined any 32-bit value explicitly. */
static __always_inline bool insn_has_def32(struct bpf_insn *insn)
{
	int dst_reg = insn_def_regno(insn);

	if (dst_reg == -1)
		return false;

	return !bpf_is_reg64(insn, dst_reg, NULL, DST_OP);
}

bool bpf_insn_is_cond_jump(u8 code)
{
	u8 op;

	op = BPF_OP(code);
	if (BPF_CLASS(code) == BPF_JMP32)
		return op != BPF_JA;

	if (BPF_CLASS(code) != BPF_JMP)
		return false;

	return op != BPF_JA && op != BPF_EXIT && op != BPF_CALL;
}
