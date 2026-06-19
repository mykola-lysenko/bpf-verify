/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF surface for kernel/bpf/backtrack.c. */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H

#include <linux/types.h>
#include <linux/filter.h>
#include <uapi/linux/bpf.h>

#ifndef BPF_REG_FP
#define BPF_REG_FP		BPF_REG_10
#endif

#ifndef MAX_BPF_FUNC_ARGS
#define MAX_BPF_FUNC_ARGS	12
#endif
#ifndef MAX_BPF_FUNC_REG_ARGS
#define MAX_BPF_FUNC_REG_ARGS	5
#endif

struct bpf_prog {
	struct bpf_insn *insnsi;
	int len;
};

enum bpf_reg_type {
	NOT_INIT = 0,
	SCALAR_VALUE = 1,
};

static inline bool bpf_pseudo_call(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == BPF_PSEUDO_CALL;
}

#endif /* _LINUX_BPF_H */
