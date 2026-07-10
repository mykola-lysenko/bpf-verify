/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF surface for kernel/bpf/cfg.c. */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H

#include <linux/errno.h>
#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/filter.h>

#ifndef BPF_MAX_SUBPROGS
#define BPF_MAX_SUBPROGS	4
#endif

#ifndef MAX_BPF_FUNC_ARGS
#define MAX_BPF_FUNC_ARGS	12
#endif
#ifndef MAX_BPF_FUNC_REG_ARGS
#define MAX_BPF_FUNC_REG_ARGS	5
#endif

struct bpf_map;
struct bpf_prog;

struct bpf_map_ops {
	void *(*map_lookup_elem)(struct bpf_map *map, void *key);
};

struct bpf_map {
	const struct bpf_map_ops *ops;
	u32 max_entries;
};

struct bpf_prog_aux {
	bool changes_pkt_data;
	bool might_sleep;
};

struct bpf_prog {
	struct bpf_insn *insnsi;
	int len;
	struct bpf_prog_aux *aux;
};

struct bpf_func_proto {
	bool might_sleep;
};

struct bpf_kfunc_call_arg_meta {
	bool dummy;
};

static inline bool bpf_is_ldimm64(const struct bpf_insn *insn)
{
	return insn->code == (BPF_LD | BPF_IMM | BPF_DW);
}

static inline bool bpf_pseudo_func(const struct bpf_insn *insn)
{
	return bpf_is_ldimm64(insn) && insn->src_reg == BPF_PSEUDO_FUNC;
}

#endif /* _LINUX_BPF_H */
