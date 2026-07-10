/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF surface for kernel/bpf/check_btf.c. */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H

#include <linux/types.h>

union bpf_attr {
	struct {
		u32 prog_type;
		u32 insn_cnt;
		void *insns;
		void *license;
		u32 log_level;
		u32 log_size;
		void *log_buf;
		u32 kern_version;
		u32 prog_flags;
		char prog_name[16];
		u32 prog_ifindex;
		u32 expected_attach_type;
		u32 prog_btf_fd;
		u32 func_info_rec_size;
		void *func_info;
		u32 func_info_cnt;
		u32 line_info_rec_size;
		void *line_info;
		u32 line_info_cnt;
		u32 attach_btf_id;
		u32 attach_prog_fd;
		u32 core_relo_cnt;
		void *fd_array;
		void *core_relos;
		u32 core_relo_rec_size;
		u32 log_true_size;
	};
};

struct bpf_func_info {
	u32 insn_off;
	u32 type_id;
};

struct bpf_func_info_aux {
	u16 linkage;
	bool unreliable;
	bool called:1;
	bool verified:1;
};

struct bpf_line_info {
	u32 insn_off;
	u32 file_name_off;
	u32 line_off;
	u32 line_col;
};

enum bpf_core_relo_kind {
	BPF_FIELD_BYTE_OFFSET = 0,
};

struct bpf_core_relo {
	u32 insn_off;
	u32 type_id;
	u32 access_str_off;
	enum bpf_core_relo_kind kind;
};

struct bpf_insn {
	u8 code;
	u8 dst_reg:4;
	u8 src_reg:4;
	s16 off;
	s32 imm;
};

struct btf;

struct bpf_prog_aux {
	struct btf *btf;
	struct bpf_func_info *func_info;
	struct bpf_func_info_aux *func_info_aux;
	struct bpf_line_info *linfo;
	u32 func_info_cnt;
	u32 nr_linfo;
};

struct bpf_prog {
	struct bpf_prog_aux *aux;
	struct bpf_insn *insnsi;
	u32 len;
};

#endif /* _LINUX_BPF_H */
