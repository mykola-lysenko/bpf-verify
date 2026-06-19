/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF surface for kernel/bpf/log.c. */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H

#include <linux/types.h>

#define PTR_MAYBE_NULL		(1U << 31)
#define MEM_RDONLY		(1U << 30)
#define MEM_RINGBUF		(1U << 29)
#define MEM_USER		(1U << 28)
#define MEM_PERCPU		(1U << 27)
#define MEM_RCU			(1U << 26)
#define PTR_UNTRUSTED		(1U << 25)
#define PTR_TRUSTED		(1U << 24)
#define MEM_TYPE_MASK		(PTR_MAYBE_NULL | MEM_RDONLY | MEM_RINGBUF | \
				 MEM_USER | MEM_PERCPU | MEM_RCU | \
				 PTR_UNTRUSTED | PTR_TRUSTED)

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
	PTR_TO_ARENA,
	PTR_TO_BUF,
	PTR_TO_FUNC,
	PTR_TO_INSN,
	CONST_PTR_TO_DYNPTR,
};

#define PTR_TO_MAP_VALUE_OR_NULL	(PTR_MAYBE_NULL | PTR_TO_MAP_VALUE)
#define PTR_TO_SOCKET_OR_NULL		(PTR_MAYBE_NULL | PTR_TO_SOCKET)
#define PTR_TO_SOCK_COMMON_OR_NULL	(PTR_MAYBE_NULL | PTR_TO_SOCK_COMMON)
#define PTR_TO_TCP_SOCK_OR_NULL		(PTR_MAYBE_NULL | PTR_TO_TCP_SOCK)
#define PTR_TO_BTF_ID_OR_NULL		(PTR_MAYBE_NULL | PTR_TO_BTF_ID)
#define PTR_TO_MEM_OR_NULL		(PTR_MAYBE_NULL | PTR_TO_MEM)

static inline enum bpf_reg_type base_type(enum bpf_reg_type type)
{
	return type & ~MEM_TYPE_MASK;
}

enum bpf_dynptr_type {
	BPF_DYNPTR_TYPE_INVALID,
	BPF_DYNPTR_TYPE_LOCAL,
	BPF_DYNPTR_TYPE_RINGBUF,
	BPF_DYNPTR_TYPE_SKB,
	BPF_DYNPTR_TYPE_XDP,
	BPF_DYNPTR_TYPE_SKB_META,
	BPF_DYNPTR_TYPE_FILE,
};

struct bpf_map {
	char name[16];
	u32 key_size;
	u32 value_size;
};

struct btf;

struct bpf_prog_aux {
	const struct btf *btf;
};

struct bpf_prog {
	struct bpf_prog_aux *aux;
};

#endif /* _LINUX_BPF_H */
