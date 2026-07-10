/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF surface for kernel/bpf/bpf_verification_stubs.c. */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H

#include <linux/types.h>
#include <linux/errno.h>

#ifndef EOPNOTSUPP
#define EOPNOTSUPP	95
#endif

#define __init
#define __read_mostly
#define __bpf_kfunc
#define __bpf_kfunc_start_defs()
#define __bpf_kfunc_end_defs()
#define THIS_MODULE	((void *)0)

#define MEM_RDONLY		(1U << 30)
#define PTR_MAYBE_NULL		(1U << 31)
#define RET_INTEGER		1
#define ARG_PTR_TO_MEM		1
#define ARG_CONST_SIZE		2
#define ARG_CONST_SIZE_OR_ZERO	3
#define ARG_PTR_TO_UNINIT_MEM	4
#define ARG_ANYTHING		5

#define BPF_PROG_TYPE_KPROBE		1
#define BPF_PROG_TYPE_TRACING		2
#define BPF_PROG_TYPE_TRACEPOINT	3
#define BPF_PROG_TYPE_PERF_EVENT	4
#define BPF_PROG_TYPE_LSM		5

#define KF_ACQUIRE	(1U << 0)
#define KF_RET_NULL	(1U << 1)
#define KF_RELEASE	(1U << 2)
#define KF_SLEEPABLE	(1U << 3)

enum bpf_func_id {
	BPF_FUNC_unspec = 0,
	BPF_FUNC_trace_printk,
	BPF_FUNC_trace_vprintk,
};

enum bpf_access_type {
	BPF_READ = 0,
	BPF_WRITE = 1,
};

typedef u64 (*bpf_func_t)(u64, u64, u64, u64, u64);

struct bpf_prog {
	int dummy;
};

struct bpf_insn_access_aux {
	int dummy;
};

struct bpf_func_proto {
	bpf_func_t func;
	bool gpl_only;
	int ret_type;
	int arg1_type;
	int arg2_type;
	int arg3_type;
	int arg4_type;
};

struct bpf_verifier_ops {
	const struct bpf_func_proto *(*get_func_proto)(enum bpf_func_id func_id,
						       const struct bpf_prog *prog);
	bool (*is_valid_access)(int off, int size, enum bpf_access_type type,
				const struct bpf_prog *prog,
				struct bpf_insn_access_aux *info);
};

struct bpf_prog_ops {
	int (*test_run)(struct bpf_prog *prog);
};

static const struct bpf_func_proto __bpf_verif_base_proto = {
	.ret_type = RET_INTEGER,
};

static inline const struct bpf_func_proto *
bpf_base_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	(void)func_id;
	(void)prog;
	return &__bpf_verif_base_proto;
}

static inline bool bpf_tracing_btf_ctx_access(int off, int size,
					      enum bpf_access_type type,
					      const struct bpf_prog *prog,
					      struct bpf_insn_access_aux *info)
{
	(void)type;
	(void)prog;
	(void)info;
	return off >= 0 && size > 0 && size <= 8;
}

static inline int bpf_prog_test_run_tracing(struct bpf_prog *prog)
{
	(void)prog;
	return 0;
}

static inline int bpf_prog_test_run_raw_tp(struct bpf_prog *prog)
{
	(void)prog;
	return 0;
}

static inline int bpf_probe_read_kernel_common(void *dst, u32 size,
					       const void *unsafe_ptr)
{
	(void)dst;
	(void)size;
	(void)unsafe_ptr;
	return 0;
}

static inline long strncpy_from_kernel_nofault(void *dst,
					       const void *unsafe_ptr,
					       u32 size)
{
	(void)dst;
	(void)unsafe_ptr;
	(void)size;
	return 0;
}

static inline void *memset(void *dst, int c, unsigned long size)
{
	(void)c;
	(void)size;
	return dst;
}

#define BPF_CALL_3(name, t1, a1, t2, a2, t3, a3) \
	u64 name(u64 a1, u64 a2, u64 a3, u64 __unused1, u64 __unused2)
#define BPF_CALL_4(name, t1, a1, t2, a2, t3, a3, t4, a4) \
	u64 name(u64 a1, u64 a2, u64 a3, u64 a4, u64 __unused)
#define BPF_CALL_5(name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) \
	u64 name(u64 a1, u64 a2, u64 a3, u64 a4, u64 a5)

struct task_struct {
	int pid;
};

#endif /* _LINUX_BPF_H */
