/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local verifier surface for kernel/bpf/check_btf.c. */
#ifndef _LINUX_BPF_VERIFIER_H
#define _LINUX_BPF_VERIFIER_H

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>

#ifndef NULL
#define NULL ((void *)0)
#endif
#ifndef INT_MAX
#define INT_MAX ((int)(~0U >> 1))
#endif
#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif
#ifndef offsetofend
#define offsetofend(type, member) \
	(offsetof(type, member) + sizeof(((type *)0)->member))
#endif
#ifndef min_t
#define min_t(type, x, y) ((type)(x) < (type)(y) ? (type)(x) : (type)(y))
#endif
#ifndef ERR_PTR
#define ERR_PTR(error) ((void *)(long)(error))
#endif
#ifndef PTR_ERR
#define PTR_ERR(ptr) ((long)(ptr))
#endif
#ifndef IS_ERR
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) > (unsigned long)-4096)
#endif

#define GFP_KERNEL_ACCOUNT 0
#define __GFP_NOWARN 0

typedef struct {
	void *ptr;
	bool is_kernel;
} bpfptr_t;

struct bpf_verifier_log {
	u32 level;
};

struct bpf_subprog_info {
	u32 start;
	u32 linfo_idx;
	bool has_ld_abs;
	bool has_tail_call;
	const char *name;
};

struct bpf_verifier_env {
	struct bpf_prog *prog;
	struct bpf_subprog_info *subprog_info;
	u32 subprog_cnt;
	struct bpf_verifier_log log;
};

struct bpf_core_ctx {
	struct bpf_verifier_log *log;
	const struct btf *btf;
};

static inline bpfptr_t make_bpfptr(const void *ptr, bool is_kernel)
{
	bpfptr_t bpfptr;

	bpfptr.ptr = (void *)ptr;
	bpfptr.is_kernel = is_kernel;
	return bpfptr;
}

static inline void bpfptr_add(bpfptr_t *bpfptr, size_t len)
{
	bpfptr->ptr = (void *)((unsigned char *)bpfptr->ptr + len);
}

static inline int bpf_check_uarg_tail_zero(bpfptr_t uaddr, size_t expected,
					   size_t actual)
{
	(void)uaddr;
	(void)expected;
	(void)actual;
	return 0;
}

static inline int copy_to_bpfptr_offset(bpfptr_t dst, size_t offset,
					const void *src, size_t len)
{
	(void)dst;
	(void)offset;
	(void)src;
	(void)len;
	return 0;
}

static inline int copy_from_bpfptr(void *dst, bpfptr_t src, size_t len)
{
	unsigned char *d = dst;
	unsigned char *s = src.ptr;
	size_t i;

	for (i = 0; i < len && i < 256; i++)
		d[i] = s[i];
	return 0;
}

#define bpf_verifier_log_write(env, fmt, ...) do { (void)(env); } while (0)

static struct bpf_func_info __check_btf_func_info_pool[4];
static struct bpf_func_info_aux __check_btf_func_info_aux_pool[4];
static struct bpf_line_info __check_btf_line_info_pool[4];

static inline void __check_btf_zero(void *ptr, size_t len)
{
	unsigned char *p = ptr;
	size_t i;

	for (i = 0; i < len && i < 256; i++)
		p[i] = 0;
}

static inline void *__check_btf_kvcalloc(size_t count, size_t size)
{
	if (size != sizeof(struct bpf_func_info) ||
	    count > sizeof(__check_btf_func_info_pool) / sizeof(__check_btf_func_info_pool[0]))
		return NULL;
	__check_btf_zero(__check_btf_func_info_pool, count * size);
	return __check_btf_func_info_pool;
}

static inline void *__check_btf_kvzalloc_objs(size_t size, size_t count)
{
	if (size != sizeof(struct bpf_line_info) ||
	    count > sizeof(__check_btf_line_info_pool) / sizeof(__check_btf_line_info_pool[0]))
		return NULL;
	__check_btf_zero(__check_btf_line_info_pool, count * size);
	return __check_btf_line_info_pool;
}

static inline void *__check_btf_kzalloc_objs(size_t size, size_t count)
{
	if (size != sizeof(struct bpf_func_info_aux) ||
	    count > sizeof(__check_btf_func_info_aux_pool) / sizeof(__check_btf_func_info_aux_pool[0]))
		return NULL;
	__check_btf_zero(__check_btf_func_info_aux_pool, count * size);
	return __check_btf_func_info_aux_pool;
}

#define kvcalloc(count, size, flags) \
	__check_btf_kvcalloc((count), (size))
#define kvzalloc_objs(type, count, flags) \
	((typeof(type) *)__check_btf_kvzalloc_objs(sizeof(type), (count)))
#define kzalloc_objs(obj, count, flags) \
	((typeof(&(obj)))__check_btf_kzalloc_objs(sizeof(obj), (count)))
#define kvfree(ptr) do { (void)(ptr); } while (0)
#define kfree(ptr) do { (void)(ptr); } while (0)

#endif /* _LINUX_BPF_VERIFIER_H */
