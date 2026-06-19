/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF surface for kernel/bpf/crypto.c. */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H

#include <linux/types.h>
#include <linux/errno.h>

#ifndef NULL
#define NULL ((void *)0)
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif
#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif
#ifndef container_of
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#endif

#define __init
#define __bpf_kfunc
#define __bpf_kfunc_start_defs()
#define __bpf_kfunc_end_defs()
#define CFI_NOSEAL(fn)
#define late_initcall(fn)
#define THIS_MODULE NULL

#define BPF_PROG_TYPE_SCHED_CLS 1
#define BPF_PROG_TYPE_SCHED_ACT 2
#define BPF_PROG_TYPE_XDP 3
#define BPF_PROG_TYPE_SYSCALL 4

#define KF_ACQUIRE (1U << 0)
#define KF_RET_NULL (1U << 1)
#define KF_SLEEPABLE (1U << 2)
#define KF_RELEASE (1U << 3)
#define KF_RCU (1U << 4)

#define BPF_DYNPTR_RDONLY (1U << 31)
#define BPF_DYNPTR_SIZE_MASK 0x00ffffffU

struct module {
	int refs;
};

typedef struct {
	int refs;
} refcount_t;

static inline void refcount_set(refcount_t *ref, int value)
{
	ref->refs = value;
}

static inline bool refcount_inc_not_zero(refcount_t *ref)
{
	if (!ref->refs)
		return false;
	ref->refs++;
	return true;
}

static inline bool refcount_dec_and_test(refcount_t *ref)
{
	ref->refs--;
	return ref->refs == 0;
}

static inline int refcount_read(const refcount_t *ref)
{
	return ref->refs;
}

struct rw_semaphore {
	int locked;
};

#define DECLARE_RWSEM(name) struct rw_semaphore name = { 0 }

static inline void down_write(struct rw_semaphore *sem)
{
	sem->locked = 1;
}

static inline void up_write(struct rw_semaphore *sem)
{
	sem->locked = 0;
}

static inline void down_read(struct rw_semaphore *sem)
{
	(void)sem;
}

static inline void up_read(struct rw_semaphore *sem)
{
	(void)sem;
}

extern bool __bpf_crypto_type_registered;
extern struct bpf_crypto_type_list __bpf_crypto_type_node;

#define LIST_HEAD(name) struct list_head name = { &(name), &(name) }
/* Keep the registry traversal empty. Persisting kernel pointers in BPF global
 * data would dominate this target with verifier pointer-spill limitations; the
 * harness covers registration allocation and create()'s not-found path instead.
 */
#define list_for_each_entry(pos, head, member) \
	for (pos = NULL; pos; pos = NULL)
#define list_add(entry, head) do { \
	(void)(entry); \
	(void)(head); \
	__bpf_crypto_type_registered = true; \
	__bpf_crypto_list_adds++; \
} while (0)
#define list_del(entry) do { \
	(void)(entry); \
	__bpf_crypto_type_registered = false; \
	__bpf_crypto_list_dels++; \
} while (0)

#define MAX_ERRNO 4095
#define ERR_PTR(error) ((void *)(long)(error))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-MAX_ERRNO)

static inline int strcmp(const char *a, const char *b)
{
	int i;

	for (i = 0; i < 128; i++) {
		unsigned char ca = a[i];
		unsigned char cb = b[i];

		if (ca != cb)
			return ca - cb;
		if (!ca)
			break;
	}
	return 0;
}

static inline bool try_module_get(struct module *module)
{
	if (module)
		module->refs++;
	return true;
}

static inline void module_put(struct module *module)
{
	if (module)
		module->refs--;
}

#define call_rcu(head, func) do { (void)(head); (void)(func); } while (0)

struct bpf_dynptr {
	u64 __opaque[2];
} __attribute__((aligned(8)));

struct bpf_dynptr_kern {
	void *data;
	u32 size;
	u32 offset;
} __attribute__((aligned(8)));

static inline bool __bpf_dynptr_is_rdonly(const struct bpf_dynptr_kern *ptr)
{
	return ptr->size & BPF_DYNPTR_RDONLY;
}

static inline u64 __bpf_dynptr_size(const struct bpf_dynptr_kern *ptr)
{
	return ptr->size & BPF_DYNPTR_SIZE_MASK;
}

static inline const void *__bpf_dynptr_data(const struct bpf_dynptr_kern *ptr,
					    u64 len)
{
	if (!ptr->data || len > __bpf_dynptr_size(ptr))
		return NULL;
	return (const unsigned char *)ptr->data + ptr->offset;
}

static inline void *__bpf_dynptr_data_rw(const struct bpf_dynptr_kern *ptr,
					 u64 len)
{
	if (__bpf_dynptr_is_rdonly(ptr))
		return NULL;
	return (void *)__bpf_dynptr_data(ptr, len);
}

#endif /* _LINUX_BPF_H */
