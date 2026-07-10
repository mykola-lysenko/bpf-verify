/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF surface for kernel/bpf/stream.c. */
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
#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

#define __user
#define __bpf_kfunc
#define __bpf_kfunc_start_defs()
#define __bpf_kfunc_end_defs()

#define MAX_BPRINTF_BUF 64
#define MAX_BPRINTF_VARARGS 12
#define BPF_STREAM_MAX_CAPACITY 4096

typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_end(ap) __builtin_va_end(ap)

static inline void atomic_set(atomic_t *v, int i)
{
	v->counter = i;
}

static inline int atomic_read(const atomic_t *v)
{
	return v->counter;
}

static inline int atomic_add_return(int i, atomic_t *v)
{
	v->counter += i;
	return v->counter;
}

static inline void atomic_sub(int i, atomic_t *v)
{
	v->counter -= i;
}

struct mutex {
	int locked;
};

static inline void mutex_init(struct mutex *lock)
{
	lock->locked = 0;
}

static inline void mutex_lock(struct mutex *lock)
{
	lock->locked = 1;
}

static inline void mutex_unlock(struct mutex *lock)
{
	lock->locked = 0;
}

struct llist_node {
	struct llist_node *next;
};

struct llist_head {
	struct llist_node *first;
};

static inline void init_llist_node(struct llist_node *node)
{
	node->next = NULL;
}

static inline void init_llist_head(struct llist_head *head)
{
	head->first = NULL;
}

static inline bool llist_empty(const struct llist_head *head)
{
	return head->first == NULL;
}

static inline bool llist_add_batch(struct llist_node *first,
				   struct llist_node *last,
				   struct llist_head *head)
{
	last->next = head->first;
	head->first = first;
	return last->next == NULL;
}

static inline bool llist_add(struct llist_node *node, struct llist_head *head)
{
	return llist_add_batch(node, node, head);
}

static inline struct llist_node *llist_del_all(struct llist_head *head)
{
	struct llist_node *first = head->first;

	head->first = NULL;
	return first;
}

static inline struct llist_node *llist_reverse_order(struct llist_node *head)
{
	return head;
}

static inline struct llist_node *llist_next(struct llist_node *node)
{
	(void)node;
	return NULL;
}

#define llist_for_each_entry_safe(pos, n, node, member) \
	for (pos = (node) ? container_of((node), typeof(*pos), member) : NULL, \
	     n = NULL; pos; pos = NULL)

struct bpf_stream_elem {
	struct llist_node node;
	int total_len;
	int consumed_len;
	char str[MAX_BPRINTF_BUF];
};

struct bpf_stream {
	atomic_t capacity;
	struct llist_head log;
	struct mutex lock;
	struct llist_node *backlog_head;
	struct llist_node *backlog_tail;
};

enum bpf_stream_id {
	BPF_STDOUT = 1,
	BPF_STDERR = 2,
};

struct bpf_prog;

struct bpf_prog_aux {
	struct bpf_stream stream[2];
	struct bpf_prog_aux *main_prog_aux;
	struct bpf_prog *prog;
};

struct bpf_prog {
	struct bpf_prog_aux *aux;
};

struct bpf_stream_stage {
	struct llist_head log;
	int len;
};

struct bpf_bprintf_buffers {
	char buf[MAX_BPRINTF_BUF];
	u64 bin_args[MAX_BPRINTF_VARARGS];
};

struct bpf_bprintf_data {
	bool get_bin_args;
	bool get_buf;
	char *buf;
	u64 *bin_args;
};

struct cred {
	struct {
		u32 val;
	} euid;
};

struct task_struct {
	int pid;
	char comm[16];
};

static struct task_struct __bpf_stream_current = {
	.pid = 1,
	.comm = "bpf-stream",
};
static struct cred __bpf_stream_cred = {
	.euid = { .val = 0 },
};

#define current (&__bpf_stream_current)
#define __kuid_val(kuid) ((kuid).val)

static inline const struct cred *current_real_cred(void)
{
	return &__bpf_stream_cred;
}

static inline int raw_smp_processor_id(void)
{
	return 0;
}

static inline size_t __bpf_stream_strlen(const char *s)
{
	size_t i;

	for (i = 0; i < MAX_BPRINTF_BUF; i++) {
		if (!s[i])
			break;
	}
	return i;
}

static inline void *__bpf_stream_memcpy(void *dst, const void *src, size_t len)
{
	unsigned char *d = dst;
	const unsigned char *s = src;
	size_t i;

	for (i = 0; i < len && i < MAX_BPRINTF_BUF; i++)
		d[i] = s[i];
	return dst;
}

static inline int __bpf_stream_copy_to_user(void *dst, const void *src,
					    size_t len)
{
	__bpf_stream_memcpy(dst, src, len);
	return 0;
}

#define strlen(s) __bpf_stream_strlen(s)
#define memcpy(dst, src, len) __bpf_stream_memcpy((dst), (src), (len))
#define copy_to_user(dst, src, len) \
	__bpf_stream_copy_to_user((dst), (src), (len))

static struct bpf_bprintf_buffers __bpf_stream_buffers;

static inline int bpf_try_get_buffers(struct bpf_bprintf_buffers **buf)
{
	*buf = &__bpf_stream_buffers;
	return 0;
}

static inline void bpf_put_buffers(void)
{
}

static inline int bpf_bprintf_prepare(const char *fmt, u32 fmt_size,
				      const void *args, int num_args,
				      struct bpf_bprintf_data *data)
{
	(void)fmt;
	(void)fmt_size;
	(void)num_args;
	data->buf = __bpf_stream_buffers.buf;
	data->bin_args = (u64 *)args;
	return 0;
}

static inline void bpf_bprintf_cleanup(struct bpf_bprintf_data *data)
{
	(void)data;
}

static inline int bstr_printf(char *buf, size_t size, const char *fmt,
			      const u64 *bin_args)
{
	size_t i;

	(void)bin_args;
	for (i = 0; i + 1 < size && i < MAX_BPRINTF_BUF; i++) {
		if (!fmt[i])
			break;
		buf[i] = fmt[i];
	}
	if (size)
		buf[i < size ? i : size - 1] = '\0';
	return i;
}

static inline int vsnprintf(char *buf, size_t size, const char *fmt,
			    va_list args)
{
	(void)args;
	return bstr_printf(buf, size, fmt, NULL);
}

static inline struct bpf_prog *bpf_prog_ksym_find(u64 ip)
{
	(void)ip;
	return NULL;
}

static inline int bpf_prog_get_file_line(struct bpf_prog *prog, u64 ip,
					 const char **file,
					 const char **line, int *num)
{
	(void)prog;
	(void)ip;
	*file = "";
	*line = "";
	*num = 0;
	return -ENOENT;
}

static inline void rcu_read_lock(void)
{
}

static inline void rcu_read_unlock(void)
{
}

static inline void arch_bpf_stack_walk(bool (*cb)(void *cookie, u64 ip,
						  u64 sp, u64 bp),
				       void *cookie)
{
	(void)cb;
	(void)cookie;
}

#define __bpf_stream_internal __attribute__((internal_linkage))
__bpf_stream_internal void bpf_stream_stage_init(struct bpf_stream_stage *ss);
__bpf_stream_internal void bpf_stream_stage_free(struct bpf_stream_stage *ss);
__bpf_stream_internal int bpf_stream_stage_commit(struct bpf_stream_stage *ss,
						  struct bpf_prog *prog,
						  enum bpf_stream_id stream_id);
__bpf_stream_internal int bpf_stream_stage_dump_stack(struct bpf_stream_stage *ss);

#define bpf_stream_dump_stack(ss) bpf_stream_stage_dump_stack(&(ss))
#define bpf_stream_stage(ss, prog, stream_id, body) do { \
	bpf_stream_stage_init(&(ss)); \
	body; \
	bpf_stream_stage_commit(&(ss), (prog), (stream_id)); \
	bpf_stream_stage_free(&(ss)); \
} while (0)

#endif /* _LINUX_BPF_H */
