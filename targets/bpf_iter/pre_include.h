#include <linux/errno.h>
#define _LINUX_FS_H
#define _LINUX_ANON_INODES_H
#define __LINUX_FILTER_H__
#define _LINUX_BPF_H 1
#define __LINUX_RCUPDATE_TRACE_H
#define __user
#define __aligned(x) __attribute__((aligned(x)))
#define __init
#define __bpf_kfunc
#define __bpf_kfunc_start_defs()
#define __bpf_kfunc_end_defs()
#define PAGE_SIZE 4096
#define GFP_KERNEL 0
#define GFP_USER 0
#define __GFP_NOWARN 0
#define O_RDONLY 0
#define O_CLOEXEC 0
#define BPF_LINK_TYPE_ITER 1
#define BPF_MAX_LOOPS 16
#define BPF_ITER_RESCHED 1
#define BPF_ITER_FUNC_PREFIX "bpf_iter_"
#define RET_INTEGER 1
#define ARG_CONST_MAP_PTR 1
#define ARG_PTR_TO_FUNC 2
#define ARG_PTR_TO_STACK_OR_NULL 3
#define ARG_ANYTHING 4
#define PTR_TO_BTF_ID_OR_NULL 1
#define PTR_TRUSTED 2
#define PTR_TO_BUF 4
#define PTR_MAYBE_NULL 8
#define MEM_RDONLY 16
#define ERR_PTR(error) ((void *)(long)(error))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-4095)
#define IS_ERR_OR_NULL(ptr) (!(ptr) || IS_ERR(ptr))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define xchg(ptr, val) ({ typeof(*(ptr)) __old = *(ptr); *(ptr) = (val); __old; })
#define pr_info_ratelimited(fmt, ...) do { } while (0)
#define cond_resched() do { } while (0)
#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define DEFINE_MUTEX(name) struct mutex name
#define atomic64_inc_return(v) (++((v)->counter))
#define seq_has_overflowed(seq) ((seq)->count > (seq)->size)
#define BPF_CALL_4(name, t1, a1, t2, a2, t3, a3, t4, a4)     static u64 name(t1 a1, t2 a2, t3 a3, t4 a4)
#define BUILD_BUG_ON(cond) do { } while (0)
#ifndef container_of
#define container_of(ptr, type, member)     ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
#endif

typedef long ssize_t;
typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);
struct mutex {
    u32 locked;
};
struct inode {
    void *i_private;
};
struct file;
struct file_operations {
    int (*open)(struct inode *inode, struct file *file);
    ssize_t (*read)(struct file *file, char __user *buf, size_t size,
                    loff_t *ppos);
    int (*release)(struct inode *inode, struct file *file);
};
struct file {
    void *private_data;
    struct inode *f_inode;
    const struct file_operations *f_op;
};
struct seq_file;
struct bpf_iter_aux_info;
struct seq_operations {
    void *(*start)(struct seq_file *seq, loff_t *pos);
    void *(*next)(struct seq_file *seq, void *v, loff_t *pos);
    void (*stop)(struct seq_file *seq, void *v);
    int (*show)(struct seq_file *seq, void *v);
};
struct seq_file {
    void *private;
    struct mutex lock;
    char *buf;
    size_t size;
    size_t count;
    size_t from;
    loff_t index;
    const struct seq_operations *op;
    struct file *file;
};
struct bpf_iter_meta {
    struct seq_file *seq;
    u64 session_id;
    u64 seq_num;
};
struct bpf_ctx_arg_aux {
    u32 offset;
    u32 reg_type;
    u32 btf_id;
};
struct bpf_iter_seq_info {
    const struct seq_operations *seq_ops;
    int (*init_seq_private)(void *priv, struct bpf_iter_aux_info *aux);
    void (*fini_seq_private)(void *priv);
    u32 seq_priv_size;
};
struct bpf_prog_aux {
    u32 attach_btf_id;
    const char *attach_func_name;
};
struct bpf_prog {
    struct bpf_prog_aux *aux;
    u32 type;
    u32 expected_attach_type;
    bool sleepable;
};
struct bpf_map;
struct bpf_map_ops {
    const struct bpf_iter_seq_info *iter_seq_info;
    int (*map_for_each_callback)(struct bpf_map *map, void *callback_fn,
                                 void *callback_ctx, u64 flags);
};
struct bpf_map {
    const struct bpf_map_ops *ops;
};
struct bpf_iter_aux_info {
    struct bpf_map *map;
};
union bpf_iter_link_info {
    struct {
        u32 map_fd;
    } map;
};
struct bpf_link_info {
    struct {
        u64 target_name;
        u32 target_name_len;
    } iter;
};
enum bpf_func_id {
    BPF_FUNC_unspec = 0,
};
struct bpf_func_proto {
    void *func;
    bool gpl_only;
    int ret_type;
    int arg1_type;
    int arg2_type;
    int arg3_type;
    int arg4_type;
};
typedef int (*bpf_iter_attach_target_t)(struct bpf_prog *prog,
                                        union bpf_iter_link_info *linfo,
                                        struct bpf_iter_aux_info *aux);
typedef void (*bpf_iter_detach_target_t)(struct bpf_iter_aux_info *aux);
typedef void (*bpf_iter_show_fdinfo_t)(const struct bpf_iter_aux_info *aux,
                                       struct seq_file *seq);
typedef int (*bpf_iter_fill_link_info_t)(const struct bpf_iter_aux_info *aux,
                                         struct bpf_link_info *info);
typedef const struct bpf_func_proto *
(*bpf_iter_get_func_proto_t)(enum bpf_func_id func_id,
                             const struct bpf_prog *prog);
struct bpf_iter_reg {
    const char *target;
    bpf_iter_attach_target_t attach_target;
    bpf_iter_detach_target_t detach_target;
    bpf_iter_show_fdinfo_t show_fdinfo;
    bpf_iter_fill_link_info_t fill_link_info;
    bpf_iter_get_func_proto_t get_func_proto;
    u32 ctx_arg_info_size;
    u32 feature;
    struct bpf_ctx_arg_aux ctx_arg_info[4];
    const struct bpf_iter_seq_info *seq_info;
};
struct bpf_link;
struct bpf_link_ops {
    void (*release)(struct bpf_link *link);
    void (*dealloc)(struct bpf_link *link);
    int (*update_prog)(struct bpf_link *link, struct bpf_prog *new_prog,
                       struct bpf_prog *old_prog);
    void (*show_fdinfo)(const struct bpf_link *link, struct seq_file *seq);
    int (*fill_link_info)(const struct bpf_link *link,
                          struct bpf_link_info *info);
};
struct bpf_link {
    const struct bpf_link_ops *ops;
    struct bpf_prog *prog;
    u32 type;
    u32 attach_type;
};
struct bpf_link_primer {
    struct bpf_link *link;
};
union bpf_attr {
    struct {
        u32 target_fd;
        u32 flags;
        u64 iter_info;
        u32 iter_info_len;
        u32 attach_type;
    } link_create;
};
typedef struct {
    void *ptr;
    bool is_kernel;
} bpfptr_t;
struct fd_prepare {
    int err;
    int fd;
    struct file *file;
};
struct bpf_run_ctx {
    u32 dummy;
};
struct bpf_iter_num {
    __u64 __opaque[1];
} __aligned(8);

static u64 __bpf_iter_core_alloc_storage[64];
static char __bpf_iter_core_seq_buf[PAGE_SIZE];
static struct file __bpf_iter_core_file;
static struct inode __bpf_iter_core_inode;
static volatile u32 __bpf_iter_core_allocs;
static volatile u32 __bpf_iter_core_frees;
static volatile u32 __bpf_iter_core_prog_puts;
static volatile u32 __bpf_iter_core_prog_incs;
static volatile u32 __bpf_iter_core_link_sets;

static inline void __bpf_iter_core_reset(void)
{
    __bpf_iter_core_allocs = 0;
    __bpf_iter_core_frees = 0;
    __bpf_iter_core_prog_puts = 0;
    __bpf_iter_core_prog_incs = 0;
    __bpf_iter_core_link_sets = 0;
    __bpf_iter_core_file.private_data = 0;
    __bpf_iter_core_file.f_inode = &__bpf_iter_core_inode;
    __bpf_iter_core_file.f_op = 0;
    __bpf_iter_core_inode.i_private = 0;
}
static inline void mutex_lock(struct mutex *mutex)
{
    mutex->locked = 1;
}
static inline void mutex_unlock(struct mutex *mutex)
{
    mutex->locked = 0;
}
static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}
static inline void list_add(struct list_head *entry, struct list_head *head)
{
    entry->next = head->next;
    entry->prev = head;
    head->next->prev = entry;
    head->next = entry;
}
static inline void list_del(struct list_head *entry)
{
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;
    entry->next = entry;
    entry->prev = entry;
}
#define list_for_each_entry(pos, head, member)     for (pos = container_of((head)->next, typeof(*pos), member);          &pos->member != (head);          pos = container_of(pos->member.next, typeof(*pos), member))
static inline void *__bpf_iter_core_alloc(size_t size)
{
    (void)size;
    __bpf_iter_core_allocs++;
    return __bpf_iter_core_alloc_storage;
}
#define kzalloc_obj(obj, ...) __bpf_iter_core_alloc(sizeof(obj))
static inline void kfree(const void *ptr)
{
    (void)ptr;
    __bpf_iter_core_frees++;
}
static inline void *kvmalloc(size_t size, int flags)
{
    (void)flags;
    if (size > sizeof(__bpf_iter_core_seq_buf))
        return 0;
    return __bpf_iter_core_seq_buf;
}
static inline int copy_to_user(void *dst, const void *src, size_t n)
{
    (void)dst;
    (void)src;
    (void)n;
    return 0;
}
static inline int put_user(char value, char *dst)
{
    *dst = value;
    return 0;
}
static inline int __bpf_iter_core_seq_printf(struct seq_file *seq)
{
    seq->count++;
    return 0;
}
#define seq_printf(seq, fmt, ...) __bpf_iter_core_seq_printf(seq)
static inline char *u64_to_user_ptr(u64 value)
{
    return (char *)(long)value;
}
static inline struct file *anon_inode_getfile(const char *name,
                                              const struct file_operations *fops,
                                              void *priv, int flags)
{
    (void)name;
    (void)priv;
    (void)flags;
    __bpf_iter_core_file.f_op = fops;
    return &__bpf_iter_core_file;
}
#define FD_PREPARE(name, flags, file_expr)     struct fd_prepare name = { .err = 0, .fd = 3, .file = (file_expr) }
static inline struct file *fd_prepare_file(struct fd_prepare fdf)
{
    return fdf.file;
}
static inline int fd_publish(struct fd_prepare fdf)
{
    return fdf.fd;
}
static inline struct bpf_iter_priv_data *
__seq_open_private(struct file *file, const struct seq_operations *ops,
                   u32 size)
{
    struct seq_file *seq = (struct seq_file *)__bpf_iter_core_alloc_storage;
    (void)size;
    seq->op = ops;
    seq->file = file;
    seq->buf = 0;
    seq->size = 0;
    seq->count = 0;
    seq->from = 0;
    seq->index = 0;
    file->private_data = seq;
    return (struct bpf_iter_priv_data *)(seq + 1);
}
static inline int seq_release_private(struct inode *inode, struct file *file)
{
    (void)inode;
    file->private_data = 0;
    return 0;
}
static inline void bpf_prog_put(struct bpf_prog *prog)
{
    (void)prog;
    __bpf_iter_core_prog_puts++;
}
static inline void bpf_prog_inc(struct bpf_prog *prog)
{
    (void)prog;
    __bpf_iter_core_prog_incs++;
}
static inline void bpf_link_init(struct bpf_link *link, int type,
                                 const struct bpf_link_ops *ops,
                                 struct bpf_prog *prog, u32 attach_type)
{
    link->type = type;
    link->ops = ops;
    link->prog = prog;
    link->attach_type = attach_type;
}
static inline int bpf_link_prime(struct bpf_link *link,
                                 struct bpf_link_primer *primer)
{
    primer->link = link;
    return 0;
}
static inline void bpf_link_cleanup(struct bpf_link_primer *primer)
{
    primer->link = 0;
}
static inline int bpf_link_settle(struct bpf_link_primer *primer)
{
    (void)primer;
    __bpf_iter_core_link_sets++;
    return 5;
}
static inline bpfptr_t make_bpfptr(u64 value, bool is_kernel)
{
    bpfptr_t ptr = { .ptr = (void *)(long)value, .is_kernel = is_kernel };
    return ptr;
}
static inline bool bpfptr_is_null(bpfptr_t ptr)
{
    return !ptr.ptr;
}
static inline int bpf_check_uarg_tail_zero(bpfptr_t ptr, u32 size, u32 len)
{
    (void)ptr;
    (void)size;
    (void)len;
    return 0;
}
static inline int copy_from_bpfptr(void *dst, bpfptr_t src, u32 len)
{
    char *d = dst;
    u32 i;

    (void)src;
    (void)len;
    for (i = 0; i < sizeof(union bpf_iter_link_info); i++)
        d[i] = 0;
    return 0;
}
static inline int bpf_prog_ctx_arg_info_init(struct bpf_prog *prog,
                                             struct bpf_ctx_arg_aux *info,
                                             u32 nr)
{
    (void)prog;
    (void)info;
    return (int)nr;
}
static inline struct bpf_run_ctx *bpf_set_run_ctx(struct bpf_run_ctx *run_ctx)
{
    return run_ctx;
}
static inline void bpf_reset_run_ctx(struct bpf_run_ctx *run_ctx)
{
    (void)run_ctx;
}
static inline int bpf_prog_run(struct bpf_prog *prog, void *ctx)
{
    (void)prog;
    (void)ctx;
    return 0;
}
static inline void rcu_read_lock_trace(void) {}
static inline void rcu_read_unlock_trace(void) {}
static inline void rcu_read_lock_dont_migrate(void) {}
static inline void rcu_read_unlock_migrate(void) {}
static inline void migrate_disable(void) {}
static inline void migrate_enable(void) {}
static inline void might_fault(void) {}
static inline int strlen(const char *s)
{
    int n = 0;
    while (s[n])
        n++;
    return n;
}
static inline int strcmp(const char *a, const char *b)
{
    int i = 0;
    while (a[i] && a[i] == b[i])
        i++;
    return (unsigned char)a[i] - (unsigned char)b[i];
}
static inline int strncmp(const char *a, const char *b, size_t n)
{
    size_t i = 0;
    while (i < n && a[i] && a[i] == b[i])
        i++;
    if (i == n)
        return 0;
    return (unsigned char)a[i] - (unsigned char)b[i];
}
static inline void *__bpf_iter_core_memset(void *dst, int c, size_t n)
{
    char *d = dst;
    while (n--)
        *d++ = (char)c;
    return dst;
}
#define memset(dst, c, n) __bpf_iter_core_memset((dst), (c), (n))
