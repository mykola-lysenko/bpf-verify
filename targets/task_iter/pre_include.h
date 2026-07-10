#include <linux/errno.h>
#define _LINUX_BPF_H 1
#define _LINUX_FS_H
#define __LINUX_FILTER_H__
#define _LINUX_KERNEL_H
#define _LINUX_BTF_IDS_H
#define __DMA_BUF_H__
#define _LINUX_SEQ_FILE_H
#define __init
#define __bpf_kfunc
#define __bpf_kfunc_start_defs()
#define __bpf_kfunc_end_defs()
#define __bpf_md_ptr(type, name) type name
#define __aligned(x) __attribute__((aligned(x)))
#define DEFINE_BPF_ITER_FUNC(target, args...) int bpf_iter_ ## target(args) { return 0; }
#define BTF_ID_LIST_SINGLE(name, prefix, typename) static u32 name[1];
#define BTF_ID_LIST_GLOBAL_SINGLE(name, prefix, typename) static u32 name[1];
#define BTF_KFUNCS_START(name) static u32 name[] = {
#define BTF_ID_FLAGS(kind, name) 0,
#define BTF_KFUNCS_END(name) };
#define late_initcall(fn)
#define THIS_MODULE ((void *)0)
#define offsetof(type, member) __builtin_offsetof(type, member)
#define READ_ONCE(x) (x)
#define BUILD_BUG_ON(cond) do { } while (0)
#define PTR_TO_BTF_ID_OR_NULL 1
#define PTR_TRUSTED 2
#define PTR_TO_BUF 4
#define PTR_MAYBE_NULL 8
#define MEM_RDONLY 16
#define BPF_ITER_RESCHED 1
#define BPF_PROG_TYPE_UNSPEC 0
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_HASH 3
#define BPF_MAP_TYPE_PERCPU_ARRAY 4
#define BPF_MAP_TYPE_LRU_HASH 5
#define BPF_MAP_TYPE_LRU_PERCPU_HASH 6
#define BPF_MAP_TYPE_RHASH 7
#define ERR_PTR(error) ((void *)(long)(error))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-4095)
#define round_up(x, y) ((((x) + (y) - 1) / (y)) * (y))
#define num_possible_cpus() 2
#define for_each_possible_cpu(cpu) for ((cpu) = 0; (cpu) < 2; (cpu)++)
#define per_cpu_ptr(ptr, cpu) (&((ptr)[cpu]))

struct seq_file {
    void *private;
    u32 writes;
};
struct seq_operations {
    void *(*start)(struct seq_file *seq, loff_t *pos);
    void *(*next)(struct seq_file *seq, void *v, loff_t *pos);
    void (*stop)(struct seq_file *seq, void *v);
    int (*show)(struct seq_file *seq, void *v);
};
struct bpf_iter_meta {
    struct seq_file *seq;
    u64 session_id;
    u64 seq_num;
};
struct bpf_map;
struct cgroup;
struct bpf_iter__bpf_map_elem {
    __bpf_md_ptr(struct bpf_iter_meta *, meta);
    __bpf_md_ptr(struct bpf_map *, map);
    __bpf_md_ptr(void *, key);
    __bpf_md_ptr(void *, value);
};
struct bpf_ctx_arg_aux {
    u32 offset;
    u32 reg_type;
    u32 btf_id;
};
struct bpf_prog;
struct bpf_iter_aux_info;
struct bpf_link_info;
union bpf_iter_link_info;
struct bpf_iter_seq_info {
    const struct seq_operations *seq_ops;
    int (*init_seq_private)(void *priv, struct bpf_iter_aux_info *aux);
    void (*fini_seq_private)(void *priv);
    u32 seq_priv_size;
};
struct bpf_iter_reg {
    const char *target;
    int (*attach_target)(struct bpf_prog *prog,
                         union bpf_iter_link_info *linfo,
                         struct bpf_iter_aux_info *aux);
    void (*detach_target)(struct bpf_iter_aux_info *aux);
    void (*show_fdinfo)(const struct bpf_iter_aux_info *aux,
                        struct seq_file *seq);
    int (*fill_link_info)(const struct bpf_iter_aux_info *aux,
                          struct bpf_link_info *info);
    const void *get_func_proto;
    u32 ctx_arg_info_size;
    u32 feature;
    struct bpf_ctx_arg_aux ctx_arg_info[4];
    const struct bpf_iter_seq_info *seq_info;
};
struct bpf_prog_aux {
    u32 max_rdonly_access;
    u32 max_rdwr_access;
    u32 attach_btf_id;
    const char *attach_func_name;
};
struct bpf_prog {
    struct bpf_prog_aux *aux;
    u32 type;
    u32 expected_attach_type;
    bool sleepable;
};
struct bpf_map_ops {
    const struct bpf_iter_seq_info *iter_seq_info;
};
struct bpf_map {
    const struct bpf_map_ops *ops;
    u32 id;
    u32 map_type;
    u32 key_size;
    u32 value_size;
    s64 *elem_count;
    char *excl_prog_sha;
};
struct bpf_link {
    const void *ops;
    struct bpf_prog *prog;
    u32 id;
};
struct dma_buf {
    u32 id;
};
enum bpf_iter_task_type {
    BPF_TASK_ITER_ALL = 0,
    BPF_TASK_ITER_TID,
    BPF_TASK_ITER_TGID,
};
struct bpf_iter_aux_info {
    struct bpf_map *map;
    struct {
        struct cgroup *start;
        int order;
    } cgroup;
    struct {
        enum bpf_iter_task_type type;
        u32 pid;
    } task;
};
union bpf_iter_link_info {
    struct {
        u32 map_fd;
    } map;
    struct {
        u32 order;
        u32 cgroup_fd;
        u64 cgroup_id;
    } cgroup;
    struct {
        u32 tid;
        u32 pid;
        u32 pid_fd;
    } task;
};
struct bpf_link_info {
    struct {
        u64 target_name;
        u32 target_name_len;
        struct {
            u32 map_id;
        } map;
        struct {
            u32 order;
            u64 cgroup_id;
        } cgroup;
        struct {
            u32 tid;
            u32 pid;
        } task;
    } iter;
};
struct btf_kfunc_id_set {
    void *owner;
    const void *set;
};

static struct bpf_prog_aux __bpf_iter_driver_aux;
static struct bpf_prog __bpf_iter_driver_prog = { .aux = &__bpf_iter_driver_aux };
static struct bpf_prog __bpf_iter_prog0;
static struct bpf_link __bpf_iter_link0;
static s64 __bpf_iter_elem_counts[2];
static struct bpf_map __bpf_iter_map0;
static struct dma_buf __bpf_iter_dmabuf0;
static struct dma_buf __bpf_iter_dmabuf1;
static volatile u32 __bpf_iter_runs;
static volatile u32 __bpf_iter_regs;
static volatile u32 __bpf_iter_kfunc_regs;
static volatile u32 __bpf_iter_prog_puts;
static volatile u32 __bpf_iter_link_puts;
static volatile u32 __bpf_iter_map_puts;
static volatile u32 __bpf_iter_map_puts_uref;
static volatile u32 __bpf_iter_dmabuf_puts;

static inline void __bpf_iter_reset(void)
{
    __bpf_iter_runs = 0;
    __bpf_iter_regs = 0;
    __bpf_iter_kfunc_regs = 0;
    __bpf_iter_prog_puts = 0;
    __bpf_iter_link_puts = 0;
    __bpf_iter_map_puts = 0;
    __bpf_iter_map_puts_uref = 0;
    __bpf_iter_dmabuf_puts = 0;
    __bpf_iter_prog0.aux = &__bpf_iter_driver_aux;
    __bpf_iter_link0.id = 1;
    __bpf_iter_map0.ops = 0;
    __bpf_iter_map0.id = 1234;
    __bpf_iter_map0.map_type = BPF_MAP_TYPE_HASH;
    __bpf_iter_map0.key_size = 4;
    __bpf_iter_map0.value_size = 8;
    __bpf_iter_map0.elem_count = 0;
    __bpf_iter_elem_counts[0] = 0;
    __bpf_iter_elem_counts[1] = 0;
    __bpf_iter_dmabuf0.id = 1;
    __bpf_iter_dmabuf1.id = 2;
}

static inline struct bpf_prog *bpf_iter_get_info(struct bpf_iter_meta *meta,
                                                 bool in_stop)
{
    (void)meta;
    (void)in_stop;
    return &__bpf_iter_driver_prog;
}
static inline int bpf_iter_run_prog(struct bpf_prog *prog, void *ctx)
{
    (void)prog;
    (void)ctx;
    __bpf_iter_runs++;
    return 7;
}
static inline int bpf_iter_reg_target(const struct bpf_iter_reg *reg_info)
{
    (void)reg_info;
    __bpf_iter_regs++;
    return 0;
}
static inline struct bpf_prog *bpf_prog_get_curr_or_next(u32 *id)
{
    if (*id <= 1)
        return &__bpf_iter_prog0;
    return 0;
}
static inline void bpf_prog_put(struct bpf_prog *prog)
{
    (void)prog;
    __bpf_iter_prog_puts++;
}
static inline struct bpf_link *bpf_link_get_curr_or_next(u32 *id)
{
    if (*id <= 1)
        return &__bpf_iter_link0;
    return 0;
}
static inline void bpf_link_put(struct bpf_link *link)
{
    (void)link;
    __bpf_iter_link_puts++;
}
static inline struct bpf_map *bpf_map_get_curr_or_next(u32 *id)
{
    if (*id <= 1)
        return &__bpf_iter_map0;
    return 0;
}
static inline void bpf_map_put(struct bpf_map *map)
{
    (void)map;
    __bpf_iter_map_puts++;
}
static inline struct bpf_map *bpf_map_get_with_uref(u32 fd)
{
    if (fd == 1)
        return &__bpf_iter_map0;
    return ERR_PTR(-EBADF);
}
static inline void bpf_map_put_with_uref(struct bpf_map *map)
{
    (void)map;
    __bpf_iter_map_puts_uref++;
}
static inline int __bpf_iter_seq_write(struct seq_file *seq)
{
    seq->writes++;
    return 0;
}
#define seq_printf(seq, fmt, ...) __bpf_iter_seq_write(seq)
#define seq_puts(seq, str) __bpf_iter_seq_write(seq)
static inline int register_btf_kfunc_id_set(int prog_type,
                                            const struct btf_kfunc_id_set *set)
{
    (void)prog_type;
    (void)set;
    __bpf_iter_kfunc_regs++;
    return 0;
}
static inline struct dma_buf *dma_buf_iter_begin(void)
{
    return &__bpf_iter_dmabuf0;
}
static inline struct dma_buf *dma_buf_iter_next(struct dma_buf *dmabuf)
{
    if (dmabuf == &__bpf_iter_dmabuf0)
        return &__bpf_iter_dmabuf1;
    return 0;
}
static inline void dma_buf_put(struct dma_buf *dmabuf)
{
    (void)dmabuf;
    __bpf_iter_dmabuf_puts++;
}
#define _LINUX_INIT_H
#define _LINUX_NAMEI_H
#define _LINUX_PID_NS_H
#define _BPF_MEM_ALLOC_H
#define _LINUX_MM_TYPES_H
#define _LINUX_MMAP_LOCK_H
#define _LINUX_SCHED_MM_H
#define __MMAP_UNLOCK_WORK_H__
#undef CONFIG_CGROUPS
#undef CONFIG_MMU
#undef per_cpu_ptr
#define per_cpu_ptr(ptr, cpu) (ptr)
#define DEFINE_PER_CPU(type, name) static type name
#define PIDTYPE_TGID 0
#define PIDTYPE_PID 1
#define PF_KTHREAD 0x00200000UL
#define PAGE_SIZE 4096UL
#define CSS_TASK_ITER_PROCS 1
#define CSS_TASK_ITER_THREADED 2
#define RET_INTEGER 1
#define ARG_PTR_TO_BTF_ID 1
#define ARG_ANYTHING 2
#define ARG_PTR_TO_FUNC 3
#define ARG_PTR_TO_STACK_OR_NULL 4
#define BTF_TRACING_TYPE_TASK 0
#define BTF_TRACING_TYPE_FILE 1
#define BTF_TRACING_TYPE_VMA 2
#define MAX_BTF_TRACING_TYPE 3
#define BPF_CALL_5(name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)     static u64 name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5)
#define thread_group_leader(task) true
#ifndef container_of
#define container_of(ptr, type, member)     ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
#endif

typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);
typedef struct {
    u32 locked;
} spinlock_t;
struct pid_namespace {
    u32 id;
    u32 refs;
};
struct pid {
    u32 nr;
};
struct file {
    u32 id;
    u32 refs;
};
struct files_struct {
    struct file *file;
};
struct mm_struct {
    u32 users;
};
struct vm_area_struct {
    unsigned long vm_start;
    unsigned long vm_end;
    struct file *vm_file;
    struct mm_struct *vm_mm;
};
struct task_struct {
    struct files_struct *files;
    struct task_struct *group_leader;
    struct task_struct *next_thread;
    struct mm_struct *mm;
    unsigned long flags;
    spinlock_t alloc_lock;
    u32 pid;
    u32 refs;
};
struct irq_work {
    u32 busy;
};
struct mmap_unlock_irq_work {
    struct irq_work irq_work;
    struct mm_struct *mm;
};
struct bpf_mem_alloc {
    u32 dummy;
};
struct vma_iterator {
    struct mm_struct *mm;
    unsigned long addr;
};
struct bpf_func_proto {
    void *func;
    bool gpl_only;
    int ret_type;
    int arg1_type;
    int arg2_type;
    int arg3_type;
    int arg4_type;
    int arg5_type;
    const u32 *arg1_btf_id;
};

static u32 btf_tracing_ids[MAX_BTF_TRACING_TYPE] = { 1, 2, 3 };
static struct pid_namespace __bpf_iter_pid_ns = { .id = 1, .refs = 1 };
static struct pid __bpf_iter_pid = { .nr = 1 };
static struct file __bpf_iter_file = { .id = 7, .refs = 1 };
static struct files_struct __bpf_iter_files = { .file = &__bpf_iter_file };
static struct mm_struct __bpf_iter_mm = { .users = 1 };
static struct vm_area_struct __bpf_iter_vma = {
    .vm_start = 0x1000,
    .vm_end = 0x2000,
    .vm_file = &__bpf_iter_file,
    .vm_mm = &__bpf_iter_mm,
};
static struct task_struct init_task;
static struct task_struct __bpf_iter_task0;
static struct bpf_mem_alloc bpf_global_ma;
static u64 __bpf_iter_task_vma_storage[16];
static volatile u32 __bpf_iter_task_gets;
static volatile u32 __bpf_iter_task_puts;
static volatile u32 __bpf_iter_file_gets;
static volatile u32 __bpf_iter_file_puts;
static volatile u32 __bpf_iter_pid_ns_gets;
static volatile u32 __bpf_iter_pid_ns_puts;
static volatile u32 __bpf_iter_mm_gets;
static volatile u32 __bpf_iter_mm_puts;
static volatile u32 __bpf_iter_vma_callbacks;

#define current (&__bpf_iter_task0)

static inline void __bpf_iter_task_reset(void)
{
    __bpf_iter_reset();
    __bpf_iter_task_gets = 0;
    __bpf_iter_task_puts = 0;
    __bpf_iter_file_gets = 0;
    __bpf_iter_file_puts = 0;
    __bpf_iter_pid_ns_gets = 0;
    __bpf_iter_pid_ns_puts = 0;
    __bpf_iter_mm_gets = 0;
    __bpf_iter_mm_puts = 0;
    __bpf_iter_vma_callbacks = 0;
    init_task.files = &__bpf_iter_files;
    init_task.group_leader = &init_task;
    init_task.next_thread = 0;
    init_task.mm = &__bpf_iter_mm;
    init_task.flags = 0;
    init_task.alloc_lock.locked = 0;
    init_task.pid = 0;
    init_task.refs = 1;
    __bpf_iter_task0.files = &__bpf_iter_files;
    __bpf_iter_task0.group_leader = &__bpf_iter_task0;
    __bpf_iter_task0.next_thread = 0;
    __bpf_iter_task0.mm = &__bpf_iter_mm;
    __bpf_iter_task0.flags = 0;
    __bpf_iter_task0.alloc_lock.locked = 0;
    __bpf_iter_task0.pid = 1;
    __bpf_iter_task0.refs = 1;
    __bpf_iter_file.refs = 1;
    __bpf_iter_mm.users = 1;
}
static inline void rcu_read_lock(void) {}
static inline void rcu_read_unlock(void) {}
static inline struct pid *find_pid_ns(u32 nr, struct pid_namespace *ns)
{
    (void)ns;
    if (nr <= 1)
        return &__bpf_iter_pid;
    return 0;
}
static inline struct pid *find_ge_pid(u32 nr, struct pid_namespace *ns)
{
    return find_pid_ns(nr <= 1 ? 1 : nr, ns);
}
static inline u32 pid_nr_ns(struct pid *pid, struct pid_namespace *ns)
{
    (void)ns;
    return pid ? pid->nr : 0;
}
static inline struct task_struct *get_pid_task(struct pid *pid, int type)
{
    (void)type;
    if (!pid)
        return 0;
    __bpf_iter_task0.refs++;
    __bpf_iter_task_gets++;
    return &__bpf_iter_task0;
}
static inline struct task_struct *find_task_by_pid_ns(u32 nr,
                                                      struct pid_namespace *ns)
{
    (void)ns;
    if (nr == 1)
        return &__bpf_iter_task0;
    return 0;
}
static inline struct task_struct *__next_thread(struct task_struct *task)
{
    return task->next_thread;
}
static inline u32 __task_pid_nr_ns(struct task_struct *task, int type,
                                   struct pid_namespace *ns)
{
    (void)type;
    (void)ns;
    return task ? task->pid : 0;
}
static inline struct task_struct *get_task_struct(struct task_struct *task)
{
    task->refs++;
    __bpf_iter_task_gets++;
    return task;
}
static inline struct task_struct *get_task_struct_rcu(struct task_struct *task)
{
    get_task_struct(task);
    return task;
}
static inline void put_task_struct(struct task_struct *task)
{
    if (task && task->refs)
        task->refs--;
    __bpf_iter_task_puts++;
}
static inline struct pid *pidfd_get_pid(int fd, unsigned int *flags)
{
    *flags = 0;
    if (fd == 1)
        return &__bpf_iter_pid;
    return ERR_PTR(-EBADF);
}
static inline void put_pid(struct pid *pid)
{
    (void)pid;
}
static inline struct pid_namespace *task_active_pid_ns(struct task_struct *task)
{
    (void)task;
    return &__bpf_iter_pid_ns;
}
static inline struct task_struct *next_task(struct task_struct *task)
{
    if (task == &init_task)
        return &__bpf_iter_task0;
    return &init_task;
}
static inline struct file *fget_task_next(struct task_struct *task,
                                          unsigned int *fd)
{
    (void)task;
    if (*fd <= 1) {
        *fd = 1;
        __bpf_iter_file.refs++;
        __bpf_iter_file_gets++;
        return &__bpf_iter_file;
    }
    return 0;
}
static inline void fput(struct file *file)
{
    if (file && file->refs)
        file->refs--;
    __bpf_iter_file_puts++;
}
static inline void get_file(struct file *file)
{
    if (file)
        file->refs++;
    __bpf_iter_file_gets++;
}
static inline struct pid_namespace *get_pid_ns(struct pid_namespace *ns)
{
    ns->refs++;
    __bpf_iter_pid_ns_gets++;
    return ns;
}
static inline void put_pid_ns(struct pid_namespace *ns)
{
    if (ns->refs)
        ns->refs--;
    __bpf_iter_pid_ns_puts++;
}
static inline struct mm_struct *get_task_mm(struct task_struct *task)
{
    (void)task;
    __bpf_iter_mm.users++;
    __bpf_iter_mm_gets++;
    return &__bpf_iter_mm;
}
static inline void mmput(struct mm_struct *mm)
{
    if (mm && mm->users)
        mm->users--;
    __bpf_iter_mm_puts++;
}
static inline void mmput_async(struct mm_struct *mm)
{
    mmput(mm);
}
static inline void mmget(struct mm_struct *mm)
{
    mm->users++;
    __bpf_iter_mm_gets++;
}
static inline int mmap_read_lock_killable(struct mm_struct *mm)
{
    (void)mm;
    return 0;
}
static inline bool mmap_read_trylock(struct mm_struct *mm)
{
    (void)mm;
    return true;
}
static inline void mmap_read_unlock(struct mm_struct *mm)
{
    (void)mm;
}
static inline void mmap_read_unlock_non_owner(struct mm_struct *mm)
{
    (void)mm;
}
static inline bool mmap_lock_is_contended(struct mm_struct *mm)
{
    (void)mm;
    return false;
}
static inline struct vm_area_struct *find_vma(struct mm_struct *mm,
                                              unsigned long addr)
{
    (void)mm;
    if (addr < __bpf_iter_vma.vm_end)
        return &__bpf_iter_vma;
    return 0;
}
static inline void vma_iter_init(struct vma_iterator *vmi,
                                 struct mm_struct *mm,
                                 unsigned long addr)
{
    vmi->mm = mm;
    vmi->addr = addr;
}
static inline struct vm_area_struct *vma_next(struct vma_iterator *vmi)
{
    return find_vma(vmi->mm, vmi->addr);
}
static inline struct vm_area_struct *lock_vma_under_rcu(struct mm_struct *mm,
                                                        unsigned long addr)
{
    return find_vma(mm, addr);
}
static inline void vma_end_read(struct vm_area_struct *vma)
{
    (void)vma;
}
static inline bool spin_trylock(spinlock_t *lock)
{
    lock->locked = 1;
    return true;
}
static inline void spin_unlock(spinlock_t *lock)
{
    lock->locked = 0;
}
static inline void *bpf_mem_alloc(struct bpf_mem_alloc *ma, size_t size)
{
    (void)ma;
    if (size > sizeof(__bpf_iter_task_vma_storage))
        return 0;
    return __bpf_iter_task_vma_storage;
}
static inline void bpf_mem_free(struct bpf_mem_alloc *ma, void *ptr)
{
    (void)ma;
    (void)ptr;
}
static inline bool bpf_mmap_unlock_get_irq_work(struct mmap_unlock_irq_work **work_ptr)
{
    *work_ptr = 0;
    return false;
}
static inline void bpf_mmap_unlock_mm(struct mmap_unlock_irq_work *work,
                                      struct mm_struct *mm)
{
    (void)work;
    mmap_read_unlock(mm);
}
static inline void init_irq_work(struct irq_work *work,
                                 void (*func)(struct irq_work *entry))
{
    (void)func;
    work->busy = 0;
}
static inline void *memcpy(void *dst, const void *src, size_t n)
{
    char *d = dst;
    const char *s = src;
    while (n--)
        *d++ = *s++;
    return dst;
}
static u64 __bpf_iter_vma_cb(u64 task, u64 vma, u64 callback_ctx,
                             u64 flags, u64 reserved)
{
    (void)task;
    (void)flags;
    (void)reserved;
    if (callback_ctx)
        *(u64 *)(long)callback_ctx = vma;
    __bpf_iter_vma_callbacks++;
    return 0;
}
