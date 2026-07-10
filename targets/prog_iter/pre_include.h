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
