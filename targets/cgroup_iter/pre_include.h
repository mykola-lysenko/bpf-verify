#define _LINUX_CGROUP_H
#define __CGROUP_INTERNAL_H
#define PATH_MAX 4096
#define GFP_KERNEL 0
#define BPF_CGROUP_ITER_ORDER_UNSPEC 0
#define BPF_CGROUP_ITER_SELF_ONLY 1
#define BPF_CGROUP_ITER_DESCENDANTS_PRE 2
#define BPF_CGROUP_ITER_DESCENDANTS_POST 3
#define BPF_CGROUP_ITER_ANCESTORS_UP 4
#define BPF_CGROUP_ITER_CHILDREN 5

struct cgroup_subsys_state {
    struct cgroup *cgroup;
    struct cgroup_subsys_state *parent;
    u32 refs;
};
struct cgroup {
    struct cgroup_subsys_state self;
    u64 id;
    bool dead;
    u32 refs;
};
struct cgroup_namespace {
    u32 id;
};
struct nsproxy {
    struct cgroup_namespace *cgroup_ns;
};
struct task_struct {
    struct nsproxy *nsproxy;
};

static struct cgroup_namespace __bpf_iter_cgroup_ns = { .id = 1 };
static struct nsproxy __bpf_iter_nsproxy = { .cgroup_ns = &__bpf_iter_cgroup_ns };
static struct task_struct __bpf_iter_current_task = { .nsproxy = &__bpf_iter_nsproxy };
static struct cgroup __bpf_iter_cgroup_root;
static struct cgroup __bpf_iter_cgroup_child;
static char __bpf_iter_cgroup_path_buf[PATH_MAX];
static volatile u32 __bpf_iter_cgroup_locks;
static volatile u32 __bpf_iter_cgroup_unlocks;
static volatile u32 __bpf_iter_cgroup_css_gets;
static volatile u32 __bpf_iter_cgroup_css_puts;
static volatile u32 __bpf_iter_cgroup_puts;

#define current (&__bpf_iter_current_task)

static inline void __bpf_iter_cgroup_reset(void)
{
    __bpf_iter_reset();
    __bpf_iter_cgroup_locks = 0;
    __bpf_iter_cgroup_unlocks = 0;
    __bpf_iter_cgroup_css_gets = 0;
    __bpf_iter_cgroup_css_puts = 0;
    __bpf_iter_cgroup_puts = 0;
    __bpf_iter_cgroup_root.self.cgroup = &__bpf_iter_cgroup_root;
    __bpf_iter_cgroup_root.self.parent = 0;
    __bpf_iter_cgroup_root.self.refs = 1;
    __bpf_iter_cgroup_root.id = 10;
    __bpf_iter_cgroup_root.dead = false;
    __bpf_iter_cgroup_root.refs = 1;
    __bpf_iter_cgroup_child.self.cgroup = &__bpf_iter_cgroup_child;
    __bpf_iter_cgroup_child.self.parent = &__bpf_iter_cgroup_root.self;
    __bpf_iter_cgroup_child.self.refs = 1;
    __bpf_iter_cgroup_child.id = 11;
    __bpf_iter_cgroup_child.dead = false;
    __bpf_iter_cgroup_child.refs = 1;
}
static inline void cgroup_lock(void)
{
    __bpf_iter_cgroup_locks++;
}
static inline void cgroup_unlock(void)
{
    __bpf_iter_cgroup_unlocks++;
}
static inline bool cgroup_is_dead(const struct cgroup *cgrp)
{
    return cgrp->dead;
}
static inline void css_get(struct cgroup_subsys_state *css)
{
    css->refs++;
    __bpf_iter_cgroup_css_gets++;
}
static inline void css_put(struct cgroup_subsys_state *css)
{
    if (css->refs)
        css->refs--;
    __bpf_iter_cgroup_css_puts++;
}
static inline struct cgroup_subsys_state *
css_next_descendant_pre(struct cgroup_subsys_state *pos,
                        struct cgroup_subsys_state *root)
{
    if (!pos)
        return root;
    if (pos == root)
        return &__bpf_iter_cgroup_child.self;
    return 0;
}
static inline struct cgroup_subsys_state *
css_next_descendant_post(struct cgroup_subsys_state *pos,
                         struct cgroup_subsys_state *root)
{
    if (!pos)
        return &__bpf_iter_cgroup_child.self;
    if (pos == &__bpf_iter_cgroup_child.self)
        return root;
    return 0;
}
static inline struct cgroup_subsys_state *
css_next_child(struct cgroup_subsys_state *pos,
               struct cgroup_subsys_state *root)
{
    (void)root;
    if (!pos)
        return &__bpf_iter_cgroup_child.self;
    return 0;
}
static inline struct cgroup *cgroup_v1v2_get_from_fd(int fd)
{
    if (fd == 1)
        return &__bpf_iter_cgroup_root;
    return ERR_PTR(-EBADF);
}
static inline struct cgroup *cgroup_get_from_id(u64 id)
{
    if (id == __bpf_iter_cgroup_root.id)
        return &__bpf_iter_cgroup_root;
    if (id == __bpf_iter_cgroup_child.id)
        return &__bpf_iter_cgroup_child;
    return ERR_PTR(-ENOENT);
}
static inline struct cgroup *cgroup_get_from_path(const char *path)
{
    (void)path;
    return &__bpf_iter_cgroup_root;
}
static inline void cgroup_put(struct cgroup *cgrp)
{
    if (cgrp->refs)
        cgrp->refs--;
    __bpf_iter_cgroup_puts++;
}
static inline u64 cgroup_id(const struct cgroup *cgrp)
{
    return cgrp->id;
}
static inline void *kzalloc(size_t size, int flags)
{
    (void)flags;
    if (size > sizeof(__bpf_iter_cgroup_path_buf))
        return 0;
    __bpf_iter_cgroup_path_buf[0] = 0;
    return __bpf_iter_cgroup_path_buf;
}
static inline void kfree(const void *ptr)
{
    (void)ptr;
}
static inline int cgroup_path_ns(struct cgroup *cgrp, char *buf, int buflen,
                                 struct cgroup_namespace *ns)
{
    (void)cgrp;
    (void)ns;
    if (buflen > 1) {
        buf[0] = '/';
        buf[1] = 0;
    }
    return 0;
}
