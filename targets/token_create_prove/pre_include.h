#include <linux/errno.h>
#define _LINUX_BPF_H 1
#define _LINUX_VMALLOC_H
#define __LINUX_FILE_H
#define _LINUX_FS_H
#define _LINUX_KERNEL_H
#define __IDR_H__
#define _LINUX_NAMEI_H
#define _LINUX_USER_NAMESPACE_H
#define __LINUX_SECURITY_H
#define _LINUX_WORKQUEUE_H
#define _LINUX_SEQ_FILE_H
#define __user
#define __force
#define CONFIG_SECURITY 1
#define GFP_USER 0
#define O_CLOEXEC 02000000
#define O_RDWR 02
#define MAY_ACCESS 0x00000001
#define S_IFREG 0100000
#define S_IRUSR 00400
#define S_IWUSR 00200
#define CAP_SYS_ADMIN 21
#define CAP_PERFMON 38
#define CAP_BPF 39
#define BUILD_BUG_ON(cond) do { } while (0)
#define BPF_KEEP_SCALAR(x) asm volatile("" : "+r"(x))
#define ERR_PTR(error) ((void *)(long)(error))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-4095)
#define IS_ERR_OR_NULL(ptr) (!(ptr) || IS_ERR(ptr))
#define no_free_ptr(ptr) (ptr)
#define __free(name)
#define kzalloc_obj(obj, flags) ((typeof(&(obj)))__bpf_token_kzalloc(sizeof(obj)))
#define CLASS(_name, var) class_##_name##_t var = class_##_name##_constructor
#define FD_PREPARE(_fdf, _fd_flags, _file_owned)     struct file *__bpf_owned_file_##_fdf = (_file_owned);     struct fd_prepare _fdf = {         .err = __bpf_token_alloc_file_err,         .__fd = 7,         .__file = __bpf_owned_file_##_fdf,     }
#define fd_prepare_file(_fdf) ((_fdf).__file)
#define fd_publish(_fdf) ((_fdf).err ? (_fdf).err : (_fdf).__fd)
#define put_user(value, ptr) ({ typeof(ptr) __p = (ptr);     __p ? (*__p = (value), 0) : -EFAULT; })
#ifndef BIT_ULL
#define BIT_ULL(nr) (1ULL << (nr))
#endif
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef min_t
#define min_t(type, a, b) ((type)min((type)(a), (type)(b)))
#endif
#ifndef container_of
#define container_of(ptr, type, member)     ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
#endif

enum bpf_cmd {
    BPF_MAP_CREATE = 0,
    BPF_PROG_LOAD = 5,
    BPF_TOKEN_CREATE = 36,
    __MAX_BPF_CMD = 38,
};
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    __MAX_BPF_MAP_TYPE = 31,
};
enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC = 0,
    BPF_PROG_TYPE_SOCKET_FILTER = 1,
    BPF_PROG_TYPE_XDP = 6,
    __MAX_BPF_PROG_TYPE = 34,
};
enum bpf_attach_type {
    BPF_CGROUP_INET_INGRESS = 0,
    BPF_CGROUP_INET_EGRESS = 1,
    __MAX_BPF_ATTACH_TYPE = 63,
};

typedef struct fd class_fd_t;

struct user_namespace {
    u64 caps;
};
struct work_struct {
    void (*func)(struct work_struct *work);
};
struct bpf_token {
    struct work_struct work;
    atomic64_t refcnt;
    struct user_namespace *userns;
    u64 allowed_cmds;
    u64 allowed_maps;
    u64 allowed_progs;
    u64 allowed_attachs;
    void *security;
};
struct bpf_token_info {
    u64 allowed_cmds;
    u64 allowed_maps;
    u64 allowed_progs;
    u64 allowed_attachs;
};
struct bpf_mount_opts {
    u64 delegate_cmds;
    u64 delegate_maps;
    u64 delegate_progs;
    u64 delegate_attachs;
};
struct seq_file {
    u32 writes;
};
struct inode;
struct file;
struct file_operations {
    int (*release)(struct inode *inode, struct file *filp);
    void (*show_fdinfo)(struct seq_file *m, struct file *filp);
};
struct inode_operations {
    u32 dummy;
};
struct super_operations {
    u32 dummy;
};
struct vfsmount {
    u32 id;
};
struct super_block;
struct dentry {
    struct super_block *d_sb;
};
struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};
struct inode {
    const struct inode_operations *i_op;
    const struct file_operations *i_fop;
};
struct file {
    const struct file_operations *f_op;
    void *private_data;
    struct path f_path;
};
struct super_block {
    struct dentry *s_root;
    const struct super_operations *s_op;
    struct user_namespace *s_user_ns;
    void *s_fs_info;
};
struct fd {
    struct file *file;
};
struct fd_prepare {
    s32 err;
    s32 __fd;
    struct file *__file;
};
union bpf_attr {
    struct {
        u32 bpffs_fd;
    } token_create;
    struct {
        u64 info;
        u32 info_len;
    } info;
};

static struct user_namespace init_user_ns = {
    .caps = BIT_ULL(CAP_SYS_ADMIN) | BIT_ULL(CAP_BPF) |
            BIT_ULL(CAP_PERFMON),
};
static const struct super_operations bpf_super_ops = { };
static struct bpf_mount_opts __bpf_token_mnt_opts = {
    .delegate_cmds = BIT_ULL(BPF_MAP_CREATE),
    .delegate_maps = BIT_ULL(BPF_MAP_TYPE_ARRAY),
    .delegate_progs = BIT_ULL(BPF_PROG_TYPE_SOCKET_FILTER),
    .delegate_attachs = BIT_ULL(BPF_CGROUP_INET_INGRESS),
};
static struct user_namespace __bpf_token_owner_ns = {
    .caps = BIT_ULL(CAP_BPF),
};
static struct user_namespace __bpf_token_other_ns = {
    .caps = BIT_ULL(CAP_BPF),
};
static struct super_block __bpf_token_sb = {
    .s_op = &bpf_super_ops,
    .s_user_ns = &__bpf_token_owner_ns,
    .s_fs_info = &__bpf_token_mnt_opts,
};
static struct dentry __bpf_token_root = {
    .d_sb = &__bpf_token_sb,
};
static struct dentry __bpf_token_child = {
    .d_sb = &__bpf_token_sb,
};
static struct vfsmount __bpf_token_mnt;
static struct file __bpf_token_file = {
    .f_path = {
        .mnt = &__bpf_token_mnt,
        .dentry = &__bpf_token_root,
    },
};
static struct inode __bpf_token_inode;
static struct bpf_token __bpf_token_alloc;
static const struct super_operations __bpf_token_other_super_ops = { };
static u32 __bpf_token_work_scheduled;
static u32 __bpf_token_work_initialized;
static u32 __bpf_token_saw_work;
static u32 __bpf_token_use_child_dentry;
static u32 __bpf_token_bad_super_ops;
static int __bpf_token_path_permission_ret;
static u32 __bpf_token_current_mismatch;
static u32 __bpf_token_clear_caps;
static u32 __bpf_token_use_init_userns;
static u32 __bpf_token_empty_delegation;
static int __bpf_token_inode_err;
static int __bpf_token_alloc_file_err;
static u32 __bpf_token_alloc_fail;
static int __bpf_token_security_create_ret;
static u32 __bpf_token_kzallocs;
static u32 __bpf_token_userns_gets;

static inline void __bpf_token_reset_fs(void)
{
    __bpf_token_sb.s_root = &__bpf_token_root;
    __bpf_token_sb.s_op = __bpf_token_bad_super_ops ?
                           &__bpf_token_other_super_ops : &bpf_super_ops;
    __bpf_token_owner_ns.caps = __bpf_token_clear_caps ?
                                0 : BIT_ULL(CAP_BPF);
    __bpf_token_sb.s_user_ns = __bpf_token_use_init_userns ?
                               &init_user_ns : &__bpf_token_owner_ns;
    if (__bpf_token_empty_delegation) {
        __bpf_token_mnt_opts.delegate_cmds = 0;
        __bpf_token_mnt_opts.delegate_maps = 0;
        __bpf_token_mnt_opts.delegate_progs = 0;
        __bpf_token_mnt_opts.delegate_attachs = 0;
    } else {
        __bpf_token_mnt_opts.delegate_cmds = BIT_ULL(BPF_MAP_CREATE);
        __bpf_token_mnt_opts.delegate_maps = BIT_ULL(BPF_MAP_TYPE_ARRAY);
        __bpf_token_mnt_opts.delegate_progs =
            BIT_ULL(BPF_PROG_TYPE_SOCKET_FILTER);
        __bpf_token_mnt_opts.delegate_attachs =
            BIT_ULL(BPF_CGROUP_INET_INGRESS);
    }
    __bpf_token_sb.s_fs_info = &__bpf_token_mnt_opts;
    __bpf_token_root.d_sb = &__bpf_token_sb;
    __bpf_token_child.d_sb = &__bpf_token_sb;
    __bpf_token_file.f_path.mnt = &__bpf_token_mnt;
    __bpf_token_file.f_path.dentry = __bpf_token_use_child_dentry ?
                                     &__bpf_token_child : &__bpf_token_root;
}
static inline void __bpf_token_reset_create_controls(void)
{
    __bpf_token_use_child_dentry = 0;
    __bpf_token_bad_super_ops = 0;
    __bpf_token_path_permission_ret = 0;
    __bpf_token_current_mismatch = 0;
    __bpf_token_clear_caps = 0;
    __bpf_token_use_init_userns = 0;
    __bpf_token_empty_delegation = 0;
    __bpf_token_inode_err = 0;
    __bpf_token_alloc_file_err = 0;
    __bpf_token_alloc_fail = 0;
    __bpf_token_security_create_ret = 0;
    __bpf_token_kzallocs = 0;
    __bpf_token_userns_gets = 0;
    __bpf_token_file.f_op = NULL;
    __bpf_token_file.private_data = NULL;
    __bpf_token_inode.i_op = NULL;
    __bpf_token_inode.i_fop = NULL;
    __bpf_token_reset_fs();
}
static inline bool ns_capable(struct user_namespace *ns, int cap)
{
    return ns && cap >= 0 && cap < 64 && (ns->caps & BIT_ULL(cap));
}
static inline struct user_namespace *current_user_ns(void)
{
    if (__bpf_token_use_init_userns)
        return &init_user_ns;
    if (__bpf_token_current_mismatch)
        return &__bpf_token_other_ns;
    return &__bpf_token_owner_ns;
}
static inline void get_user_ns(struct user_namespace *ns)
{
    (void)ns;
    __bpf_token_userns_gets++;
}
static inline void put_user_ns(struct user_namespace *ns)
{
    (void)ns;
}
static inline int security_bpf_token_capable(const struct bpf_token *token,
                                             int cap)
{
    (void)cap;
    return token && token->security ? -EPERM : 0;
}
static inline int security_bpf_token_cmd(const struct bpf_token *token,
                                         enum bpf_cmd cmd)
{
    (void)cmd;
    return token && token->security ? -EPERM : 0;
}
static inline int security_bpf_token_create(struct bpf_token *token,
                                            union bpf_attr *attr,
                                            struct path *path)
{
    (void)token;
    (void)attr;
    (void)path;
    return __bpf_token_security_create_ret;
}
static inline void security_bpf_token_free(struct bpf_token *token)
{
    (void)token;
}
static inline void atomic64_set(atomic64_t *v, long long i)
{
    v->counter = i;
}
static inline void atomic64_inc(atomic64_t *v)
{
    v->counter++;
}
static inline bool atomic64_dec_and_test(atomic64_t *v)
{
    v->counter--;
    return v->counter == 0;
}
static inline void INIT_WORK(struct work_struct *work,
                             void (*func)(struct work_struct *work))
{
    (void)work;
    (void)func;
    __bpf_token_work_initialized++;
}
static inline bool schedule_work(struct work_struct *work)
{
    __bpf_token_work_scheduled++;
    if (work)
        __bpf_token_saw_work++;
    return true;
}
static inline void kfree(const void *ptr)
{
    (void)ptr;
}
static inline void *__bpf_token_kzalloc(size_t size)
{
    if (size != sizeof(__bpf_token_alloc))
        return NULL;
    if (__bpf_token_alloc_fail)
        return NULL;
    __bpf_token_kzallocs++;
    __bpf_token_alloc.work.func = NULL;
    __bpf_token_alloc.refcnt.counter = 0;
    __bpf_token_alloc.userns = NULL;
    __bpf_token_alloc.allowed_cmds = 0;
    __bpf_token_alloc.allowed_maps = 0;
    __bpf_token_alloc.allowed_progs = 0;
    __bpf_token_alloc.allowed_attachs = 0;
    __bpf_token_alloc.security = NULL;
    return &__bpf_token_alloc;
}
static inline struct fd class_fd_constructor(int fd)
{
    __bpf_token_reset_fs();
    return (struct fd){ fd == 1 ? &__bpf_token_file : NULL };
}
static inline bool fd_empty(struct fd fd)
{
    return !fd.file;
}
static inline struct file *fd_file(struct fd fd)
{
    return fd.file;
}
static inline int path_permission(const struct path *path, int mask)
{
    (void)path;
    (void)mask;
    return __bpf_token_path_permission_ret;
}
static inline unsigned int current_umask(void)
{
    return 0;
}
static inline struct inode *bpf_get_inode(struct super_block *sb,
                                          const struct inode *dir,
                                          umode_t mode)
{
    (void)sb;
    (void)dir;
    (void)mode;
    if (__bpf_token_inode_err)
        return ERR_PTR(__bpf_token_inode_err);
    return &__bpf_token_inode;
}
static inline void clear_nlink(struct inode *inode)
{
    (void)inode;
}
static inline struct file *alloc_file_pseudo(struct inode *inode,
                                             struct vfsmount *mnt,
                                             const char *name, int flags,
                                             const struct file_operations *fops)
{
    (void)inode;
    (void)mnt;
    (void)name;
    (void)flags;
    if (__bpf_token_alloc_file_err)
        return ERR_PTR(__bpf_token_alloc_file_err);
    __bpf_token_file.f_op = fops;
    return &__bpf_token_file;
}
static inline void *u64_to_user_ptr(u64 value)
{
    return (void *)(long)value;
}
static inline int copy_to_user(void *dst, const void *src, size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    size_t i;

    if (!dst && n)
        return -EFAULT;

    for (i = 0; i < sizeof(struct bpf_token_info); i++) {
        if (i >= n)
            break;
        d[i] = s[i];
    }
    return 0;
}
static inline int __bpf_token_seq_printf(struct seq_file *m)
{
    if (m)
        m->writes++;
    return 0;
}
#define seq_printf(m, fmt, ...) __bpf_token_seq_printf(m)
static __always_inline void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = dst;
    size_t i;

    for (i = 0; i < 64; i++) {
        if (i >= n)
            break;
        d[i] = (unsigned char)c;
    }
    return dst;
}
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
