#include <linux/errno.h>
#define _LINUX_BPF_H 1
#define _BPF_LOCAL_STORAGE_H
#define _LINUX_BTF_IDS_H
#define _UAPI__LINUX_BTF_H__
#define __LINUX_FILTER_H__
#define _LINUX_PID_H
#define _LINUX_SCHED_H
#define _LINUX_RCULIST_H
#define _LINUX_LIST_H
#define _LINUX_HASH_H
#define __LINUX_SPINLOCK_H
#define __LINUX_RCUPDATE_TRACE_H
#define _LINUX_BPF_LSM_H
#define _SOCK_H
#define _UAPI__SOCK_DIAG_H__
#define __rcu
#define __user
#define __aligned(x) __attribute__((aligned(x)))
#define ____cacheline_aligned __attribute__((aligned(64)))
#define offsetof(type, member) __builtin_offsetof(type, member)
#define BPF_NOEXIST 1
#define BPF_EXIST 2
#define BPF_F_LOCK 4
#define BPF_LOCAL_STORAGE_GET_F_CREATE 1
#define BPF_UPTR 1
#define RET_INTEGER 1
#define RET_PTR_TO_MAP_VALUE_OR_NULL 2
#define ARG_CONST_MAP_PTR 1
#define ARG_PTR_TO_BTF_ID_OR_NULL 2
#define ARG_PTR_TO_MAP_VALUE_OR_NULL 3
#define ARG_ANYTHING 4
#define BTF_TRACING_TYPE_TASK 0
#define MAX_BTF_TRACING_TYPE 1
#define PIDTYPE_PID 0
#define BPF_CALL_2(name, t1, a1, t2, a2)     static u64 name(t1 a1, t2 a2)
#define BPF_CALL_4(name, t1, a1, t2, a2, t3, a3, t4, a4)     static u64 name(t1 a1, t2 a2, t3 a3, t4 a4)
#define BTF_ID_LIST_SINGLE(name, prefix, typename) static u32 name[1];
#define BTF_ID_LIST_GLOBAL_SINGLE(name, prefix, typename) static u32 name[1];
#define ERR_PTR(error) ((void *)(long)(error))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-4095)
#define IS_ERR_OR_NULL(ptr) (!(ptr) || IS_ERR(ptr))
#define ERR_CAST(ptr) ((void *)(ptr))
#define PTR_ERR_OR_ZERO(ptr) (IS_ERR(ptr) ? PTR_ERR(ptr) : 0)
#define rcu_dereference(ptr) (ptr)
#define rcu_dereference_check(ptr, cond) (ptr)
#define rcu_access_pointer(ptr) (ptr)
#define container_of(ptr, type, member)     ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
#define CLASS(_name, var) class_##_name##_t var = class_##_name##_constructor

typedef struct {
    int refs;
} refcount_t;
struct percpu_ref {
    bool dying;
};
struct btf;
struct btf_type;
union bpf_attr;
struct bpf_map;
struct bpf_local_storage;
struct bpf_local_storage_map;
struct bpf_local_storage_data;
struct bpf_local_storage_elem;

struct bpf_map_ops {
    bool (*map_meta_equal)(const struct bpf_map *meta0,
                           const struct bpf_map *meta1);
    int (*map_alloc_check)(union bpf_attr *attr);
    struct bpf_map *(*map_alloc)(union bpf_attr *attr);
    void (*map_free)(struct bpf_map *map);
    int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
    void *(*map_lookup_elem)(struct bpf_map *map, void *key);
    long (*map_update_elem)(struct bpf_map *map, void *key, void *value,
                            u64 flags);
    long (*map_delete_elem)(struct bpf_map *map, void *key);
    int (*map_check_btf)(struct bpf_map *map, const struct btf *btf,
                         const struct btf_type *key_type,
                         const struct btf_type *value_type);
    u64 (*map_mem_usage)(const struct bpf_map *map);
    u32 *map_btf_id;
    struct bpf_local_storage __rcu **(*map_owner_storage_ptr)(void *owner);
};
struct bpf_map {
    const struct bpf_map_ops *ops;
    u32 id;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    void *record;
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
    u32 *arg1_btf_id;
    u32 *arg2_btf_id;
};
struct bpf_local_storage_map {
    struct bpf_map map;
    u16 cache_idx;
};
struct bpf_local_storage_data {
    struct bpf_local_storage_map __rcu *smap;
    u8 data[16] __aligned(8);
};
struct bpf_local_storage_elem {
    struct bpf_local_storage_data sdata;
};
struct bpf_local_storage {
    struct bpf_local_storage_data __rcu *sdata;
    void *owner;
};
struct bpf_local_storage_cache {
    u32 idx;
};
struct cgroup_subsys_state {
    struct percpu_ref refcnt;
};
struct cgroup {
    struct cgroup_subsys_state self;
    struct bpf_local_storage __rcu *bpf_cgrp_storage;
    u32 refs;
};
struct task_struct {
    struct bpf_local_storage __rcu *bpf_storage;
    refcount_t usage;
    u32 pid;
};
struct pid {
    struct task_struct *task;
    u32 refs;
};
struct bpf_storage_blob {
    struct bpf_local_storage __rcu *storage;
};
struct inode {
    void *i_security;
};
struct file {
    struct inode *inode;
};
struct fd {
    unsigned long word;
};
typedef struct fd class_fd_raw_t;

static struct bpf_local_storage __bpf_storage_local;
static struct bpf_local_storage_elem __bpf_storage_elem;
static struct bpf_local_storage_map __bpf_storage_smap;
static struct cgroup __bpf_storage_cgroup;
static struct task_struct __bpf_storage_task;
static struct pid __bpf_storage_pid;
static struct bpf_storage_blob __bpf_storage_blob;
static struct inode __bpf_storage_inode;
static struct file __bpf_storage_file;
static u32 btf_tracing_ids[MAX_BTF_TRACING_TYPE] = { 1 };
static volatile u32 __bpf_storage_present;
static volatile u32 __bpf_storage_updates;
static volatile u32 __bpf_storage_deletes;
static volatile u32 __bpf_storage_destroys;
static volatile u32 __bpf_storage_cgroup_puts;
static volatile u32 __bpf_storage_pid_puts;
static volatile u32 __bpf_storage_fd_gets;

#define DEFINE_BPF_STORAGE_CACHE(name)     static struct bpf_local_storage_cache name = { 0 }
#define SELEM(_SDATA) (&__bpf_storage_elem)

static inline void __bpf_storage_reset(void)
{
    __bpf_storage_present = 0;
    __bpf_storage_updates = 0;
    __bpf_storage_deletes = 0;
    __bpf_storage_destroys = 0;
    __bpf_storage_cgroup_puts = 0;
    __bpf_storage_pid_puts = 0;
    __bpf_storage_fd_gets = 0;
    __bpf_storage_smap.map.ops = 0;
    __bpf_storage_smap.map.id = 10;
    __bpf_storage_smap.map.key_size = 4;
    __bpf_storage_smap.map.value_size = 8;
    __bpf_storage_smap.map.max_entries = 1;
    __bpf_storage_smap.map.record = 0;
    __bpf_storage_smap.cache_idx = 0;
    __bpf_storage_elem.sdata.smap = &__bpf_storage_smap;
    *(u64 *)__bpf_storage_elem.sdata.data = 0;
    __bpf_storage_local.sdata = 0;
    __bpf_storage_local.owner = 0;
    __bpf_storage_cgroup.self.refcnt.dying = false;
    __bpf_storage_cgroup.bpf_cgrp_storage = &__bpf_storage_local;
    __bpf_storage_cgroup.refs = 1;
    __bpf_storage_task.bpf_storage = &__bpf_storage_local;
    __bpf_storage_task.usage.refs = 1;
    __bpf_storage_task.pid = 1;
    __bpf_storage_pid.task = &__bpf_storage_task;
    __bpf_storage_pid.refs = 1;
    __bpf_storage_blob.storage = &__bpf_storage_local;
    __bpf_storage_inode.i_security = &__bpf_storage_blob;
    __bpf_storage_file.inode = &__bpf_storage_inode;
}
static inline void rcu_read_lock(void) {}
static inline void rcu_read_unlock(void) {}
static inline void rcu_read_lock_dont_migrate(void) {}
static inline void rcu_read_unlock_migrate(void) {}
static inline bool rcu_read_lock_held(void) { return true; }
static inline bool rcu_read_lock_trace_held(void) { return true; }
static inline bool bpf_rcu_lock_held(void) { return true; }
static inline bool percpu_ref_is_dying(struct percpu_ref *ref)
{
    return ref->dying;
}
static inline int refcount_read(const refcount_t *ref)
{
    return ref->refs;
}
static inline bool btf_record_has_field(void *record, int field)
{
    (void)record;
    (void)field;
    return false;
}
static inline struct bpf_local_storage_data *
bpf_local_storage_lookup(struct bpf_local_storage *local_storage,
                         struct bpf_local_storage_map *smap,
                         bool cacheit_lockit)
{
    (void)local_storage;
    (void)cacheit_lockit;
    if (!__bpf_storage_present)
        return NULL;
    return __bpf_storage_elem.sdata.smap == smap ? &__bpf_storage_elem.sdata :
                                                   NULL;
}
static inline struct bpf_local_storage_data *
bpf_local_storage_update(void *owner, struct bpf_local_storage_map *smap,
                         void *value, u64 map_flags, bool swap_uptrs)
{
    (void)owner;
    (void)map_flags;
    (void)swap_uptrs;
    __bpf_storage_present = 1;
    __bpf_storage_updates++;
    __bpf_storage_local.sdata = &__bpf_storage_elem.sdata;
    __bpf_storage_elem.sdata.smap = smap;
    if (value)
        *(u64 *)__bpf_storage_elem.sdata.data = *(u64 *)value;
    return &__bpf_storage_elem.sdata;
}
static inline u32 bpf_local_storage_destroy(struct bpf_local_storage *local_storage)
{
    (void)local_storage;
    __bpf_storage_present = 0;
    __bpf_storage_destroys++;
    return 1;
}
static inline int bpf_selem_unlink(struct bpf_local_storage_elem *selem)
{
    (void)selem;
    if (!__bpf_storage_present)
        return -ENOENT;
    __bpf_storage_present = 0;
    __bpf_storage_deletes++;
    return 0;
}
static inline bool bpf_map_meta_equal(const struct bpf_map *meta0,
                                      const struct bpf_map *meta1)
{
    return meta0 == meta1;
}
static inline int bpf_local_storage_map_alloc_check(union bpf_attr *attr)
{
    (void)attr;
    return 0;
}
static inline struct bpf_map *
bpf_local_storage_map_alloc(union bpf_attr *attr,
                            struct bpf_local_storage_cache *cache)
{
    (void)attr;
    (void)cache;
    return &__bpf_storage_smap.map;
}
static inline void bpf_local_storage_map_free(struct bpf_map *map,
                                             struct bpf_local_storage_cache *cache)
{
    (void)map;
    (void)cache;
}
static inline int bpf_local_storage_map_check_btf(struct bpf_map *map,
                                                  const struct btf *btf,
                                                  const struct btf_type *key_type,
                                                  const struct btf_type *value_type)
{
    (void)map;
    (void)btf;
    (void)key_type;
    (void)value_type;
    return 0;
}
static inline u64 bpf_local_storage_map_mem_usage(const struct bpf_map *map)
{
    (void)map;
    return sizeof(__bpf_storage_smap) + sizeof(__bpf_storage_elem);
}
static inline struct cgroup *cgroup_v1v2_get_from_fd(int fd)
{
    return fd == 1 ? &__bpf_storage_cgroup : ERR_PTR(-EBADF);
}
static inline void cgroup_put(struct cgroup *cgroup)
{
    if (cgroup && !IS_ERR(cgroup) && cgroup->refs)
        cgroup->refs--;
    __bpf_storage_cgroup_puts++;
}
static inline struct pid *pidfd_get_pid(int fd, unsigned int *f_flags)
{
    if (f_flags)
        *f_flags = 0;
    return fd == 1 ? &__bpf_storage_pid : ERR_PTR(-EBADF);
}
static inline struct task_struct *pid_task(struct pid *pid, int type)
{
    (void)type;
    return pid ? pid->task : NULL;
}
static inline void put_pid(struct pid *pid)
{
    if (pid && !IS_ERR(pid) && pid->refs)
        pid->refs--;
    __bpf_storage_pid_puts++;
}
static inline struct fd class_fd_raw_constructor(int fd)
{
    __bpf_storage_fd_gets++;
    return (struct fd){ fd == 1 ? (unsigned long)&__bpf_storage_file : 0 };
}
static inline bool fd_empty(struct fd fd)
{
    return !fd.word;
}
static inline struct file *fd_file(struct fd fd)
{
    return (struct file *)fd.word;
}
static inline struct inode *file_inode(struct file *file)
{
    return file ? file->inode : NULL;
}
static inline struct bpf_storage_blob *bpf_inode(const struct inode *inode)
{
    return inode ? (struct bpf_storage_blob *)inode->i_security : NULL;
}
