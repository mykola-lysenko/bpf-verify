#define _LINUX_NETDEVICE_H
#define __NET_TCX_H
#define CONFIG_NET_XGRESS 1
#define CONFIG_BPF_SYSCALL 1
#define ASSERT_RTNL() do { } while (0)
#define rcu_assign_pointer(ptr, val) ((ptr) = (val))
#define rcu_dereference_rtnl(ptr) (ptr)
#define kfree_rcu(ptr, member) kfree(ptr)
#define kzalloc_obj(obj, flags) __bpf_tcx_kzalloc(sizeof(obj))

struct net {
    u32 id;
};
struct nsproxy {
    struct net *net_ns;
};
struct task_struct {
    struct nsproxy *nsproxy;
};
struct net_device {
    int ifindex;
    struct bpf_mprog_entry *tcx_ingress;
    struct bpf_mprog_entry *tcx_egress;
};
struct tcx_entry {
    void *miniq;
    struct bpf_mprog_bundle bundle;
    u32 miniq_active;
    struct rcu_head rcu;
};
struct tcx_link {
    struct bpf_link link;
    struct net_device *dev;
};

static struct net __bpf_tcx_net;
static struct nsproxy __bpf_tcx_nsproxy;
static struct task_struct __bpf_tcx_current;
static struct net_device __bpf_tcx_dev;
static struct tcx_entry __bpf_tcx_entry0;
static struct tcx_link __bpf_tcx_link0;
static volatile u32 __bpf_tcx_locks;
static volatile u32 __bpf_tcx_unlocks;
static volatile u32 __bpf_tcx_syncs;
static volatile u32 __bpf_tcx_skey_inc;
static volatile u32 __bpf_tcx_skey_dec;
static volatile u32 __bpf_tcx_frees;
static volatile u32 __bpf_tcx_link_settles;
static volatile u32 __bpf_tcx_ingress_active;
static volatile u32 __bpf_tcx_egress_active;

#define current (&__bpf_tcx_current)

static inline void __bpf_tcx_reset(void)
{
    __bpf_mprog_reset();
    __bpf_tcx_locks = 0;
    __bpf_tcx_unlocks = 0;
    __bpf_tcx_syncs = 0;
    __bpf_tcx_skey_inc = 0;
    __bpf_tcx_skey_dec = 0;
    __bpf_tcx_frees = 0;
    __bpf_tcx_link_settles = 0;
    __bpf_tcx_ingress_active = 0;
    __bpf_tcx_egress_active = 0;
    __bpf_tcx_net.id = 1;
    __bpf_tcx_nsproxy.net_ns = &__bpf_tcx_net;
    __bpf_tcx_current.nsproxy = &__bpf_tcx_nsproxy;
    __bpf_tcx_dev.ifindex = 1;
    __bpf_tcx_dev.tcx_ingress = NULL;
    __bpf_tcx_dev.tcx_egress = NULL;
    __bpf_mprog_memset(&__bpf_tcx_link0, 0, sizeof(__bpf_tcx_link0));
    bpf_mprog_bundle_init(&__bpf_tcx_entry0.bundle);
    __bpf_tcx_entry0.miniq = NULL;
    __bpf_tcx_entry0.miniq_active = 0;
}
static inline void rtnl_lock(void)
{
    __bpf_tcx_locks++;
}
static inline void rtnl_unlock(void)
{
    __bpf_tcx_unlocks++;
}
static inline struct net_device *__dev_get_by_index(struct net *net, int ifindex)
{
    (void)net;
    return ifindex == __bpf_tcx_dev.ifindex ? &__bpf_tcx_dev : NULL;
}
static inline struct tcx_entry *tcx_entry(struct bpf_mprog_entry *entry)
{
    (void)entry;
    return &__bpf_tcx_entry0;
}
static inline struct tcx_link *tcx_link(const struct bpf_link *link)
{
    (void)link;
    return &__bpf_tcx_link0;
}
static inline void synchronize_rcu(void)
{
    __bpf_tcx_syncs++;
}
static inline void tcx_entry_sync(void)
{
    synchronize_rcu();
}
static inline void tcx_entry_update(struct net_device *dev,
                                    struct bpf_mprog_entry *entry,
                                    bool ingress)
{
    (void)dev;
    if (ingress) {
        rcu_assign_pointer(__bpf_tcx_dev.tcx_ingress, entry);
        __bpf_tcx_ingress_active = entry != NULL;
    } else {
        rcu_assign_pointer(__bpf_tcx_dev.tcx_egress, entry);
        __bpf_tcx_egress_active = entry != NULL;
    }
}
static inline struct bpf_mprog_entry *
tcx_entry_fetch(struct net_device *dev, bool ingress)
{
    (void)dev;
    if (ingress)
        return __bpf_tcx_ingress_active ? &__bpf_tcx_entry0.bundle.b : NULL;
    return __bpf_tcx_egress_active ? &__bpf_tcx_entry0.bundle.b : NULL;
}
static inline struct bpf_mprog_entry *tcx_entry_create(void)
{
    bpf_mprog_bundle_init(&__bpf_tcx_entry0.bundle);
    __bpf_tcx_entry0.miniq = NULL;
    __bpf_tcx_entry0.miniq_active = 0;
    return &__bpf_tcx_entry0.bundle.a;
}
static inline void kfree(const void *ptr)
{
    (void)ptr;
    __bpf_tcx_frees++;
}
static inline void tcx_entry_free(struct bpf_mprog_entry *entry)
{
    kfree_rcu(tcx_entry(entry), rcu);
}
static inline struct bpf_mprog_entry *
tcx_entry_fetch_or_create(struct net_device *dev, bool ingress, bool *created)
{
    struct bpf_mprog_entry *entry = tcx_entry_fetch(dev, ingress);

    *created = false;
    if (!entry) {
        entry = tcx_entry_create();
        if (!entry)
            return NULL;
        *created = true;
    }
    return entry;
}
static inline void tcx_inc(void)
{
    __bpf_tcx_skey_inc++;
}
static inline void tcx_dec(void)
{
    __bpf_tcx_skey_dec++;
}
static inline void net_inc_ingress_queue(void) {}
static inline void net_inc_egress_queue(void) {}
static inline void net_dec_ingress_queue(void) {}
static inline void net_dec_egress_queue(void) {}
static inline void tcx_skeys_inc(bool ingress)
{
    (void)ingress;
    tcx_inc();
}
static inline void tcx_skeys_dec(bool ingress)
{
    (void)ingress;
    tcx_dec();
}
static inline bool tcx_entry_is_active(struct bpf_mprog_entry *entry)
{
    (void)entry;
    return __bpf_tcx_entry0.bundle.count || __bpf_tcx_entry0.miniq_active;
}
static inline void *__bpf_tcx_kzalloc(size_t size)
{
    if (size == sizeof(__bpf_tcx_link0)) {
        __bpf_mprog_memset(&__bpf_tcx_link0, 0, sizeof(__bpf_tcx_link0));
        return &__bpf_tcx_link0;
    }
    return NULL;
}
static inline int bpf_link_settle(struct bpf_link_primer *primer)
{
    (void)primer;
    __bpf_tcx_link_settles++;
    return 7;
}
static inline int __bpf_tcx_seq_printf(struct seq_file *seq)
{
    seq->writes++;
    return 0;
}
#define seq_printf(seq, fmt, ...) __bpf_tcx_seq_printf(seq)

static __inline __attribute__((always_inline))
int bpf_mprog_attach(struct bpf_mprog_entry *entry,
                     struct bpf_mprog_entry **entry_new,
                     struct bpf_prog *prog_new, struct bpf_link *link,
                     struct bpf_prog *prog_old, u32 flags, u32 id_or_fd,
                     u64 revision)
{
    struct bpf_mprog_bundle *bundle = &__bpf_tcx_entry0.bundle;
    struct bpf_mprog_entry *peer = &__bpf_tcx_entry0.bundle.b;

    (void)entry;
    (void)prog_old;
    (void)flags;
    (void)id_or_fd;
    (void)revision;

    if (!entry_new || !prog_new)
        return -EINVAL;
    if (bundle->count >= bpf_mprog_max())
        return -ERANGE;

    peer->parent = bundle;
    peer->fp_items[0].prog = prog_new;
    bundle->cp_items[0].link = link;
    bundle->count = 1;
    *entry_new = peer;
    return 0;
}

static __inline __attribute__((always_inline))
int bpf_mprog_detach(struct bpf_mprog_entry *entry,
                     struct bpf_mprog_entry **entry_new,
                     struct bpf_prog *prog, struct bpf_link *link,
                     u32 flags, u32 id_or_fd, u64 revision)
{
    (void)entry;
    (void)prog;
    (void)link;
    (void)flags;
    (void)id_or_fd;
    (void)revision;

    if (!entry_new || !__bpf_tcx_entry0.bundle.count)
        return -ENOENT;
    __bpf_tcx_entry0.bundle.b.fp_items[0].prog = NULL;
    __bpf_tcx_entry0.bundle.cp_items[0].link = NULL;
    __bpf_tcx_entry0.bundle.count = 0;
    *entry_new = &__bpf_tcx_entry0.bundle.b;
    return 0;
}

static __inline __attribute__((always_inline))
int bpf_mprog_query(const union bpf_attr *attr, union bpf_attr __user *uattr,
                    struct bpf_mprog_entry *entry)
{
    (void)attr;
    (void)uattr;
    (void)entry;
    return 0;
}

static __inline __attribute__((always_inline))
void __bpf_tcx_mprog_commit(struct bpf_mprog_entry *entry)
{
    (void)entry;
    if (__bpf_tcx_entry0.bundle.ref) {
        bpf_prog_put(__bpf_tcx_entry0.bundle.ref);
        __bpf_tcx_entry0.bundle.ref = NULL;
    }
    atomic64_inc(&__bpf_tcx_entry0.bundle.revision);
}

static __inline __attribute__((always_inline))
void __bpf_tcx_mprog_clear_all(struct bpf_mprog_entry *entry,
                               struct bpf_mprog_entry **entry_new)
{
    (void)entry;
    __bpf_tcx_entry0.bundle.b.fp_items[0].prog = NULL;
    __bpf_tcx_entry0.bundle.cp_items[0].link = NULL;
    __bpf_tcx_entry0.bundle.count = 0;
    *entry_new = &__bpf_tcx_entry0.bundle.b;
}

#define bpf_mprog_commit(entry) __bpf_tcx_mprog_commit(entry)
#define bpf_mprog_clear_all(entry, entry_new)     __bpf_tcx_mprog_clear_all(entry, entry_new)
#undef bpf_mprog_foreach_tuple
#define bpf_mprog_foreach_tuple(entry, fp, cp, t)     for (u32 __bpf_tcx_tuple_i = 0;          __bpf_tcx_tuple_i < 1 &&          ({ fp = &__bpf_tcx_entry0.bundle.b.fp_items[0];             cp = &__bpf_tcx_entry0.bundle.cp_items[0];             (t).prog = READ_ONCE((fp)->prog); (t).link = (cp)->link;             (t).prog; });          __bpf_tcx_tuple_i++)

#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
