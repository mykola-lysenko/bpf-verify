#include <linux/errno.h>
#define _LINUX_BPF_H 1
#define __BPF_MPROG_H
#define __user
#define __rcu
#define BPF_MPROG_MAX 4
#define BPF_F_REPLACE (1U << 2)
#define BPF_F_BEFORE (1U << 3)
#define BPF_F_AFTER (1U << 4)
#define BPF_F_ID (1U << 5)
#define BPF_F_LINK (1U << 13)
#define BPF_TCX_INGRESS 100
#define BPF_TCX_EGRESS 101
#define BPF_LINK_TYPE_TCX 11
#define GFP_KERNEL 0
#define GFP_USER 0
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define BUILD_BUG_ON(cond) do { } while (0)
#define WARN_ON_ONCE(cond) (0)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, val) ((x) = (val))
#define ERR_PTR(error) ((void *)(long)(error))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-4095)
#define IS_ERR_OR_NULL(ptr) (!(ptr) || IS_ERR(ptr))
#define container_of(ptr, type, member)     ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
#define xchg(ptr, val) ({ typeof(*(ptr)) __old = *(ptr); *(ptr) = (val); __old; })

enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC = 0,
    BPF_PROG_TYPE_SCHED_CLS = 3,
};
enum bpf_attach_type {
    __BPF_ATTACH_TYPE_UNSPEC = 0,
    __BPF_TCX_INGRESS = BPF_TCX_INGRESS,
    __BPF_TCX_EGRESS = BPF_TCX_EGRESS,
};
enum bpf_link_type {
    __BPF_LINK_TYPE_TCX = BPF_LINK_TYPE_TCX,
};

struct bpf_prog_aux {
    u32 id;
};
struct bpf_prog {
    struct bpf_prog_aux *aux;
    enum bpf_prog_type type;
    enum bpf_attach_type expected_attach_type;
};
struct bpf_link;
struct seq_file {
    void *private;
    u32 writes;
};
struct bpf_link_info {
    struct {
        u32 ifindex;
        u32 attach_type;
    } tcx;
};
struct bpf_link_ops {
    void (*release)(struct bpf_link *link);
    void (*dealloc)(struct bpf_link *link);
    int (*detach)(struct bpf_link *link);
    int (*update_prog)(struct bpf_link *link, struct bpf_prog *new_prog,
                       struct bpf_prog *old_prog);
    void (*show_fdinfo)(const struct bpf_link *link, struct seq_file *seq);
    int (*fill_link_info)(const struct bpf_link *link,
                          struct bpf_link_info *info);
};
struct bpf_link {
    atomic64_t refcnt;
    u32 id;
    enum bpf_link_type type;
    const struct bpf_link_ops *ops;
    struct bpf_prog *prog;
    u32 flags;
    enum bpf_attach_type attach_type;
};
struct bpf_link_primer {
    struct bpf_link *link;
};
union bpf_attr {
    struct {
        union {
            u32 target_fd;
            u32 target_ifindex;
        };
        u32 attach_bpf_fd;
        u32 attach_type;
        u32 attach_flags;
        u32 replace_bpf_fd;
        union {
            u32 relative_fd;
            u32 relative_id;
        };
        u64 expected_revision;
    };
    struct {
        union {
            u32 target_fd;
            u32 target_ifindex;
        };
        u32 attach_type;
        u32 query_flags;
        u32 attach_flags;
        u64 prog_ids;
        union {
            u32 prog_cnt;
            u32 count;
        };
        u32 __query_pad;
        u64 prog_attach_flags;
        u64 link_ids;
        u64 link_attach_flags;
        u64 revision;
    } query;
    struct {
        union {
            u32 prog_fd;
            u32 map_fd;
        };
        union {
            u32 target_fd;
            u32 target_ifindex;
        };
        u32 attach_type;
        u32 flags;
        union {
            u32 target_btf_id;
            struct {
                u64 iter_info;
                u32 iter_info_len;
            };
            struct {
                union {
                    u32 relative_fd;
                    u32 relative_id;
                };
                u64 expected_revision;
            } tcx;
        };
    } link_create;
};

struct bpf_mprog_fp {
    struct bpf_prog *prog;
};
struct bpf_mprog_cp {
    struct bpf_link *link;
};
struct bpf_mprog_entry {
    struct bpf_mprog_fp fp_items[BPF_MPROG_MAX];
    struct bpf_mprog_bundle *parent;
};
struct bpf_mprog_bundle {
    struct bpf_mprog_entry a;
    struct bpf_mprog_entry b;
    struct bpf_mprog_cp cp_items[BPF_MPROG_MAX];
    struct bpf_prog *ref;
    atomic64_t revision;
    u32 count;
};
struct bpf_tuple {
    struct bpf_prog *prog;
    struct bpf_link *link;
};

#define bpf_mprog_foreach_tuple(entry, fp, cp, t)     for (fp = &(entry)->fp_items[0], cp = &(entry)->parent->cp_items[0];          ({ (t).prog = READ_ONCE((fp)->prog); (t).link = (cp)->link;             (t).prog; });          fp++, cp++)

#define bpf_mprog_foreach_prog(entry, fp, p)     for (fp = &(entry)->fp_items[0]; (p = READ_ONCE((fp)->prog)); fp++)

static struct bpf_prog_aux __bpf_mprog_prog0_aux;
static struct bpf_prog_aux __bpf_mprog_prog1_aux;
static struct bpf_prog_aux __bpf_mprog_prog2_aux;
static struct bpf_prog_aux __bpf_mprog_prog3_aux;
static struct bpf_prog __bpf_mprog_prog0;
static struct bpf_prog __bpf_mprog_prog1;
static struct bpf_prog __bpf_mprog_prog2;
static struct bpf_prog __bpf_mprog_prog3;
static struct bpf_link __bpf_mprog_link0;
static volatile u32 __bpf_mprog_prog_puts;
static volatile u32 __bpf_mprog_link_puts;
static volatile u32 __bpf_mprog_copies;

static inline void bpf_prog_put(struct bpf_prog *prog);

static inline void __bpf_mprog_reset(void)
{
    __bpf_mprog_prog_puts = 0;
    __bpf_mprog_link_puts = 0;
    __bpf_mprog_copies = 0;
    __bpf_mprog_prog0_aux.id = 10;
    __bpf_mprog_prog1_aux.id = 11;
    __bpf_mprog_prog2_aux.id = 12;
    __bpf_mprog_prog3_aux.id = 13;
    __bpf_mprog_prog0.aux = &__bpf_mprog_prog0_aux;
    __bpf_mprog_prog1.aux = &__bpf_mprog_prog1_aux;
    __bpf_mprog_prog2.aux = &__bpf_mprog_prog2_aux;
    __bpf_mprog_prog3.aux = &__bpf_mprog_prog3_aux;
    __bpf_mprog_prog0.type = BPF_PROG_TYPE_SCHED_CLS;
    __bpf_mprog_prog1.type = BPF_PROG_TYPE_SCHED_CLS;
    __bpf_mprog_prog2.type = BPF_PROG_TYPE_SCHED_CLS;
    __bpf_mprog_prog3.type = BPF_PROG_TYPE_SCHED_CLS;
    __bpf_mprog_link0.id = 100;
    __bpf_mprog_link0.prog = &__bpf_mprog_prog0;
    __bpf_mprog_link0.attach_type = BPF_TCX_INGRESS;
}
static inline void *__bpf_mprog_memset(void *dst, int c, size_t n)
{
    char *d = dst;
    size_t i;

    for (i = 0; i < 256 && i < n; i++)
        d[i] = (char)c;
    return dst;
}
static inline void *__bpf_mprog_memcpy(void *dst, const void *src, size_t n)
{
    char *d = dst;
    const char *s = src;
    size_t i;

    for (i = 0; i < 256 && i < n; i++)
        d[i] = s[i];
    return dst;
}
static inline void *__bpf_mprog_memmove(void *dst, const void *src, size_t n)
{
    char *d = dst;
    const char *s = src;
    int i;

    if (d < s) {
        for (i = 0; i < 256 && i < (int)n; i++)
            d[i] = s[i];
    } else {
        for (i = 255; i >= 0; i--)
            if (i < (int)n)
                d[i] = s[i];
    }
    return dst;
}
#define memset(dst, c, n) __bpf_mprog_memset((dst), (c), (n))
#define memcpy(dst, src, n) __bpf_mprog_memcpy((dst), (src), (n))
#define memmove(dst, src, n) __bpf_mprog_memmove((dst), (src), (n))

static inline void atomic64_set(atomic64_t *v, long long value)
{
    v->counter = value;
}
static inline void atomic64_inc(atomic64_t *v)
{
    v->counter++;
}
static inline long long atomic64_read(const atomic64_t *v)
{
    return v->counter;
}
static inline struct bpf_mprog_entry *
bpf_mprog_peer(const struct bpf_mprog_entry *entry)
{
    if (entry == &entry->parent->a)
        return &entry->parent->b;
    return &entry->parent->a;
}
static inline void bpf_mprog_bundle_init(struct bpf_mprog_bundle *bundle)
{
    u32 i;

    BUILD_BUG_ON(sizeof(bundle->a.fp_items[0]) > sizeof(u64));
    for (i = 0; i < BPF_MPROG_MAX; i++) {
        bundle->a.fp_items[i].prog = NULL;
        bundle->b.fp_items[i].prog = NULL;
        bundle->cp_items[i].link = NULL;
    }
    bundle->ref = NULL;
    atomic64_set(&bundle->revision, 1);
    bundle->count = 0;
    bundle->a.parent = bundle;
    bundle->b.parent = bundle;
}
static inline void bpf_mprog_inc(struct bpf_mprog_entry *entry)
{
    entry->parent->count++;
}
static inline void bpf_mprog_dec(struct bpf_mprog_entry *entry)
{
    entry->parent->count--;
}
static inline int bpf_mprog_max(void)
{
    return ARRAY_SIZE(((struct bpf_mprog_entry *)NULL)->fp_items) - 1;
}
static inline int bpf_mprog_total(struct bpf_mprog_entry *entry)
{
    int total = entry->parent->count;

    WARN_ON_ONCE(total > bpf_mprog_max());
    return total;
}
static inline bool bpf_mprog_exists(struct bpf_mprog_entry *entry,
                                    struct bpf_prog *prog)
{
    const struct bpf_mprog_fp *fp;
    const struct bpf_prog *tmp;

    bpf_mprog_foreach_prog(entry, fp, tmp) {
        if (tmp == prog)
            return true;
    }
    return false;
}
static inline void bpf_mprog_mark_for_release(struct bpf_mprog_entry *entry,
                                              struct bpf_tuple *tuple)
{
    WARN_ON_ONCE(entry->parent->ref);
    if (!tuple->link)
        entry->parent->ref = tuple->prog;
}
static inline void bpf_mprog_complete_release(struct bpf_mprog_entry *entry)
{
    if (entry->parent->ref) {
        bpf_prog_put(entry->parent->ref);
        entry->parent->ref = NULL;
    }
}
static inline void bpf_mprog_revision_new(struct bpf_mprog_entry *entry)
{
    atomic64_inc(&entry->parent->revision);
}
static inline void bpf_mprog_commit(struct bpf_mprog_entry *entry)
{
    bpf_mprog_complete_release(entry);
    bpf_mprog_revision_new(entry);
}
static inline u64 bpf_mprog_revision(struct bpf_mprog_entry *entry)
{
    return atomic64_read(&entry->parent->revision);
}
static inline void bpf_mprog_entry_copy(struct bpf_mprog_entry *dst,
                                        struct bpf_mprog_entry *src)
{
    u32 i;

    for (i = 0; i < BPF_MPROG_MAX; i++)
        dst->fp_items[i] = src->fp_items[i];
    __bpf_mprog_copies++;
}
static inline void bpf_mprog_entry_clear(struct bpf_mprog_entry *dst)
{
    u32 i;

    for (i = 0; i < BPF_MPROG_MAX; i++)
        dst->fp_items[i].prog = NULL;
}
static inline void bpf_mprog_clear_all(struct bpf_mprog_entry *entry,
                                       struct bpf_mprog_entry **entry_new)
{
    struct bpf_mprog_entry *peer = bpf_mprog_peer(entry);

    bpf_mprog_entry_clear(peer);
    peer->parent->count = 0;
    *entry_new = peer;
}
static inline void bpf_mprog_entry_grow(struct bpf_mprog_entry *entry, int idx)
{
    int i;

    for (i = BPF_MPROG_MAX - 1; i > 0; i--) {
        if (i > idx) {
            entry->fp_items[i] = entry->fp_items[i - 1];
            entry->parent->cp_items[i] = entry->parent->cp_items[i - 1];
        }
    }
}
static inline void bpf_mprog_entry_shrink(struct bpf_mprog_entry *entry, int idx)
{
    int i;

    for (i = 0; i < BPF_MPROG_MAX - 1; i++) {
        if (i >= idx) {
            entry->fp_items[i] = entry->fp_items[i + 1];
            entry->parent->cp_items[i] = entry->parent->cp_items[i + 1];
        }
    }
    entry->fp_items[BPF_MPROG_MAX - 1].prog = NULL;
    entry->parent->cp_items[BPF_MPROG_MAX - 1].link = NULL;
}
static inline void bpf_mprog_read(struct bpf_mprog_entry *entry, u32 idx,
                                  struct bpf_mprog_fp **fp,
                                  struct bpf_mprog_cp **cp)
{
    *fp = &entry->fp_items[idx];
    *cp = &entry->parent->cp_items[idx];
}
static inline void bpf_mprog_write(struct bpf_mprog_fp *fp,
                                   struct bpf_mprog_cp *cp,
                                   struct bpf_tuple *tuple)
{
    WRITE_ONCE(fp->prog, tuple->prog);
    cp->link = tuple->link;
}
static inline struct bpf_prog *__bpf_mprog_prog_by_id(u32 id)
{
    if (id == __bpf_mprog_prog0_aux.id || id == 1)
        return &__bpf_mprog_prog0;
    if (id == __bpf_mprog_prog1_aux.id || id == 2)
        return &__bpf_mprog_prog1;
    if (id == __bpf_mprog_prog2_aux.id || id == 3)
        return &__bpf_mprog_prog2;
    if (id == __bpf_mprog_prog3_aux.id || id == 4)
        return &__bpf_mprog_prog3;
    return ERR_PTR(-ENOENT);
}
static inline struct bpf_prog *bpf_prog_by_id(u32 id)
{
    return __bpf_mprog_prog_by_id(id);
}
static inline struct bpf_prog *bpf_prog_get(u32 fd)
{
    return __bpf_mprog_prog_by_id(fd);
}
static inline struct bpf_prog *bpf_prog_get_type(u32 fd, enum bpf_prog_type type)
{
    struct bpf_prog *prog = bpf_prog_get(fd);

    if (IS_ERR(prog))
        return prog;
    if (prog->type != type)
        return ERR_PTR(-EINVAL);
    return prog;
}
static inline void bpf_prog_put(struct bpf_prog *prog)
{
    (void)prog;
    __bpf_mprog_prog_puts++;
}
static inline struct bpf_link *bpf_link_by_id(u32 id)
{
    return id == __bpf_mprog_link0.id ? &__bpf_mprog_link0 : ERR_PTR(-ENOENT);
}
static inline struct bpf_link *bpf_link_get_from_fd(u32 fd)
{
    return fd == 5 ? &__bpf_mprog_link0 : ERR_PTR(-EBADF);
}
static inline void bpf_link_put(struct bpf_link *link)
{
    (void)link;
    __bpf_mprog_link_puts++;
}
static inline void bpf_link_init(struct bpf_link *link, enum bpf_link_type type,
                                 const struct bpf_link_ops *ops,
                                 struct bpf_prog *prog,
                                 enum bpf_attach_type attach_type)
{
    link->id = 200;
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
    primer->link = NULL;
}
static inline int bpf_link_settle(struct bpf_link_primer *primer);
static inline void *u64_to_user_ptr(u64 value)
{
    return (void *)(long)value;
}
static inline int copy_to_user(void *dst, const void *src, size_t n)
{
    (void)dst;
    (void)src;
    (void)n;
    __bpf_mprog_copies++;
    return 0;
}
#define bpf_mprog_attach static __inline __attribute__((always_inline)) bpf_mprog_attach
#define bpf_mprog_detach static __inline __attribute__((always_inline)) bpf_mprog_detach
#define bpf_mprog_query static __inline __attribute__((always_inline)) bpf_mprog_query
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
