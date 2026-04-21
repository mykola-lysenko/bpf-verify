// SPDX-License-Identifier: GPL-2.0-only
/* bpf_lru_list-shim.c: BPF-compatible self-contained shim for
 * kernel/bpf/bpf_lru_list.c
 *
 * This shim is fully self-contained: it does NOT include any kernel headers.
 * It defines all necessary types from scratch, provides no-op spinlock and
 * RCU macros, implements a minimal doubly-linked list, and copies the core
 * LRU list manipulation functions verbatim from the Linux 6.1.102 source.
 *
 * Per-CPU infrastructure (alloc_percpu, per_cpu_ptr, raw_smp_processor_id)
 * is stubbed out -- the harness exercises only the non-percpu "common" LRU
 * path using a single-CPU view.
 */

/* -----------------------------------------------------------------------
 * Primitive types (guarded against linux/types.h redefinition)
 * ----------------------------------------------------------------------- */
#ifndef _LINUX_TYPES_H
typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef signed int          s32;
typedef _Bool               bool;
#define true  1
#define false 0
#define NULL  ((void *)0)
#endif /* _LINUX_TYPES_H */

/* -----------------------------------------------------------------------
 * Miscellaneous macros
 * ----------------------------------------------------------------------- */
#ifndef offsetof
#define offsetof(t, m)      __builtin_offsetof(t, m)
#endif
#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#endif
#ifndef unlikely
#define unlikely(x)         (x)
#endif
#ifndef likely
#define likely(x)           (x)
#endif
#ifndef WARN_ON_ONCE
#define WARN_ON_ONCE(c)     (0)
#endif
#ifndef READ_ONCE
#define READ_ONCE(x)        (x)
#endif
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v)    do { (x) = (v); } while (0)
#endif
#ifndef __cacheline_aligned_in_smp
#define __cacheline_aligned_in_smp
#endif
#ifndef ____cacheline_aligned_in_smp
#define ____cacheline_aligned_in_smp
#endif

/* -----------------------------------------------------------------------
 * Spinlock stubs (no-op: BPF is single-threaded)
 * ----------------------------------------------------------------------- */
typedef struct { int dummy; } raw_spinlock_t;
#define raw_spin_lock_init(l)                   do {} while (0)
#define raw_spin_lock(l)                        do {} while (0)
#define raw_spin_unlock(l)                      do {} while (0)
#define raw_spin_lock_irqsave(l, f)             do { (void)(f); } while (0)
#define raw_spin_unlock_irqrestore(l, f)        do { (void)(f); } while (0)

/* -----------------------------------------------------------------------
 * Doubly-linked list (minimal linux/list.h subset)
 * linux/types.h already defines struct list_head, so guard it.
 * ----------------------------------------------------------------------- */
#ifndef _LINUX_TYPES_H
struct list_head {
    struct list_head *next, *prev;
};
#endif /* _LINUX_TYPES_H */

static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

static inline int list_empty(const struct list_head *head)
{
    return head->next == head;
}

static inline void __list_add(struct list_head *new_,
    struct list_head *prev, struct list_head *next)
{
    next->prev = new_;
    new_->next = next;
    new_->prev = prev;
    prev->next = new_;
}

static inline void list_add(struct list_head *new_,
    struct list_head *head)
{
    __list_add(new_, head, head->next);
}

static inline void list_add_tail(struct list_head *new_,
    struct list_head *head)
{
    __list_add(new_, head->prev, head);
}

static inline void __list_del(struct list_head *prev,
    struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = NULL;
    entry->prev = NULL;
}

static inline void list_move(struct list_head *list,
    struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add(list, head);
}

#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)

#define list_first_entry_or_null(ptr, type, member) \
    (!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)

/* list_for_each_entry_safe_reverse: iterate backwards, safe for deletion */
#define list_for_each_entry_safe_reverse(pos, n, head, member)          \
    for (pos = list_entry((head)->prev, __typeof__(*pos), member),      \
         n   = list_entry(pos->member.prev, __typeof__(*pos), member);  \
         &pos->member != (head);                                         \
         pos = n,                                                        \
         n   = list_entry(n->member.prev, __typeof__(*n), member))

/* list_for_each_entry_safe: iterate forwards, safe for deletion */
#define list_for_each_entry_safe(pos, n, head, member)                  \
    for (pos = list_entry((head)->next, __typeof__(*pos), member),      \
         n   = list_entry(pos->member.next, __typeof__(*pos), member);  \
         &pos->member != (head);                                         \
         pos = n,                                                        \
         n   = list_entry(n->member.next, __typeof__(*n), member))

/* list_for_each_entry_reverse: iterate backwards, NOT safe for deletion */
#define list_for_each_entry_reverse(pos, head, member)                  \
    for (pos = list_entry((head)->prev, __typeof__(*pos), member);      \
         &pos->member != (head);                                         \
         pos = list_entry(pos->member.prev, __typeof__(*pos), member))

/* -----------------------------------------------------------------------
 * bpf_lru_list types (from bpf_lru_list.h, verbatim)
 * ----------------------------------------------------------------------- */
#define NR_BPF_LRU_LIST_T       (3)
#define NR_BPF_LRU_LIST_COUNT   (2)
#define NR_BPF_LRU_LOCAL_LIST_T (2)
#define BPF_LOCAL_LIST_T_OFFSET  NR_BPF_LRU_LIST_T

enum bpf_lru_list_type {
    BPF_LRU_LIST_T_ACTIVE,
    BPF_LRU_LIST_T_INACTIVE,
    BPF_LRU_LIST_T_FREE,
    BPF_LRU_LOCAL_LIST_T_FREE,
    BPF_LRU_LOCAL_LIST_T_PENDING,
};

struct bpf_lru_node {
    struct list_head list;
    u16 cpu;
    u8  type;
    u8  ref;
};

struct bpf_lru_list {
    struct list_head lists[NR_BPF_LRU_LIST_T];
    unsigned int     counts[NR_BPF_LRU_LIST_COUNT];
    struct list_head *next_inactive_rotation;
    raw_spinlock_t   lock ____cacheline_aligned_in_smp;
};

struct bpf_lru_locallist {
    struct list_head lists[NR_BPF_LRU_LOCAL_LIST_T];
    u16              next_steal;
    raw_spinlock_t   lock;
};

struct bpf_common_lru {
    struct bpf_lru_list      lru_list;
    struct bpf_lru_locallist *local_list; /* single-CPU stub (no percpu) */
};

typedef bool (*del_from_htab_func)(void *arg, struct bpf_lru_node *node);

struct bpf_lru {
    union {
        struct bpf_common_lru  common_lru;
        struct bpf_lru_list   *percpu_lru; /* unused in shim */
    };
    del_from_htab_func del_from_htab;
    void              *del_arg;
    unsigned int       hash_offset;
    unsigned int       nr_scans;
    bool               percpu;
};

static inline void bpf_lru_node_set_ref(
    struct bpf_lru_node *node)
{
    if (!READ_ONCE(node->ref))
        WRITE_ONCE(node->ref, 1);
}

/* -----------------------------------------------------------------------
 * Constants from bpf_lru_list.c
 * ----------------------------------------------------------------------- */
#define LOCAL_FREE_TARGET    (128)
#define LOCAL_NR_SCANS       LOCAL_FREE_TARGET
#define PERCPU_FREE_TARGET   (4)
#define PERCPU_NR_SCANS      PERCPU_FREE_TARGET

#define LOCAL_LIST_IDX(t)       ((t) - BPF_LOCAL_LIST_T_OFFSET)
#define LOCAL_FREE_LIST_IDX     LOCAL_LIST_IDX(BPF_LRU_LOCAL_LIST_T_FREE)
#define LOCAL_PENDING_LIST_IDX  LOCAL_LIST_IDX(BPF_LRU_LOCAL_LIST_T_PENDING)
#define IS_LOCAL_LIST_TYPE(t)   ((t) >= BPF_LOCAL_LIST_T_OFFSET)

/* -----------------------------------------------------------------------
 * Core algorithm functions -- copied verbatim from bpf_lru_list.c (Linux 6.1)
 * ----------------------------------------------------------------------- */

static inline
struct list_head *local_free_list(struct bpf_lru_locallist *loc_l)
{
    return &loc_l->lists[LOCAL_FREE_LIST_IDX];
}

static inline
struct list_head *local_pending_list(struct bpf_lru_locallist *loc_l)
{
    return &loc_l->lists[LOCAL_PENDING_LIST_IDX];
}

static inline
bool bpf_lru_node_is_ref(const struct bpf_lru_node *node)
{
    return READ_ONCE(node->ref);
}

static inline
void bpf_lru_node_clear_ref(struct bpf_lru_node *node)
{
    WRITE_ONCE(node->ref, 0);
}

static inline
void bpf_lru_list_count_inc(struct bpf_lru_list *l,
                             enum bpf_lru_list_type type)
{
    if (type < NR_BPF_LRU_LIST_COUNT)
        l->counts[type]++;
}

static inline
void bpf_lru_list_count_dec(struct bpf_lru_list *l,
                             enum bpf_lru_list_type type)
{
    if (type < NR_BPF_LRU_LIST_COUNT)
        l->counts[type]--;
}

static __attribute__((always_inline))
void __bpf_lru_node_move_to_free(struct bpf_lru_list *l,
                                  struct bpf_lru_node *node,
                                  struct list_head *free_list,
                                  enum bpf_lru_list_type tgt_free_type)
{
    if (WARN_ON_ONCE(IS_LOCAL_LIST_TYPE(node->type)))
        return;

    if (&node->list == l->next_inactive_rotation)
        l->next_inactive_rotation = l->next_inactive_rotation->prev;

    bpf_lru_list_count_dec(l, node->type);

    node->type = tgt_free_type;
    list_move(&node->list, free_list);
}

static __attribute__((always_inline))
void __bpf_lru_node_move_in(struct bpf_lru_list *l,
                             struct bpf_lru_node *node,
                             enum bpf_lru_list_type tgt_type)
{
    if (WARN_ON_ONCE(!IS_LOCAL_LIST_TYPE(node->type)) ||
        WARN_ON_ONCE(IS_LOCAL_LIST_TYPE(tgt_type)))
        return;

    bpf_lru_list_count_inc(l, tgt_type);
    node->type = tgt_type;
    bpf_lru_node_clear_ref(node);
    list_move(&node->list, &l->lists[tgt_type]);
}

static __attribute__((always_inline))
void __bpf_lru_node_move(struct bpf_lru_list *l,
                          struct bpf_lru_node *node,
                          enum bpf_lru_list_type tgt_type)
{
    if (WARN_ON_ONCE(IS_LOCAL_LIST_TYPE(node->type)) ||
        WARN_ON_ONCE(IS_LOCAL_LIST_TYPE(tgt_type)))
        return;

    if (node->type != tgt_type) {
        bpf_lru_list_count_dec(l, node->type);
        bpf_lru_list_count_inc(l, tgt_type);
        node->type = tgt_type;
    }
    bpf_lru_node_clear_ref(node);

    if (&node->list == l->next_inactive_rotation)
        l->next_inactive_rotation = l->next_inactive_rotation->prev;

    list_move(&node->list, &l->lists[tgt_type]);
}

static inline
bool bpf_lru_list_inactive_low(const struct bpf_lru_list *l)
{
    return l->counts[BPF_LRU_LIST_T_INACTIVE] <
           l->counts[BPF_LRU_LIST_T_ACTIVE];
}

static __attribute__((always_inline))
void __bpf_lru_list_rotate_active(struct bpf_lru *lru,
                                   struct bpf_lru_list *l)
{
    struct list_head *active = &l->lists[BPF_LRU_LIST_T_ACTIVE];
    struct bpf_lru_node *node, *tmp_node, *first_node;
    unsigned int i = 0;

    first_node = list_first_entry(active, struct bpf_lru_node, list);
    list_for_each_entry_safe_reverse(node, tmp_node, active, list) {
        if (bpf_lru_node_is_ref(node))
            __bpf_lru_node_move(l, node, BPF_LRU_LIST_T_ACTIVE);
        else
            __bpf_lru_node_move(l, node, BPF_LRU_LIST_T_INACTIVE);

        if (++i == lru->nr_scans || node == first_node)
            break;
    }
}

static __attribute__((always_inline))
void __bpf_lru_list_rotate_inactive(struct bpf_lru *lru,
                                     struct bpf_lru_list *l)
{
    struct list_head *inactive = &l->lists[BPF_LRU_LIST_T_INACTIVE];
    struct list_head *cur, *last, *next = inactive;
    struct bpf_lru_node *node;
    unsigned int i = 0;

    if (list_empty(inactive))
        return;

    last = l->next_inactive_rotation->next;
    if (last == inactive)
        last = last->next;

    cur = l->next_inactive_rotation;
    while (i < lru->nr_scans) {
        if (cur == inactive) {
            cur = cur->prev;
            continue;
        }

        node = list_entry(cur, struct bpf_lru_node, list);
        next = cur->prev;
        if (bpf_lru_node_is_ref(node))
            __bpf_lru_node_move(l, node, BPF_LRU_LIST_T_ACTIVE);
        if (cur == last)
            break;
        cur = next;
        i++;
    }

    l->next_inactive_rotation = next;
}

static __attribute__((always_inline))
unsigned int __bpf_lru_list_shrink_inactive(struct bpf_lru *lru,
                                             struct bpf_lru_list *l,
                                             unsigned int tgt_nshrink,
                                             struct list_head *free_list,
                                             enum bpf_lru_list_type tgt_free_type)
{
    struct list_head *inactive = &l->lists[BPF_LRU_LIST_T_INACTIVE];
    struct bpf_lru_node *node, *tmp_node;
    unsigned int nshrinked = 0;
    unsigned int i = 0;

    list_for_each_entry_safe_reverse(node, tmp_node, inactive, list) {
        if (bpf_lru_node_is_ref(node)) {
            __bpf_lru_node_move(l, node, BPF_LRU_LIST_T_ACTIVE);
        } else if (lru->del_from_htab(lru->del_arg, node)) {
            __bpf_lru_node_move_to_free(l, node, free_list,
                                        tgt_free_type);
            if (++nshrinked == tgt_nshrink)
                break;
        }

        if (++i == lru->nr_scans)
            break;
    }

    return nshrinked;
}

static inline
void __bpf_lru_list_rotate(struct bpf_lru *lru, struct bpf_lru_list *l)
{
    if (bpf_lru_list_inactive_low(l))
        __bpf_lru_list_rotate_active(lru, l);

    __bpf_lru_list_rotate_inactive(lru, l);
}

static __attribute__((always_inline))
void __local_list_flush(struct bpf_lru_list *l,
                         struct bpf_lru_locallist *loc_l)
{
    struct bpf_lru_node *node, *tmp_node;

    list_for_each_entry_safe_reverse(node, tmp_node,
                                     local_pending_list(loc_l), list) {
        if (bpf_lru_node_is_ref(node))
            __bpf_lru_node_move_in(l, node, BPF_LRU_LIST_T_ACTIVE);
        else
            __bpf_lru_node_move_in(l, node, BPF_LRU_LIST_T_INACTIVE);
    }
}

/* -----------------------------------------------------------------------
 * Initialisation helpers (simplified single-CPU versions)
 * ----------------------------------------------------------------------- */
static inline
void bpf_lru_list_init(struct bpf_lru_list *l)
{
    int i;
    for (i = 0; i < NR_BPF_LRU_LIST_T; i++)
        INIT_LIST_HEAD(&l->lists[i]);
    for (i = 0; i < NR_BPF_LRU_LIST_COUNT; i++)
        l->counts[i] = 0;
    l->next_inactive_rotation = &l->lists[BPF_LRU_LIST_T_INACTIVE];
    raw_spin_lock_init(&l->lock);
}

static inline
void bpf_lru_locallist_init(struct bpf_lru_locallist *loc_l, int cpu)
{
    int i;
    for (i = 0; i < NR_BPF_LRU_LOCAL_LIST_T; i++)
        INIT_LIST_HEAD(&loc_l->lists[i]);
    loc_l->next_steal = (u16)cpu;
    raw_spin_lock_init(&loc_l->lock);
}

/* Populate the free list with a static array of nodes */
static __attribute__((always_inline))
void bpf_lru_list_populate(struct bpf_lru_list *l,
                             struct bpf_lru_node *nodes, u32 nr_elems)
{
    u32 i;
    for (i = 0; i < nr_elems; i++) {
        nodes[i].type = BPF_LRU_LIST_T_FREE;
        nodes[i].ref  = 0;
        nodes[i].cpu  = 0;
        list_add(&nodes[i].list, &l->lists[BPF_LRU_LIST_T_FREE]);
    }
}

/* Move the first node from the free list to inactive (simulate "use") */
static inline
struct bpf_lru_node *bpf_lru_list_alloc(struct bpf_lru_list *l)
{
    struct list_head *free = &l->lists[BPF_LRU_LIST_T_FREE];
    struct bpf_lru_node *node;

    if (list_empty(free))
        return NULL;

    node = list_first_entry(free, struct bpf_lru_node, list);
    bpf_lru_list_count_inc(l, BPF_LRU_LIST_T_INACTIVE);
    node->type = BPF_LRU_LIST_T_INACTIVE;
    bpf_lru_node_clear_ref(node);
    list_move(&node->list, &l->lists[BPF_LRU_LIST_T_INACTIVE]);
    return node;
}
