/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BPF_VERIFY_KERNEL_BPF_SHIM_COMMON_H
#define BPF_VERIFY_KERNEL_BPF_SHIM_COMMON_H

#ifndef _LINUX_TYPES_H
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed int         s32;
typedef signed long long   s64;
typedef u8                 __u8;
typedef u16                __u16;
typedef u32                __u32;
typedef u64                __u64;
typedef __SIZE_TYPE__      size_t;
typedef _Bool              bool;
#endif

#ifndef __be32
#define __be32 __u32
#define __be16 __u16
#define __be64 __u64
#endif
#ifndef true
#define true  1
#endif
#ifndef false
#define false 0
#endif
#ifndef NULL
#define NULL  ((void *)0)
#endif

#ifndef offsetof
#define offsetof(t, m)      __builtin_offsetof(t, m)
#endif
#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#endif
#ifndef min
#define min(a, b)           ((a) < (b) ? (a) : (b))
#endif
#ifndef likely
#define likely(x)           (x)
#endif
#ifndef unlikely
#define unlikely(x)         (x)
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
#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(e)     do { } while (0)
#endif
#ifndef BIT
#define BIT(n)              (1u << (n))
#endif
#ifndef __cacheline_aligned_in_smp
#define __cacheline_aligned_in_smp
#endif
#ifndef ____cacheline_aligned_in_smp
#define ____cacheline_aligned_in_smp
#endif

#ifndef GFP_NOWAIT
#define GFP_NOWAIT          0
#endif
#ifndef GFP_ATOMIC
#define GFP_ATOMIC          0
#endif
#ifndef __GFP_NOWARN
#define __GFP_NOWARN        0
#endif
#ifndef NUMA_NO_NODE
#define NUMA_NO_NODE        (-1)
#endif
#ifndef BPF_ANY
#define BPF_ANY             0
#endif
#ifndef BPF_NOEXIST
#define BPF_NOEXIST         1
#endif
#ifndef BPF_EXIST
#define BPF_EXIST           2
#endif
#ifndef EINVAL
#define EINVAL              22
#endif
#ifndef ENOMEM
#define ENOMEM              12
#endif
#ifndef ENOENT
#define ENOENT              2
#endif
#ifndef EEXIST
#define EEXIST              17
#endif
#ifndef ENOSPC
#define ENOSPC              28
#endif
#ifndef KMALLOC_MAX_SIZE
#define KMALLOC_MAX_SIZE    (1u << 22)
#endif

typedef unsigned long irqflags_t;
typedef struct { int dummy; } raw_spinlock_t;
typedef struct { int dummy; } rqspinlock_t;

#define raw_spin_lock_init(l)                   do {} while (0)
#define raw_spin_lock(l)                        do {} while (0)
#define raw_spin_unlock(l)                      do {} while (0)
#define raw_spin_lock_irqsave(l, f)             do { (void)(f); } while (0)
#define raw_spin_unlock_irqrestore(l, f)        do { (void)(f); } while (0)
#define spin_lock_init(l)                       do {} while (0)
#define spin_lock_irqsave(l, f)                 do { (void)(f); } while (0)
#define spin_unlock_irqrestore(l, f)            do { (void)(f); } while (0)

#define __rcu
#define rcu_dereference(p)                      (p)
#define rcu_dereference_check(p, c)             (p)
#define rcu_dereference_protected(p, c)         (p)
#define rcu_access_pointer(p)                   (p)
#define rcu_assign_pointer(p, v)                do { (p) = (v); } while (0)
#define RCU_INIT_POINTER(p, v)                  do { (p) = (v); } while (0)
#define rcu_read_lock_bh_held()                 1
#ifndef rcu_head
struct rcu_head { void *next; void (*func)(struct rcu_head *); };
#endif
#define kfree_rcu(ptr, rcu_field)               do { (void)(ptr); } while (0)

#ifndef _LINUX_TYPES_H
struct list_head {
    struct list_head *next, *prev;
};
#endif

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

static inline void list_add(struct list_head *new_, struct list_head *head)
{
    __list_add(new_, head, head->next);
}

static inline void list_add_tail(struct list_head *new_, struct list_head *head)
{
    __list_add(new_, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
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

static inline void list_move(struct list_head *list, struct list_head *head)
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
#define list_for_each_entry_safe_reverse(pos, n, head, member)          \
    for (pos = list_entry((head)->prev, __typeof__(*pos), member),      \
         n   = list_entry(pos->member.prev, __typeof__(*pos), member);  \
         &pos->member != (head);                                        \
         pos = n,                                                       \
         n   = list_entry(n->member.prev, __typeof__(*n), member))
#define list_for_each_entry_safe(pos, n, head, member)                  \
    for (pos = list_entry((head)->next, __typeof__(*pos), member),      \
         n   = list_entry(pos->member.next, __typeof__(*pos), member);  \
         &pos->member != (head);                                        \
         pos = n,                                                       \
         n   = list_entry(n->member.next, __typeof__(*n), member))
#define list_for_each_entry_reverse(pos, head, member)                  \
    for (pos = list_entry((head)->prev, __typeof__(*pos), member);      \
         &pos->member != (head);                                        \
         pos = list_entry(pos->member.prev, __typeof__(*pos), member))

#endif /* BPF_VERIFY_KERNEL_BPF_SHIM_COMMON_H */
