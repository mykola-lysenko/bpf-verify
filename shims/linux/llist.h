/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * BPF shim: linux/llist.h
 *
 * The real llist.h includes linux/atomic.h and uses xchg() in llist_del_all().
 * xchg() calls arch_xchg() which is not available in BPF context when
 * atomic-instrumented.h is processed before asm/cmpxchg.h is included.
 *
 * This shim replaces the real llist.h entirely:
 *  - Omits the linux/atomic.h include (not needed for BPF)
 *  - Replaces llist_del_all() with the non-atomic __llist_del_all() body
 *  - All other declarations are identical to the real header
 *
 * The LLIST_H guard is defined here so the real header is never included.
 */
#ifndef LLIST_H
#define LLIST_H

#include <linux/container_of.h>
#include <linux/stddef.h>
#include <linux/types.h>

struct llist_head {
	struct llist_node *first;
};

struct llist_node {
	struct llist_node *next;
};

#define LLIST_HEAD_INIT(name)	{ NULL }
#define LLIST_HEAD(name)	struct llist_head name = LLIST_HEAD_INIT(name)

static inline void init_llist_head(struct llist_head *list)
{
	list->first = NULL;
}

/**
 * llist_entry - get the struct of this entry
 * @ptr:	the &struct llist_node pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the llist_node within the struct.
 */
#define llist_entry(ptr, type, member)		\
	container_of(ptr, type, member)

/**
 * member_address_is_nonnull - check whether the member address is not NULL
 * @ptr:	the object pointer (struct type * that contains the llist_node)
 * @member:	the name of the llist_node within the struct.
 *
 * This macro is conceptually the same as
 *	&ptr->member != NULL
 * but it works around the fact that compilers can decide that taking the
 * address of a member of a pointer to a structure is never NULL.
 */
#define member_address_is_nonnull(ptr, member)	\
	((uintptr_t)(ptr) + offsetof(typeof(*(ptr)), member) != 0)

#define llist_for_each(pos, node)			\
	for ((pos) = (node); pos; (pos) = (pos)->next)

#define llist_for_each_safe(pos, n, node)			\
	for ((pos) = (node); (pos) && ((n) = (pos)->next, true); (pos) = (n))

#define llist_for_each_entry(pos, node, member)				\
	for ((pos) = llist_entry((node), typeof(*(pos)), member);	\
	     member_address_is_nonnull(pos, member);			\
	     (pos) = llist_entry((pos)->member.next, typeof(*(pos)), member))

#define llist_for_each_entry_safe(pos, n, node, member)			       \
	for (pos = llist_entry((node), typeof(*pos), member);		       \
	     member_address_is_nonnull(pos, member) &&			       \
	        (n = llist_entry(pos->member.next, typeof(*n), member), true); \
	     pos = n)

/**
 * llist_empty - tests whether a lock-less list is empty
 * @head:	the list to test
 *
 * BPF shim: uses direct read instead of READ_ONCE() to avoid pulling in
 * linux/atomic.h which triggers the xchg() chain.
 */
static inline bool llist_empty(const struct llist_head *head)
{
	return head->first == NULL;
}

static inline struct llist_node *llist_next(struct llist_node *node)
{
	return node->next;
}

extern bool llist_add_batch(struct llist_node *new_first,
			    struct llist_node *new_last,
			    struct llist_head *head);

static inline bool __llist_add_batch(struct llist_node *new_first,
				     struct llist_node *new_last,
				     struct llist_head *head)
{
	new_last->next = head->first;
	head->first = new_first;
	return new_last->next == NULL;
}

/**
 * llist_add - add a new entry
 * @new:	new entry to be added
 * @head:	the head for your lock-less list
 *
 * Returns true if the list was empty prior to adding this entry.
 */
static inline bool llist_add(struct llist_node *new, struct llist_head *head)
{
	return llist_add_batch(new, new, head);
}

static inline bool __llist_add(struct llist_node *new, struct llist_head *head)
{
	return __llist_add_batch(new, new, head);
}

/**
 * llist_del_all - delete all entries from lock-less list
 * @head:	the head of lock-less list to delete all entries
 *
 * BPF shim: uses non-atomic implementation (__llist_del_all body) instead of
 * xchg() which is not valid in BPF context.
 */
static inline struct llist_node *llist_del_all(struct llist_head *head)
{
	struct llist_node *first = head->first;
	head->first = NULL;
	return first;
}

static inline struct llist_node *__llist_del_all(struct llist_head *head)
{
	struct llist_node *first = head->first;
	head->first = NULL;
	return first;
}

extern struct llist_node *llist_del_first(struct llist_head *head);
struct llist_node *llist_reverse_order(struct llist_node *head);

#endif /* LLIST_H */
