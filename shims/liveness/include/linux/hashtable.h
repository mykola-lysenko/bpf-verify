/* SPDX-License-Identifier: GPL-2.0 */
/* Minimal hashtable surface for kernel/bpf/liveness.c. */
#ifndef _LINUX_HASHTABLE_H
#define _LINUX_HASHTABLE_H

#include <linux/bpf.h>

#define DECLARE_HASHTABLE(name, bits) struct hlist_head name[1 << (bits)]

static inline void INIT_HLIST_HEAD(struct hlist_head *h)
{
	h->first = NULL;
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;

	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

static inline void hlist_del(struct hlist_node *n)
{
	if (n->next)
		n->next->pprev = n->pprev;
	if (n->pprev)
		*n->pprev = n->next;
	n->next = NULL;
	n->pprev = NULL;
}

#define hash_init(hashtable)						\
	do {								\
		u32 __i;						\
		for (__i = 0; __i < ARRAY_SIZE(hashtable); __i++)	\
			INIT_HLIST_HEAD(&(hashtable)[__i]);		\
	} while (0)

#define hash_min(val, bits) ((val) & ((1U << (bits)) - 1))

#define hash_add(hashtable, node, key)					\
	hlist_add_head((node), &(hashtable)[hash_min((key), 8)])

#define hlist_entry(ptr, type, member) container_of(ptr, type, member)

#define hash_for_each_possible(hashtable, obj, member, key)			\
	for (obj = (hashtable)[hash_min((key), 8)].first ?			\
	     hlist_entry((hashtable)[hash_min((key), 8)].first, typeof(*(obj)), member) : NULL; \
	     obj; obj = obj->member.next ? hlist_entry(obj->member.next, typeof(*(obj)), member) : NULL)

#define hash_for_each(hashtable, bkt, obj, member)				\
	for ((bkt) = 0; (bkt) < ARRAY_SIZE(hashtable); (bkt)++)		\
		for (obj = (hashtable)[bkt].first ?				\
		     hlist_entry((hashtable)[bkt].first, typeof(*(obj)), member) : NULL; \
		     obj; obj = obj->member.next ? hlist_entry(obj->member.next, typeof(*(obj)), member) : NULL)

#define hash_for_each_safe(hashtable, bkt, tmp, obj, member)			\
	for ((bkt) = 0; (bkt) < ARRAY_SIZE(hashtable); (bkt)++)		\
		for (obj = (hashtable)[bkt].first ?				\
		     hlist_entry((hashtable)[bkt].first, typeof(*(obj)), member) : NULL, \
		     tmp = obj ? obj->member.next : NULL;			\
		     obj;							\
		     obj = tmp ? hlist_entry(tmp, typeof(*(obj)), member) : NULL, \
		     tmp = obj ? obj->member.next : NULL)

#endif /* _LINUX_HASHTABLE_H */
