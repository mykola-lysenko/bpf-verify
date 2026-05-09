/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * BPF shim: linux/llist.h
 *
 * Keep the real llist API and provide non-atomic replacements for the helpers
 * the harness calls. The real inline helpers use xchg()/try_cmpxchg() on
 * pointer fields, which is not useful for single-threaded BPF verification and
 * can produce verifier-hostile atomics.
 */
#ifndef __BPF_LINUX_LLIST_SHIM_H
#define __BPF_LINUX_LLIST_SHIM_H

/*
 * Load the real atomic macros first, then hide the BPF-hostile ones only while
 * the real llist header defines its static inline helpers.
 */
#include <linux/atomic.h>

/* Rename the real atomic inline helpers while including the kernel header.
 * Pipeline-level macros for lib/llist.c are restored afterwards so that source
 * definitions still get their conflict-avoidance names. */
#pragma push_macro("try_cmpxchg")
#pragma push_macro("xchg")
#pragma push_macro("llist_add_batch")
#pragma push_macro("llist_add")
#pragma push_macro("llist_del_all")
#pragma push_macro("llist_del_first")
#pragma push_macro("llist_del_first_init")

#undef llist_add_batch
#undef llist_add
#undef llist_del_all
#undef llist_del_first
#undef llist_del_first_init
#undef try_cmpxchg
#undef xchg

#define llist_add_batch     __bpf_llist_add_batch_atomic_inline
#define llist_add           __bpf_llist_add_atomic_inline
#define llist_del_all       __bpf_llist_del_all_atomic_inline
#define llist_del_first     __bpf_llist_del_first_atomic_inline
#define llist_del_first_init __bpf_llist_del_first_init_atomic_inline
#define try_cmpxchg(ptr, oldp, new) 1
#define xchg(ptr, val) ({ typeof(*(ptr)) __old = *(ptr); *(ptr) = (val); __old; })

#include_next <linux/llist.h>

#undef llist_add_batch
#undef llist_add
#undef llist_del_all
#undef llist_del_first
#undef llist_del_first_init
#undef try_cmpxchg
#undef xchg

static inline bool llist_add_batch(struct llist_node *new_first,
				   struct llist_node *new_last,
				   struct llist_head *head)
{
	return __llist_add_batch(new_first, new_last, head);
}

static inline bool llist_add(struct llist_node *new,
			     struct llist_head *head)
{
	return __llist_add_batch(new, new, head);
}

static inline struct llist_node *llist_del_all(struct llist_head *head)
{
	return __llist_del_all(head);
}

static inline struct llist_node *llist_del_first(struct llist_head *head)
{
	struct llist_node *entry = head->first;

	if (entry)
		head->first = entry->next;
	return entry;
}

static inline struct llist_node *llist_del_first_init(struct llist_head *head)
{
	struct llist_node *node = llist_del_first(head);

	if (node)
		init_llist_node(node);
	return node;
}

#pragma pop_macro("llist_del_first_init")
#pragma pop_macro("llist_del_first")
#pragma pop_macro("llist_del_all")
#pragma pop_macro("llist_add")
#pragma pop_macro("llist_add_batch")
#pragma pop_macro("xchg")
#pragma pop_macro("try_cmpxchg")

#endif /* __BPF_LINUX_LLIST_SHIM_H */
