/* BPF shim: linux/llist.h
 * llist_del_all uses xchg() on a pointer which is not valid in BPF.
 * Include the real llist.h but override llist_del_all with a non-atomic version.
 */
#ifndef BPF_SHIM_LINUX_LLIST_H
#define BPF_SHIM_LINUX_LLIST_H

/* Rename the atomic version before including the real header */
#define llist_del_all __llist_del_all_atomic
#include_next <linux/llist.h>
#undef llist_del_all

/* BPF-safe non-atomic version of llist_del_all */
static inline struct llist_node *llist_del_all(struct llist_head *head)
{
struct llist_node *first = head->first;
head->first = NULL;
return first;
}

#endif /* BPF_SHIM_LINUX_LLIST_H */
