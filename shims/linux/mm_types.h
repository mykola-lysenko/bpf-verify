/* BPF shim: linux/mm_types.h
 * The real mm_types.h contains set_mask_bits() with try_cmpxchg() inside
 * static inline functions, which is incompatible with BPF compilation.
 * Provide minimal opaque struct definitions for the types used by other
 * headers (uio.h, slab.h, etc.) without the problematic inline functions.
 */
#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/atomic.h>
#include <asm/pgtable_types.h>

/* Opaque struct page - used as pointer only in most BPF-relevant code */
struct page {
unsigned long flags;
union {
struct list_head lru;
struct {
void *s_mem;
unsigned int active;
int units;
};
};
atomic_t _refcount;
};

/* Opaque struct folio */
struct folio {
union {
struct page page;
};
};

/* Minimal struct mm_struct - only fields accessed by BPF-relevant code */
struct mm_struct {
struct {
struct vm_area_struct __rcu *mmap;
unsigned long mmap_base;
unsigned long task_size;
pgd_t *pgd;
atomic_t mm_users;
atomic_t mm_count;
unsigned long hiwater_rss;
unsigned long hiwater_vm;
unsigned long total_vm;
unsigned long locked_vm;
unsigned long pinned_vm;
unsigned long data_vm;
unsigned long exec_vm;
unsigned long stack_vm;
unsigned long def_flags;
unsigned long start_code, end_code, start_data, end_data;
unsigned long start_brk, brk, start_stack;
unsigned long arg_start, arg_end, env_start, env_end;
};
spinlock_t page_table_lock;
unsigned long flags;
};

/* Forward declarations */
struct vm_area_struct;
struct anon_vma;
struct address_space;
struct mmu_notifier_mm;

/* pgtable_t is defined in asm/pgtable_types.h as struct page * */

#endif /* _LINUX_MM_TYPES_H */
