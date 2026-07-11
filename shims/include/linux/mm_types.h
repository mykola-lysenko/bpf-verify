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
#include <linux/rwsem.h>
#include <asm/pgtable_types.h>

/*
 * Minimal page/folio shapes used by current shimmed header paths. These are
 * not intended to mirror the full kernel layout.
 */
typedef struct {
	unsigned long f;
} memdesc_flags_t;

typedef struct {
	unsigned long val;
} swp_entry_t;

struct address_space;
struct dev_pagemap;

struct page {
	memdesc_flags_t flags;
	union {
		unsigned long compound_info;
		struct list_head lru;
		struct dev_pagemap *pgmap;
		struct {
			void *s_mem;
			unsigned int active;
			int units;
		};
	};
	struct address_space *mapping;
	union {
		pgoff_t index;
		unsigned long share;
	};
	void *zone_device_data;
	union {
		void *private;
		swp_entry_t swap;
	};
	union {
		unsigned int page_type;
		atomic_t _mapcount;
	};
	atomic_t _refcount;
};

struct folio {
	union {
		struct {
			memdesc_flags_t flags;
			union {
				unsigned long compound_info;
				struct list_head lru;
				struct dev_pagemap *pgmap;
			};
			struct address_space *mapping;
			union {
				pgoff_t index;
				unsigned long share;
			};
			void *zone_device_data;
			union {
				void *private;
				swp_entry_t swap;
			};
			union {
				unsigned int page_type;
				atomic_t _mapcount;
			};
			atomic_t _refcount;
		};
		struct page page;
	};
};

/* Forward declarations */
struct mm_struct;
struct anon_vma;
struct mmu_notifier_mm;

typedef unsigned long vm_flags_t;
typedef unsigned int vm_fault_t;
#define NUM_MM_FLAG_BITS	64
typedef struct {
	unsigned long __mm_flags[1];
} mm_flags_t;

enum {
	VM_FAULT_OOM		= 0x000001,
	VM_FAULT_SIGBUS		= 0x000002,
	VM_FAULT_MAJOR		= 0x000004,
	VM_FAULT_HWPOISON	= 0x000010,
	VM_FAULT_SIGSEGV	= 0x000040,
	VM_FAULT_NOPAGE		= 0x000100,
	VM_FAULT_LOCKED		= 0x000200,
	VM_FAULT_RETRY		= 0x000400,
	VM_FAULT_FALLBACK	= 0x000800,
	VM_FAULT_DONE_COW	= 0x001000,
	VM_FAULT_NEEDDSYNC	= 0x002000,
	VM_FAULT_COMPLETED	= 0x004000,
};

enum fault_flag {
	FAULT_FLAG_WRITE		= 1 << 0,
	FAULT_FLAG_MKWRITE		= 1 << 1,
	FAULT_FLAG_ALLOW_RETRY		= 1 << 2,
	FAULT_FLAG_RETRY_NOWAIT		= 1 << 3,
	FAULT_FLAG_KILLABLE		= 1 << 4,
	FAULT_FLAG_TRIED		= 1 << 5,
	FAULT_FLAG_USER			= 1 << 6,
	FAULT_FLAG_REMOTE		= 1 << 7,
	FAULT_FLAG_INSTRUCTION		= 1 << 8,
	FAULT_FLAG_INTERRUPTIBLE	= 1 << 9,
	FAULT_FLAG_UNSHARE		= 1 << 10,
	FAULT_FLAG_ORIG_PTE_VALID	= 1 << 11,
	FAULT_FLAG_VMA_LOCK		= 1 << 12,
};

struct vm_fault;

/* fs.h/mm.h reference these; forward-declared so their inline helpers type-check. */
struct file;
struct vm_area_desc;
struct vm_operations_struct;
struct vm_area_struct {
	unsigned long vm_start;
	unsigned long vm_end;
	unsigned long vm_pgoff;
	struct mm_struct *vm_mm;
	vm_flags_t vm_flags;
	unsigned int vm_lock_seq;
	struct list_head anon_vma_chain;
	struct file *vm_file;
	const struct vm_operations_struct *vm_ops;
};

/* Minimal mm_struct fields accessed by BPF-relevant header chains. */
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
	struct rw_semaphore mmap_lock;
	spinlock_t page_table_lock;
	mm_flags_t flags;
};

/* pgtable_t is defined in asm/pgtable_types.h as struct page * */

#endif /* _LINUX_MM_TYPES_H */
