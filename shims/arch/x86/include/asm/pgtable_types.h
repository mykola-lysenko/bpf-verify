/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF shim: asm/pgtable_types.h
 *
 * The real x86 pgtable_types.h defines page table entry types (pte_t, pmd_t,
 * pud_t, pgd_t, pgprot_t) and pgtable_t. These are needed by mm_types.h
 * (struct page uses pgtable_t) and other kernel headers.
 *
 * This shim provides minimal opaque type stubs sufficient for BPF compilation
 * of lib/ targets. We don't need actual page table manipulation — just the
 * type definitions to satisfy struct declarations.
 *
 * Note: pgtable_t is normally 'typedef struct page *pgtable_t', but since
 * struct page uses pgtable_t internally, we define it as 'void *' here to
 * break the circular dependency.
 */
#ifndef _ASM_X86_PGTABLE_DEFS_H
#define _ASM_X86_PGTABLE_DEFS_H

#include <linux/types.h>

/* Underlying scalar types for page table entries */
typedef unsigned long pteval_t;
typedef unsigned long pmdval_t;
typedef unsigned long pudval_t;
typedef unsigned long p4dval_t;
typedef unsigned long pgdval_t;
typedef unsigned long pgprotval_t;

/* Page table entry types as single-field structs (matching kernel convention) */
typedef struct { pteval_t pte; }   pte_t;
typedef struct { pmdval_t pmd; }   pmd_t;
typedef struct { pudval_t pud; }   pud_t;
typedef struct { p4dval_t p4d; }   p4d_t;
typedef struct { pgdval_t pgd; }   pgd_t;
typedef struct { pgprotval_t pgprot; } pgprot_t;

/* pgtable_t: normally 'struct page *' but defined as void * here to avoid
 * circular dependency with struct page in mm_types.h */
typedef void *pgtable_t;

/* Helper macros */
#define __pgprot(x)  ((pgprot_t) { (x) })
#define pgprot_val(x) ((x).pgprot)
#define __pgd(x)     ((pgd_t) { (x) })
#define pgd_val(x)   ((x).pgd)
#define __p4d(x)     ((p4d_t) { (x) })
#define p4d_val(x)   ((x).p4d)
#define __pud(x)     ((pud_t) { (x) })
#define pud_val(x)   ((x).pud)
#define __pmd(x)     ((pmd_t) { (x) })
#define pmd_val(x)   ((x).pmd)
#define __pte(x)     ((pte_t) { (x) })
#define pte_val(x)   ((x).pte)

/* PAGE_NONE/SHARED/COPY/EXEC/READ protection bits stubs */
#define PAGE_NONE    __pgprot(0)
#define PAGE_SHARED  __pgprot(0)
#define PAGE_COPY    __pgprot(0)
#define PAGE_READONLY __pgprot(0)
#define PAGE_KERNEL  __pgprot(0)

/* _PAGE_* bit definitions (minimal set needed by mm_types.h users) */
#define _PAGE_BIT_PRESENT   0
#define _PAGE_BIT_RW        1
#define _PAGE_BIT_USER      2
#define _PAGE_BIT_PWT       3
#define _PAGE_BIT_PCD       4
#define _PAGE_BIT_ACCESSED  5
#define _PAGE_BIT_DIRTY     6
#define _PAGE_BIT_PSE       7
#define _PAGE_BIT_GLOBAL    8
#define _PAGE_BIT_NX        63

#define _PAGE_PRESENT   (1UL << _PAGE_BIT_PRESENT)
#define _PAGE_RW        (1UL << _PAGE_BIT_RW)
#define _PAGE_USER      (1UL << _PAGE_BIT_USER)
#define _PAGE_ACCESSED  (1UL << _PAGE_BIT_ACCESSED)
#define _PAGE_DIRTY     (1UL << _PAGE_BIT_DIRTY)
#define _PAGE_PSE       (1UL << _PAGE_BIT_PSE)
#define _PAGE_GLOBAL    (1UL << _PAGE_BIT_GLOBAL)
#define _PAGE_NX        (1UL << _PAGE_BIT_NX)

/* PGD_ALLOWED_BITS stub */
#define PGD_ALLOWED_BITS (~0UL)

#endif /* _ASM_X86_PGTABLE_DEFS_H */
