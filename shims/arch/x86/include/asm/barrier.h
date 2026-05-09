/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF shim: asm/barrier.h
 *
 * x86 barrier.h uses inline asm (mfence, lfence, sfence, lock addl) which
 * is not valid in BPF context.
 *
 * BPF verification is single-threaded, so memory ordering and speculation
 * barriers can be modeled as no-ops while preserving the source API shape.
 */
#ifndef _ASM_X86_BARRIER_H
#define _ASM_X86_BARRIER_H

#define barrier()	do { } while (0)
#define barrier_data(ptr) do { (void)(ptr); } while (0)
#define nop()		do { } while (0)

#define mb()		barrier()
#define rmb()		barrier()
#define wmb()		barrier()

/* Internal barrier primitives used by asm-generic/barrier.h */
#define __mb()		barrier()
#define __rmb()		barrier()
#define __wmb()		barrier()

/* DMA barriers */
#define __dma_rmb()	barrier()
#define __dma_wmb()	barrier()

/* SMP barriers */
#define __smp_mb()	barrier()
#define __smp_rmb()	barrier()
#define __smp_wmb()	barrier()

#define __smp_mb__before_atomic() do {} while (0)
#define __smp_mb__after_atomic()  do {} while (0)

/* __smp_store_mb: store + full barrier */
#define __smp_store_mb(var, value) do { (var) = (value); barrier(); } while (0)

/* __smp_store_release / __smp_load_acquire: acquire/release semantics */
#define __smp_store_release(p, v)					\
do {									\
	barrier();							\
	WRITE_ONCE(*p, v);						\
} while (0)

#define __smp_load_acquire(p)					\
({								\
	typeof(*p) ___p1 = READ_ONCE(*p);			\
	barrier();						\
	___p1;							\
})

static inline unsigned long array_index_mask_nospec(unsigned long index,
						    unsigned long size)
{
	return (unsigned long)(-(long)(index < size));
}
#define array_index_mask_nospec array_index_mask_nospec

#define barrier_nospec() barrier()

static inline void weak_wrmsr_fence(void) {}

/* Include asm-generic/barrier.h for smp_load_acquire, smp_store_release etc. */
#include <asm-generic/barrier.h>

#endif /* _ASM_X86_BARRIER_H */
