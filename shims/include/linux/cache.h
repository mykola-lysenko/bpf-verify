/* BPF shim: linux/cache.h
 *
 * The kernel's cache.h uses __section__(".data..cacheline_aligned") and other
 * section attributes that the BPF backend cannot handle.  This shim provides
 * the cache-line constants and alignment macros without section placement.
 */
#ifndef _LINUX_CACHE_H
#define _LINUX_CACHE_H

#include <asm/cache.h>

#ifndef L1_CACHE_ALIGN
#define L1_CACHE_ALIGN(x) ALIGN(x, L1_CACHE_BYTES)
#endif

#ifndef SMP_CACHE_BYTES
#ifdef CONFIG_SMP
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#else
#define SMP_CACHE_BYTES __alignof__(unsigned long long)
#endif
#endif

#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

#ifndef ____cacheline_aligned_in_smp
#ifdef CONFIG_SMP
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#else
#define ____cacheline_aligned_in_smp
#endif
#endif

#ifndef __cacheline_aligned
#define __cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

#ifndef __cacheline_aligned_in_smp
#ifdef CONFIG_SMP
#define __cacheline_aligned_in_smp __cacheline_aligned
#else
#define __cacheline_aligned_in_smp
#endif
#endif

#ifndef __read_mostly
#define __read_mostly
#endif

#ifndef CACHELINE_PADDING_SIZE
#define CACHELINE_PADDING_SIZE SMP_CACHE_BYTES
#endif

struct cacheline_padding {
	char x[CACHELINE_PADDING_SIZE];
} __packed;

#define __cacheline_group_begin(GROUP)
#define __cacheline_group_end(GROUP)

#endif /* _LINUX_CACHE_H */
