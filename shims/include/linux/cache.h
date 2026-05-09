/* BPF shim: linux/cache.h
 * #include_next the real header, then override macros that use
 * __section__ (BPF backend rejects custom ELF sections). */
#ifndef _BPF_SHIM_LINUX_CACHE_H
#define _BPF_SHIM_LINUX_CACHE_H

#ifndef CONFIG_X86_INTERNODE_CACHE_SHIFT
#define CONFIG_X86_INTERNODE_CACHE_SHIFT 6
#endif

#include_next <linux/cache.h>

#define __bpf_cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))

#undef __read_mostly
#define __read_mostly

#undef __ro_after_init
#define __ro_after_init

#undef ____cacheline_aligned
#define ____cacheline_aligned __bpf_cacheline_aligned

#undef ____cacheline_aligned_in_smp
#ifdef CONFIG_SMP
#define ____cacheline_aligned_in_smp __bpf_cacheline_aligned
#else
#define ____cacheline_aligned_in_smp
#endif

#undef __cacheline_aligned
#define __cacheline_aligned __bpf_cacheline_aligned

#undef __cacheline_aligned_in_smp
#ifdef CONFIG_SMP
#define __cacheline_aligned_in_smp __bpf_cacheline_aligned
#else
#define __cacheline_aligned_in_smp
#endif

#undef ____cacheline_internodealigned_in_smp
#ifdef CONFIG_SMP
#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(INTERNODE_CACHE_BYTES)))
#else
#define ____cacheline_internodealigned_in_smp
#endif

#endif /* _BPF_SHIM_LINUX_CACHE_H */
