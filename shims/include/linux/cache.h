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
#ifdef CONFIG_SMP
#define __bpf_cacheline_aligned_in_smp __bpf_cacheline_aligned
#define __bpf_cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(INTERNODE_CACHE_BYTES)))
#else
#define __bpf_cacheline_aligned_in_smp
#define __bpf_cacheline_internodealigned_in_smp
#endif

#undef __read_mostly
#define __read_mostly

#undef __ro_after_init
#define __ro_after_init

#undef ____cacheline_aligned
#define ____cacheline_aligned __bpf_cacheline_aligned

#undef ____cacheline_aligned_in_smp
#define ____cacheline_aligned_in_smp __bpf_cacheline_aligned_in_smp

#undef __cacheline_aligned
#define __cacheline_aligned __bpf_cacheline_aligned

#undef __cacheline_aligned_in_smp
#define __cacheline_aligned_in_smp __bpf_cacheline_aligned_in_smp

#undef ____cacheline_internodealigned_in_smp
#define ____cacheline_internodealigned_in_smp \
	__bpf_cacheline_internodealigned_in_smp

#endif /* _BPF_SHIM_LINUX_CACHE_H */
