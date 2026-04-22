/*
 * Standalone autoconf.h for BPF compilation of kernel sources.
 *
 * This replaces the kernel build system's generated autoconf.h with the
 * minimal set of CONFIG_* symbols required for the header chains that
 * the bpf-verify pipeline pulls in.  It is designed for x86_64.
 *
 * The pipeline's -UCONFIG_* flags and harness #undef blocks override
 * symbols that conflict with BPF compilation (see pipeline.py).
 */
#ifndef __GENERATED_AUTOCONF_H
#define __GENERATED_AUTOCONF_H

/* ── Architecture ───────────────────────────────────────────────────── */
#define CONFIG_X86 1
#define CONFIG_X86_64 1
#define CONFIG_64BIT 1
#define CONFIG_ARCH_MMAP_RND_BITS 28
#define CONFIG_ARCH_MMAP_RND_COMPAT_BITS 8

/* ── SMP / preemption ───────────────────────────────────────────────── */
#define CONFIG_SMP 1
#define CONFIG_NR_CPUS 256
#define CONFIG_PREEMPT_COUNT 1

/* ── Page / cache geometry ──────────────────────────────────────────── */
#define CONFIG_PAGE_SHIFT 12
#define CONFIG_X86_L1_CACHE_SHIFT 6
#define CONFIG_ARCH_DMA_MINALIGN 1

/* ── Timer ──────────────────────────────────────────────────────────── */
#define CONFIG_HZ 250
#define CONFIG_HZ_250 1

/* ── Memory model ───────────────────────────────────────────────────── */
#define CONFIG_SPARSEMEM 1
#define CONFIG_SPARSEMEM_VMEMMAP 1
#define CONFIG_FLATMEM 1
#define CONFIG_PHYS_ADDR_T_64BIT 1
#define CONFIG_ARCH_PHYS_ADDR_T_64BIT 1

/* ── Printk / debug (expected by pipeline.py overrides) ─────────────── */
#define CONFIG_PRINTK 1
#define CONFIG_DEBUG_LIST 1
#define CONFIG_LIST_HARDENED 1
#define CONFIG_DEBUG_BUGVERBOSE 1

/* ── BPF ────────────────────────────────────────────────────────────── */
#define CONFIG_BPF 1
#define CONFIG_BPF_SYSCALL 1
#define CONFIG_BPF_JIT 1

/* ── Networking (needed for net_dim, skb, etc.) ─────────────────────── */
#define CONFIG_NET 1
#define CONFIG_INET 1

/* ── Block layer ────────────────────────────────────────────────────── */
#define CONFIG_BLOCK 1

/* ── Crypto (needed for aes, sha256, poly1305, chacha, blake2s) ──── */
#define CONFIG_CRYPTO 1

/* ── File systems (some headers check these) ────────────────────────── */
#define CONFIG_PROC_FS 1
#define CONFIG_SYSFS 1

/* ── Scheduler ──────────────────────────────────────────────────────── */
#define CONFIG_CGROUPS 1
#define CONFIG_CGROUP_SCHED 1
#define CONFIG_FAIR_GROUP_SCHED 1

/* ── Module support ─────────────────────────────────────────────────── */
#define CONFIG_MODULES 1
#define CONFIG_MODULE_UNLOAD 1

/* ── Tracing (some headers check CONFIG_TRACEPOINTS) ────────────────── */
#define CONFIG_TRACEPOINTS 1

/* ── Misc arch features ─────────────────────────────────────────────── */
#define CONFIG_X86_TSC 1
#define CONFIG_X86_CMPXCHG64 1

/* ── RCU ────────────────────────────────────────────────────────────── */
#define CONFIG_TREE_RCU 1
#define CONFIG_SRCU 1

/* ── Locking (avoid CONFIG_LOCKDEP/CONFIG_PROVE_LOCKING — they pull
 *    in heavy debugging infrastructure incompatible with BPF) ────── */
#define CONFIG_MUTEX_SPIN_ON_OWNER 1
#define CONFIG_RWSEM_SPIN_ON_OWNER 1

/* ── NUMA: intentionally NOT defined — the pipeline uses -UCONFIG_NUMA
 *    to avoid pulling in asm/sparsemem.h and deep MM headers.
 *    Do not add CONFIG_NUMA here.
 * ── PARAVIRT: intentionally NOT defined — the harness template undefs
 *    it to avoid x86 inline asm in paravirt.h.
 * ── MEMCG: intentionally NOT defined — same reason.
 * ── UPROBES: intentionally NOT defined — -UCONFIG_UPROBES in pipeline.
 */

#endif /* __GENERATED_AUTOCONF_H */
