/* BPF shim: asm/topology.h
 * Replaces the x86-specific topology.h which uses DECLARE_EARLY_PER_CPU,
 * per_cpu() infrastructure, and NUMA-specific types that BPF cannot compile.
 * We provide minimal stubs sufficient for the lib/ targets we care about.
 */
#ifndef _ASM_X86_TOPOLOGY_H
#define _ASM_X86_TOPOLOGY_H

#include <linux/numa.h>

/* Suppress the NUMA block entirely — it uses DECLARE_EARLY_PER_CPU which
 * expands to x86-specific per-CPU infrastructure with inline asm.
 * We unconditionally provide the non-NUMA fallbacks. */
static inline int numa_node_id(void) { return 0; }
#define numa_node_id numa_node_id

static inline int early_cpu_to_node(int cpu) { return 0; }
static inline void setup_node_to_cpumask_map(void) {}

/* Pull in the generic topology layer */
#include <asm-generic/topology.h>

/* x86-specific topology macros — stub out per-CPU lookups */
static inline const struct cpumask *cpu_coregroup_mask(int cpu) { return NULL; }
static inline const struct cpumask *cpu_clustergroup_mask(int cpu) { return NULL; }

#define topology_logical_package_id(cpu)    0
#define topology_physical_package_id(cpu)   0
#define topology_logical_die_id(cpu)        0
#define topology_die_id(cpu)                0
#define topology_core_id(cpu)               0

/* SMP topology stubs */
#define topology_max_packages()             1
static inline int topology_max_die_per_package(void) { return 1; }
static inline int topology_max_smt_threads(void) { return 1; }
static inline int topology_phys_to_logical_pkg(unsigned int pkg) { return 0; }
static inline int topology_phys_to_logical_die(unsigned int die, unsigned int cpu) { return 0; }
static inline int topology_update_package_map(unsigned int apicid, unsigned int cpu) { return 0; }
static inline int topology_update_die_map(unsigned int dieid, unsigned int cpu) { return 0; }

/* ITMT stubs (CONFIG_SCHED_MC_PRIO) */
#define sysctl_sched_itmt_enabled   0
static inline void sched_set_itmt_core_prio(int prio, int core_cpu) {}
static inline int sched_set_itmt_support(void) { return 0; }
static inline void sched_clear_itmt_support(void) {}

/* Frequency invariance stubs */
static inline void arch_set_max_freq_ratio(int turbo_disabled) {}
static inline void freq_invariance_set_perf_ratio(unsigned long long ratio, int turbo_disabled) {}
static inline void arch_scale_freq_tick(void) {}

#endif /* _ASM_X86_TOPOLOGY_H */
