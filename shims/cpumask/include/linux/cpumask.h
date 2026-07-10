/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local cpumask surface for kernel/bpf/cpumask.c. */
#ifndef __LINUX_CPUMASK_H
#define __LINUX_CPUMASK_H

#include <linux/types.h>

#define BPF_CPUMASK_NR_CPUS 8U
#define nr_cpu_ids BPF_CPUMASK_NR_CPUS
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
#define IS_ENABLED(option) (option)
#define IS_ALIGNED(x, a) (((x) & ((typeof(x))(a) - 1)) == 0)

struct cpumask {
	unsigned long bits[1];
};

typedef struct cpumask cpumask_t;

static inline unsigned long *__bpf_cpumask_bits(struct cpumask *cpumask)
{
	return cpumask->bits;
}

static inline const unsigned long *
__bpf_const_cpumask_bits(const struct cpumask *cpumask)
{
	return cpumask->bits;
}

#define cpumask_bits(maskp) __bpf_cpumask_bits((struct cpumask *)(maskp))

static inline unsigned long __bpf_cpumask_valid_mask(void)
{
	return (1UL << BPF_CPUMASK_NR_CPUS) - 1;
}

static inline unsigned int bitmap_size(unsigned int nbits)
{
	(void)nbits;
	return sizeof(unsigned long);
}

static inline void bitmap_copy(unsigned long *dst, const unsigned long *src,
			       unsigned int nbits)
{
	(void)nbits;
	dst[0] = src[0] & __bpf_cpumask_valid_mask();
}

static inline unsigned int cpumask_first(const struct cpumask *srcp)
{
	unsigned int cpu;
	unsigned long bits = srcp->bits[0] & __bpf_cpumask_valid_mask();

	for (cpu = 0; cpu < BPF_CPUMASK_NR_CPUS; cpu++) {
		if (bits & (1UL << cpu))
			return cpu;
	}
	return BPF_CPUMASK_NR_CPUS;
}

static inline unsigned int cpumask_first_zero(const struct cpumask *srcp)
{
	unsigned int cpu;
	unsigned long bits = srcp->bits[0] & __bpf_cpumask_valid_mask();

	for (cpu = 0; cpu < BPF_CPUMASK_NR_CPUS; cpu++) {
		if (!(bits & (1UL << cpu)))
			return cpu;
	}
	return BPF_CPUMASK_NR_CPUS;
}

static inline unsigned int cpumask_first_and(const struct cpumask *srcp1,
					     const struct cpumask *srcp2)
{
	struct cpumask tmp = {
		.bits = { srcp1->bits[0] & srcp2->bits[0] },
	};

	return cpumask_first(&tmp);
}

static inline void cpumask_set_cpu(unsigned int cpu, struct cpumask *dstp)
{
	dstp->bits[0] |= 1UL << cpu;
	dstp->bits[0] &= __bpf_cpumask_valid_mask();
}

static inline void cpumask_clear_cpu(unsigned int cpu, struct cpumask *dstp)
{
	dstp->bits[0] &= ~(1UL << cpu);
}

static inline bool cpumask_test_cpu(unsigned int cpu,
				    const struct cpumask *srcp)
{
	return srcp->bits[0] & (1UL << cpu);
}

static inline bool cpumask_test_and_set_cpu(unsigned int cpu,
					   struct cpumask *dstp)
{
	bool old = cpumask_test_cpu(cpu, dstp);

	cpumask_set_cpu(cpu, dstp);
	return old;
}

static inline bool cpumask_test_and_clear_cpu(unsigned int cpu,
					     struct cpumask *dstp)
{
	bool old = cpumask_test_cpu(cpu, dstp);

	cpumask_clear_cpu(cpu, dstp);
	return old;
}

static inline void cpumask_setall(struct cpumask *dstp)
{
	dstp->bits[0] = __bpf_cpumask_valid_mask();
}

static inline void cpumask_clear(struct cpumask *dstp)
{
	dstp->bits[0] = 0;
}

static inline bool cpumask_and(struct cpumask *dstp,
			       const struct cpumask *srcp1,
			       const struct cpumask *srcp2)
{
	dstp->bits[0] = (srcp1->bits[0] & srcp2->bits[0]) &
		       __bpf_cpumask_valid_mask();
	return dstp->bits[0] != 0;
}

static inline void cpumask_or(struct cpumask *dstp,
			      const struct cpumask *srcp1,
			      const struct cpumask *srcp2)
{
	dstp->bits[0] = (srcp1->bits[0] | srcp2->bits[0]) &
		       __bpf_cpumask_valid_mask();
}

static inline void cpumask_xor(struct cpumask *dstp,
			       const struct cpumask *srcp1,
			       const struct cpumask *srcp2)
{
	dstp->bits[0] = (srcp1->bits[0] ^ srcp2->bits[0]) &
		       __bpf_cpumask_valid_mask();
}

static inline bool cpumask_equal(const struct cpumask *srcp1,
				 const struct cpumask *srcp2)
{
	return (srcp1->bits[0] & __bpf_cpumask_valid_mask()) ==
	       (srcp2->bits[0] & __bpf_cpumask_valid_mask());
}

static inline bool cpumask_intersects(const struct cpumask *srcp1,
				      const struct cpumask *srcp2)
{
	return ((srcp1->bits[0] & srcp2->bits[0]) &
		__bpf_cpumask_valid_mask()) != 0;
}

static inline bool cpumask_subset(const struct cpumask *srcp1,
				  const struct cpumask *srcp2)
{
	unsigned long mask = __bpf_cpumask_valid_mask();

	return (srcp1->bits[0] & mask & ~srcp2->bits[0]) == 0;
}

static inline bool cpumask_empty(const struct cpumask *srcp)
{
	return (srcp->bits[0] & __bpf_cpumask_valid_mask()) == 0;
}

static inline bool cpumask_full(const struct cpumask *srcp)
{
	return (srcp->bits[0] & __bpf_cpumask_valid_mask()) ==
	       __bpf_cpumask_valid_mask();
}

static inline void cpumask_copy(struct cpumask *dstp,
				const struct cpumask *srcp)
{
	dstp->bits[0] = srcp->bits[0] & __bpf_cpumask_valid_mask();
}

static inline unsigned int cpumask_any_distribute(const struct cpumask *srcp)
{
	return cpumask_first(srcp);
}

static inline unsigned int
cpumask_any_and_distribute(const struct cpumask *srcp1,
			   const struct cpumask *srcp2)
{
	return cpumask_first_and(srcp1, srcp2);
}

static inline unsigned int cpumask_weight(const struct cpumask *srcp)
{
	unsigned int cpu, weight = 0;
	unsigned long bits = srcp->bits[0] & __bpf_cpumask_valid_mask();

	for (cpu = 0; cpu < BPF_CPUMASK_NR_CPUS; cpu++)
		weight += !!(bits & (1UL << cpu));
	return weight;
}

#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
#pragma clang attribute push(__attribute__((__noinline__)), apply_to=function)

#endif /* __LINUX_CPUMASK_H */
