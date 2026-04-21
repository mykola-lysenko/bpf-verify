/* SPDX-License-Identifier: GPL-2.0+ */
/* BPF shim: linux/srcutree.h
 * Provides minimal SRCU struct stubs without pulling in workqueue.h/irq_work.h.
 */
#ifndef _LINUX_SRCU_TREE_H
#define _LINUX_SRCU_TREE_H

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/completion.h>

/* Forward declarations */
struct srcu_node;
struct srcu_data;
struct srcu_usage;

struct srcu_ctr {
    atomic_long_t srcu_locks;
    atomic_long_t srcu_unlocks;
};

struct srcu_struct {
    struct srcu_ctr __percpu *srcu_ctrp;
    void __percpu *sda;
    unsigned char srcu_reader_flavor;
    /* dep_map, srcu_sup omitted */
};

/* Minimal srcu_usage stub - avoids pulling in workqueue.h / irq_work.h */
struct srcu_usage {
    unsigned long srcu_gp_seq;
    unsigned long srcu_gp_seq_needed;
    unsigned long srcu_gp_seq_needed_exp;
    unsigned long srcu_gp_start;
    unsigned long srcu_last_gp_end;
    unsigned long srcu_size_jiffies;
    unsigned long srcu_n_lock_retries;
    unsigned long srcu_n_exp_nodelay;
    bool sda_is_static;
    unsigned long srcu_barrier_seq;
    struct mutex srcu_barrier_mutex;
    struct completion srcu_barrier_completion;
    atomic_t srcu_barrier_cpu_cnt;
    unsigned long reschedule_jiffies;
    unsigned long reschedule_count;
    /* work and irq_work omitted - opaque padding */
    unsigned long __work_pad[8];
    struct srcu_struct *srcu_ssp;
};

/* SRCU init macros */
#define __SRCU_STRUCT_INIT(name, usage) { }
#define DEFINE_SRCU(name) struct srcu_struct name
#define DEFINE_STATIC_SRCU(name) static struct srcu_struct name
#define init_srcu_struct(sp) 0

#endif /* _LINUX_SRCU_TREE_H */
