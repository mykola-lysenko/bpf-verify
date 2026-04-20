/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: stub out completion - not needed for BPF verification */
#ifndef __LINUX_COMPLETION_H
#define __LINUX_COMPLETION_H

#include <linux/types.h>

struct completion {
    unsigned int done;
};

#define COMPLETION_INITIALIZER(work) { 0 }
#define COMPLETION_INITIALIZER_ONSTACK(work) { 0 }
#define DECLARE_COMPLETION(work) struct completion work = { 0 }
#define DECLARE_COMPLETION_ONSTACK(work) struct completion work = { 0 }

static inline void init_completion(struct completion *x) { x->done = 0; }
static inline void reinit_completion(struct completion *x) { x->done = 0; }
static inline void complete(struct completion *x) { x->done = 1; }
static inline void complete_all(struct completion *x) { x->done = 1; }
static inline void wait_for_completion(struct completion *x) {}
static inline int wait_for_completion_interruptible(struct completion *x) { return 0; }
static inline long wait_for_completion_timeout(struct completion *x, unsigned long t) { return 1; }
static inline long wait_for_completion_interruptible_timeout(struct completion *x, unsigned long t) { return 1; }
static inline bool try_wait_for_completion(struct completion *x) { return true; }
static inline bool completion_done(struct completion *x) { return true; }

#endif /* __LINUX_COMPLETION_H */
