/* BPF shim: linux/srcu.h
 * The real srcu.h defines static inline functions (srcu_read_lock, etc.)
 * that conflict with our macro stubs in srcutree.h, causing "while loop
 * outside of a function" errors when the macros expand inside function decls.
 * Block the real srcu.h and provide all needed stubs here.
 */
#ifndef _LINUX_SRCU_H
#define _LINUX_SRCU_H

#include <linux/srcutree.h>

/* srcu_read_lock_fast / srcu_read_unlock_fast stubs */
static inline int srcu_read_lock_fast(struct srcu_struct *ssp) { return 0; }
static inline void srcu_read_unlock_fast(struct srcu_struct *ssp, int idx) {}
static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp) { return 0; }
static inline void srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx) {}

/* poll_state_synchronize_srcu stub */
static inline bool poll_state_synchronize_srcu(struct srcu_struct *ssp,
unsigned long cookie)
{ return true; }
static inline unsigned long get_state_synchronize_srcu(struct srcu_struct *ssp)
{ return 0; }
static inline unsigned long start_poll_synchronize_srcu(struct srcu_struct *ssp)
{ return 0; }

#endif /* _LINUX_SRCU_H */
