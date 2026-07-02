/* USEC_PER_MSEC is defined in vdso/time64.h, normally pulled in via workqueue.h
 * -> jiffies.h -> time64.h. Since workqueue.h is blocked, define it here. */
#ifndef USEC_PER_MSEC
#define USEC_PER_MSEC 1000L
#endif
/* Provide minimal workqueue stubs (workqueue.h is blocked via -D_LINUX_WORKQUEUE_H).
 * dim.h uses struct work_struct in struct dim; net_dim.c calls schedule_work(). */
struct workqueue_struct;
struct work_struct {
    unsigned long data;
    void (*func)(struct work_struct *work);
};
/* queue_work_on is declared in workqueue.h (blocked). Provide a static inline stub.
 * This must come BEFORE dim.h is parsed (dim.h includes workqueue.h which is blocked,
 * so this is the only declaration). */
static inline int queue_work_on(int cpu, struct workqueue_struct *wq,
                                struct work_struct *work)
    { (void)cpu; (void)wq; (void)work; return 0; }
static struct workqueue_struct *system_wq = (struct workqueue_struct *)0;
/* net_dim.c includes rtnetlink.h (blocked) which would pull in netdevice.h.
 * Provide a minimal struct net_device with just the irq_moder field used by net_dim.c. */
struct dim_irq_moder;  /* forward decl; full definition comes from dim.h below */
struct net_device {
    struct dim_irq_moder *irq_moder;
};
/* ENOMEM and GFP_KERNEL are normally from errno.h / gfp.h (pulled via netdevice.h). */
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef GFP_KERNEL
#define GFP_KERNEL 0
#endif
/* Memory allocation stubs (kzalloc_obj, kmemdup, kfree, kfree_rcu). */
#define kzalloc(size, flags) ((void *)0)
#define kzalloc_obj(obj)     kzalloc(sizeof(obj), GFP_KERNEL)
#define kmemdup(src, len, flags) ((void *)0)
#define kfree(ptr)           ((void)(ptr))
#define kfree_rcu(ptr, field) ((void)(ptr))
/* rcu_assign_pointer, rcu_dereference, rtnl_dereference stubs
 * (rcupdate.h is not included since rtnetlink.h is blocked). */
#ifndef rcu_assign_pointer
#define rcu_assign_pointer(p, v) ((p) = (v))
#endif
#ifndef rcu_dereference
#define rcu_dereference(p) (p)
#endif
#ifndef rtnl_dereference
#define rtnl_dereference(p) (p)
#endif
#ifndef rcu_read_lock
#define rcu_read_lock()    do {} while (0)
#define rcu_read_unlock()  do {} while (0)
#endif
/* Apply internal_linkage to ALL functions declared from this point.
 * This ensures dim.h's declarations of net_dim_get_rx_moderation etc.
 * (which return struct dim_cq_moder by value) get internal_linkage.
 * Without this, the BPF backend rejects StructRet non-static functions. */
#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
/* Stub ktime_get to avoid extern BTF reference. */
static inline __s64 ktime_get(void) { return 0; }
/* Include dim.c here (after work_struct is defined) to provide dim_calc_stats etc. */
#include "{ksrc}/lib/dim/dim.c"
