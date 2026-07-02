#include <linux/jiffies.h>
#undef jiffies
#define jiffies ((unsigned long)0)
/* trace_dql_stall_detected is defined in trace/events/napi.h which is blocked
 * by -D_TRACE_NAPI_H. Provide a no-op stub so dynamic_queue_limits.c compiles. */
static inline void trace_dql_stall_detected(unsigned short thrs, unsigned int len,
    unsigned long last_reap, unsigned long hist_head,
    unsigned long now, unsigned long *hist)
{ (void)thrs; (void)len; (void)last_reap; (void)hist_head; (void)now; (void)hist; }
/* memset stub to avoid implicit declaration error. */
static inline void *memset(void *dst, int c, __kernel_size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}
