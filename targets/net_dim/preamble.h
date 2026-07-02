#pragma clang attribute pop
/* schedule_work is declared in workqueue.h (blocked). Provide a stub. */
static inline int schedule_work(struct work_struct *work)
    { (void)work; return 0; }
