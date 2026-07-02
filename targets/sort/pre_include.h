/* Forward declarations with internal_linkage so sort_r and sort_r_nonatomic
 * (both 6 args, over BPF limit of 5) are accepted by the BPF backend.
 * Clang propagates this attribute to the definition. */
__attribute__((internal_linkage))
void sort_r(void *base, size_t num, size_t size,
            cmp_r_func_t cmp_func, swap_r_func_t swap_func, const void *priv);
__attribute__((internal_linkage))
void sort_r_nonatomic(void *base, size_t num, size_t size,
            cmp_r_func_t cmp_func, swap_r_func_t swap_func, const void *priv);
/* Block linux/sort.h to prevent its declaration from conflicting. */
#define _LINUX_SORT_H
/* cond_resched() is from linux/sched.h which we block with -D_LINUX_SCHED_H.
 * sort.c calls cond_resched() in the may_schedule path. Stub it out. */
#define cond_resched() do {} while (0)
#define swap_words_32 __attribute__((__noinline__)) swap_words_32
#define swap_words_64 __attribute__((__noinline__)) swap_words_64
#define swap_bytes __attribute__((__noinline__)) swap_bytes
