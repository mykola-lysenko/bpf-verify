
/* Provide DECLARE_BITMAP and bitmap iteration since we block bitmap.h */
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits)+BITS_PER_LONG-1)/BITS_PER_LONG]
/* bitmap.h iteration macros needed by cpumask.h */
#define find_first_bit(addr, size) (0UL)
#define find_next_bit(addr, size, offset) (size)
#define for_each_set_bit(bit, addr, size) for ((void)(addr), (void)(size), (bit) = 0; 0; )
/* bitmap_remap, bitmap_find_next_zero_area_off etc. are renamed via EXTRA_CFLAGS -D flags
 * to avoid BPF stack-argument limits and signed division issues. */
/* Block nodemask.h which calls bitmap_remap (renamed) causing conflicting types */
#define _LINUX_NODEMASK_H
/* Block cpumask.h which includes nodemask.h */
#define __LINUX_CPUMASK_H
/* Block smp.h which uses cpu_online_mask (requires cpumask) */
#define __LINUX_SMP_H
/* Block dev_printk.h which uses struct device (guard is _DEVICE_PRINTK_H_) */
#define _DEVICE_PRINTK_H_
/* Block device.h which includes dev_printk.h (guard is _DEVICE_H_) */
#define _DEVICE_H_
/* Block spinlock.h which has DEFINE_LOCK_GUARD_1_COND (guard is __LINUX_SPINLOCK_H) */
#define __LINUX_SPINLOCK_H
/* Block spinlock_types.h and spinlock_types_raw.h - provide stubs instead */
#define __LINUX_SPINLOCK_TYPES_H
#define __LINUX_SPINLOCK_TYPES_RAW_H
/* Provide spinlock_t and raw_spinlock_t stubs so wait.h can use them */
struct raw_spinlock { int val; };
typedef struct raw_spinlock raw_spinlock_t;
typedef struct spinlock { struct raw_spinlock rlock; } spinlock_t;
#define SPINLOCK_MAGIC 0xdead4ead
/* bitmap_parse_user calls memdup_user_nul. Provide a stub that returns NULL
 * so the function compiles; the harness never calls bitmap_parse_user. */
#undef noinline
static __attribute__((noinline)) void *bpf_memdup_user_nul(
        const void *src, __kernel_size_t len) {
    (void)src; (void)len; return (void *)0;
}
#undef memdup_user_nul
#define memdup_user_nul(src, len) bpf_memdup_user_nul(src, len)
/* bitmap_find_next_zero_area_off has 6 args (stack args not supported in BPF).
 * We cannot use a macro because it conflicts with the function declaration in bitmap.h.
 * Instead, block the function body in bitmap.c using a rename trick. */
/* bitmap_remap uses signed division - stub it out */
#define __bitmap_remap_body_blocked__ 1
