#include <linux/errno.h>
#define _LINUX_HASH_H
#define _LINUX_BPF_H 1
#define __LINUX_FILTER_H__
#define _LINUX_STATIC_CALL_H
#define __weak
#define uintptr_t unsigned long
#define PAGE_SIZE 64
#define BPF_DISPATCHER_MAX 4
#define NULL ((void *)0)
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-4095)
#define __BPF_DISPATCHER_UPDATE(_d, _new) do {     (void)(_d);     (void)(_new); } while (0)
#define bpf_jit_fill_hole_with_zero ((void *)0)

struct bpf_insn {
    u8 code;
};
typedef unsigned long bpf_func_t;
typedef struct {
    int refs;
} refcount_t;
struct mutex {
    u32 locked;
};
struct bpf_ksym {
    unsigned long start;
    unsigned long end;
};
struct bpf_prog {
    bpf_func_t bpf_func;
    u32 refs;
};
struct bpf_dispatcher_prog {
    struct bpf_prog *prog;
    refcount_t users;
};
struct bpf_dispatcher {
    struct mutex mutex;
    void *func;
    struct bpf_dispatcher_prog progs[BPF_DISPATCHER_MAX];
    int num_progs;
    void *image;
    void *rw_image;
    u32 image_off;
    struct bpf_ksym ksym;
};

static u8 __bpf_dispatcher_image[PAGE_SIZE];
static u8 __bpf_dispatcher_rw_image[PAGE_SIZE];
static u32 __bpf_dispatcher_prog_incs;
static u32 __bpf_dispatcher_prog_puts;
static u8 __bpf_dispatcher_pack_allocated;
static u8 __bpf_dispatcher_exec_allocated;

static inline void refcount_set(refcount_t *r, int n)
{
    r->refs = n;
}
static inline void refcount_inc(refcount_t *r)
{
    r->refs++;
}
static inline bool refcount_dec_and_test(refcount_t *r)
{
    r->refs--;
    return r->refs == 0;
}
static inline void mutex_lock(struct mutex *mutex)
{
    mutex->locked = 1;
}
static inline void mutex_unlock(struct mutex *mutex)
{
    mutex->locked = 0;
}
static inline void bpf_prog_inc(struct bpf_prog *prog)
{
    prog->refs++;
    __bpf_dispatcher_prog_incs++;
}
static inline void bpf_prog_put(struct bpf_prog *prog)
{
    prog->refs--;
    __bpf_dispatcher_prog_puts++;
}
/* The kernel signature gained a third parameter (bool was_classic);
 * mirror it so the dispatcher.c call sites match. */
static inline void *bpf_prog_pack_alloc(unsigned int size, void *fill,
                                        _Bool was_classic)
{
    (void)fill;
    (void)was_classic;
    if (size != PAGE_SIZE || __bpf_dispatcher_pack_allocated)
        return NULL;
    __bpf_dispatcher_pack_allocated = 1;
    return __bpf_dispatcher_image;
}
static inline void bpf_prog_pack_free(void *image, unsigned int size)
{
    (void)image;
    (void)size;
    __bpf_dispatcher_pack_allocated = 0;
}
static inline void *bpf_jit_alloc_exec(unsigned int size)
{
    if (size != PAGE_SIZE || __bpf_dispatcher_exec_allocated)
        return NULL;
    __bpf_dispatcher_exec_allocated = 1;
    return __bpf_dispatcher_rw_image;
}
static inline void bpf_image_ksym_init(void *data, unsigned int size,
                                       struct bpf_ksym *ksym)
{
    ksym->start = (unsigned long)data;
    ksym->end = ksym->start + size;
}
static inline void bpf_image_ksym_add(struct bpf_ksym *ksym)
{
    (void)ksym;
}
static inline void *bpf_arch_text_copy(void *dst, void *src, unsigned int len)
{
    (void)src;
    (void)len;
    return dst;
}
static inline void synchronize_rcu(void)
{
}
static inline unsigned int bpf_dispatcher_nop_func(const void *ctx,
                                                   const struct bpf_insn *insnsi,
                                                   bpf_func_t bpf_func)
{
    (void)ctx;
    (void)insnsi;
    (void)bpf_func;
    return 0;
}
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
