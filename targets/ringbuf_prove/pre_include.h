#include <linux/errno.h>
#define _LINUX_BPF_H 1
#define _LINUX_BTF_H
#define _LINUX_ERR_H
#define _LINUX_IRQ_WORK_H
#define _LINUX_SLAB_H
#define __LINUX_FILTER_H__
#define _LINUX_MM_H
#define _LINUX_VMALLOC_H
#define _LINUX_WAIT_H
#define _LINUX_POLL_H
#define __KMEMLEAK_H
#define _UAPI__LINUX_BTF_H__
#define _LINUX_BTF_IDS_H
#define _ASM_X86_RQSPINLOCK_H 1
#define __ASM_GENERIC_RQSPINLOCK_H 1
#define __aligned(x) __attribute__((aligned(x)))
#define ____cacheline_aligned_in_smp __attribute__((aligned(64)))
#define PAGE_SHIFT 6
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_ALIGNED(x) (((x) & (PAGE_SIZE - 1)) == 0)
#define GFP_KERNEL_ACCOUNT 0
#define __GFP_RETRY_MAYFAIL 0
#define __GFP_NOWARN 0
#define __GFP_ZERO 0
#define VM_MAP 0
#define VM_USERMAP 0
#define PAGE_KERNEL 0
#define VM_WRITE 0x2UL
#define EPOLLIN 0x001
#define EPOLLOUT 0x004
#define EPOLLRDNORM 0x040
#define EPOLLWRNORM 0x100
#define NUMA_NO_NODE (-1)
#define BPF_F_NUMA_NODE (1U << 2)
#define BPF_F_RB_OVERWRITE (1U << 12)
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_USER_RINGBUF 31
#define BPF_RB_NO_WAKEUP (1ULL << 0)
#define BPF_RB_FORCE_WAKEUP (1ULL << 1)
#define BPF_RB_AVAIL_DATA 0
#define BPF_RB_RING_SIZE 1
#define BPF_RB_CONS_POS 2
#define BPF_RB_PROD_POS 3
#define BPF_RB_OVERWRITE_POS 4
#define BPF_RINGBUF_BUSY_BIT (1U << 31)
#define BPF_RINGBUF_DISCARD_BIT (1U << 30)
#define BPF_RINGBUF_HDR_SZ 8
#define BPF_MAX_USER_RINGBUF_SAMPLES 4
#define UINT_MAX (~0U)
#define RET_PTR_TO_RINGBUF_MEM_OR_NULL 1
#define RET_VOID 2
#define RET_INTEGER 3
#define ARG_CONST_MAP_PTR 1
#define ARG_CONST_ALLOC_SIZE_OR_ZERO 2
#define ARG_ANYTHING 3
#define ARG_PTR_TO_RINGBUF_MEM 4
#define ARG_PTR_TO_MEM 5
#define ARG_CONST_SIZE_OR_ZERO 6
#define ARG_PTR_TO_DYNPTR 7
#define ARG_PTR_TO_FUNC 8
#define ARG_PTR_TO_STACK_OR_NULL 9
#define OBJ_RELEASE 0x100
#define MEM_RDONLY 0x200
#define MEM_UNINIT 0x400
#define MEM_WRITE 0x800
#define DYNPTR_TYPE_RINGBUF 0x1000
#define BPF_DYNPTR_TYPE_RINGBUF 1
#define BPF_DYNPTR_TYPE_LOCAL 2
#define ERR_PTR(error) ((void *)(long)(error))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-4095)
#define BTF_ID_LIST_SINGLE(name, prefix, typename) static u32 name[1];
#define BPF_CALL_2(name, t1, a1, t2, a2) static u64 name(t1 a1, t2 a2)
#define BPF_CALL_3(name, t1, a1, t2, a2, t3, a3)     static u64 name(t1 a1, t2 a2, t3 a3)
#define BPF_CALL_4(name, t1, a1, t2, a2, t3, a3, t4, a4)     static u64 name(t1 a1, t2 a2, t3 a3, t4 a4)
#define BPF_KEEP_SCALAR(x) asm volatile("" : "+r"(x))
#ifndef container_of
#define container_of(ptr, type, member)     ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
#endif
#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef round_up
#define round_up(x, y) ((((x) + (y) - 1) / (y)) * (y))
#endif
#ifndef is_power_of_2
#define is_power_of_2(x) ((x) && !((x) & ((x) - 1)))
#endif
#undef READ_ONCE
#undef WRITE_ONCE
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) do { (x) = (v); } while (0)
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p, v) do { *(p) = (v); } while (0)
#define xchg(ptr, v) ({ typeof(*(ptr)) __old = *(ptr); *(ptr) = (v); __old; })

typedef unsigned int __poll_t;
typedef long (*bpf_callback_t)(u64, u64, u64, u64, u64);
typedef struct { u32 locked; } rqspinlock_t;
typedef struct { u32 waiters; } wait_queue_head_t;

struct page {
    u32 id;
};
struct irq_work {
    void (*func)(struct irq_work *work);
    u32 queued;
};
struct file {
    u32 id;
};
struct poll_table_struct {
    u32 id;
};
struct vm_area_struct {
    unsigned long vm_start;
    unsigned long vm_end;
    unsigned long vm_flags;
    unsigned long vm_pgoff;
};
union bpf_attr {
    struct {
        u32 map_type;
        u32 key_size;
        u32 value_size;
        u32 max_entries;
        u32 map_flags;
        u32 numa_node;
    };
};
struct bpf_map;
struct bpf_map_ops {
    bool (*map_meta_equal)(const struct bpf_map *meta0,
                           const struct bpf_map *meta1);
    struct bpf_map *(*map_alloc)(union bpf_attr *attr);
    void (*map_free)(struct bpf_map *map);
    int (*map_mmap)(struct bpf_map *map, struct vm_area_struct *vma);
    __poll_t (*map_poll)(struct bpf_map *map, struct file *filp,
                         struct poll_table_struct *pts);
    void *(*map_lookup_elem)(struct bpf_map *map, void *key);
    long (*map_update_elem)(struct bpf_map *map, void *key, void *value,
                            u64 flags);
    long (*map_delete_elem)(struct bpf_map *map, void *key);
    int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
    u64 (*map_mem_usage)(const struct bpf_map *map);
    const u32 *map_btf_id;
};
struct bpf_map {
    const struct bpf_map_ops *ops;
    u32 map_type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
    int numa_node;
};
struct bpf_func_proto {
    void *func;
    int ret_type;
    int arg1_type;
    int arg2_type;
    int arg3_type;
    int arg4_type;
};
struct bpf_dynptr_kern {
    void *data;
    u32 size;
    u32 type;
};

static inline bool bpf_map_meta_equal(const struct bpf_map *meta0,
                                      const struct bpf_map *meta1)
{
    return meta0 == meta1;
}
static inline int bpf_map_attr_numa_node(const union bpf_attr *attr)
{
    return (attr->map_flags & BPF_F_NUMA_NODE) ?
           (int)attr->numa_node : NUMA_NO_NODE;
}
static inline void bpf_map_init_from_attr(struct bpf_map *map,
                                          union bpf_attr *attr)
{
    map->map_type = attr->map_type;
    map->key_size = attr->key_size;
    map->value_size = attr->value_size;
    map->max_entries = attr->max_entries;
    map->map_flags = attr->map_flags;
    map->numa_node = bpf_map_attr_numa_node(attr);
}
static inline void *bpf_map_area_alloc(u64 size, int numa_node)
{
    (void)size;
    (void)numa_node;
    return NULL;
}
static inline void bpf_map_area_free(void *base)
{
    (void)base;
}
static inline struct page *alloc_pages_node(int node, unsigned int flags,
                                            unsigned int order)
{
    (void)node;
    (void)flags;
    (void)order;
    return NULL;
}
static inline void __free_page(struct page *page)
{
    (void)page;
}
static inline void *vmap(struct page **pages, int count,
                         unsigned long flags, unsigned long prot)
{
    (void)pages;
    (void)count;
    (void)flags;
    (void)prot;
    return NULL;
}
static inline void vunmap(const void *addr)
{
    (void)addr;
}
static inline void kmemleak_not_leak(const void *ptr)
{
    (void)ptr;
}
static inline void raw_res_spin_lock_init(rqspinlock_t *lock)
{
    lock->locked = 0;
}
static inline int raw_res_spin_lock_irqsave(rqspinlock_t *lock,
                                            unsigned long flags)
{
    (void)lock;
    (void)flags;
    return 0;
}
static inline void raw_res_spin_unlock_irqrestore(rqspinlock_t *lock,
                                                  unsigned long flags)
{
    (void)lock;
    (void)flags;
}
static inline void atomic_set(atomic_t *v, int i)
{
    v->counter = i;
}
static inline bool atomic_try_cmpxchg(atomic_t *v, int *old, int new)
{
    if (v->counter != *old) {
        *old = v->counter;
        return false;
    }
    v->counter = new;
    return true;
}
static inline void atomic_set_release(atomic_t *v, int i)
{
    v->counter = i;
}
static inline void init_waitqueue_head(wait_queue_head_t *waitq)
{
    waitq->waiters = 0;
}
static inline void init_irq_work(struct irq_work *work,
                                 void (*func)(struct irq_work *work))
{
    work->func = func;
    work->queued = 0;
}
static inline void irq_work_sync(struct irq_work *work)
{
    (void)work;
}
static inline void irq_work_queue(struct irq_work *work)
{
    work->queued++;
}
static inline void wake_up_all(wait_queue_head_t *waitq)
{
    waitq->waiters++;
}
static inline void poll_wait(struct file *filp, wait_queue_head_t *waitq,
                             struct poll_table_struct *pts)
{
    (void)filp;
    (void)waitq;
    (void)pts;
}
static inline int remap_vmalloc_range(struct vm_area_struct *vma, void *addr,
                                      unsigned long pgoff)
{
    (void)vma;
    (void)addr;
    (void)pgoff;
    return 0;
}
static inline int bpf_dynptr_check_size(u32 size)
{
    return size <= 64 ? 0 : -E2BIG;
}
static inline void bpf_dynptr_set_null(struct bpf_dynptr_kern *ptr)
{
    ptr->data = NULL;
    ptr->size = 0;
    ptr->type = 0;
}
static inline void bpf_dynptr_init(struct bpf_dynptr_kern *ptr, void *data,
                                   u32 type, u32 flags, u32 size)
{
    (void)flags;
    ptr->data = data;
    ptr->size = size;
    ptr->type = type;
}
static __always_inline void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    size_t i;

    for (i = 0; i < 64; i++) {
        if (i >= n)
            break;
        d[i] = s[i];
    }
    return dst;
}
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
