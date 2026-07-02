#define _LINUX_SLAB_H
#define MM_SLAB_H

struct mutex {
    u32 locked;
};
struct kmem_cache {
    struct list_head list;
    int refcount;
    u32 id;
};

static struct list_head slab_caches = { &slab_caches, &slab_caches };
static struct mutex slab_mutex;
static struct kmem_cache __bpf_iter_kmem0;
static struct kmem_cache __bpf_iter_kmem1;
static volatile u32 __bpf_iter_kmem_destroys;
static volatile u32 __bpf_iter_kmem_empty;

#ifndef container_of
#define container_of(ptr, type, member)     ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
#endif
#define list_empty(head) (__bpf_iter_kmem_empty)
#define list_first_entry(head, type, member) (&__bpf_iter_kmem0)
#define list_last_entry(head, type, member) (&__bpf_iter_kmem1)
#define list_next_entry(pos, member)     ((pos) == &__bpf_iter_kmem0 ? &__bpf_iter_kmem1 : (struct kmem_cache *)0)
#define list_for_each_entry(pos, head, member)     for (u32 __bpf_kmem_i = 0;          __bpf_kmem_i < 2 && (((pos) = __bpf_iter_kmem_by_idx(__bpf_kmem_i)) != 0);          __bpf_kmem_i++)

static inline struct kmem_cache *__bpf_iter_kmem_by_idx(u32 idx)
{
    if (idx == 0)
        return &__bpf_iter_kmem0;
    if (idx == 1)
        return &__bpf_iter_kmem1;
    return 0;
}
static inline void __bpf_iter_kmem_reset(void)
{
    __bpf_iter_reset();
    __bpf_iter_kmem_destroys = 0;
    __bpf_iter_kmem_empty = 0;
    slab_mutex.locked = 0;
    __bpf_iter_kmem0.list.next = &__bpf_iter_kmem1.list;
    __bpf_iter_kmem0.list.prev = &slab_caches;
    __bpf_iter_kmem0.refcount = 1;
    __bpf_iter_kmem0.id = 10;
    __bpf_iter_kmem1.list.next = &slab_caches;
    __bpf_iter_kmem1.list.prev = &__bpf_iter_kmem0.list;
    __bpf_iter_kmem1.refcount = 1;
    __bpf_iter_kmem1.id = 11;
    slab_caches.next = &__bpf_iter_kmem0.list;
    slab_caches.prev = &__bpf_iter_kmem1.list;
}
static inline void mutex_lock(struct mutex *mutex)
{
    mutex->locked = 1;
}
static inline void mutex_unlock(struct mutex *mutex)
{
    mutex->locked = 0;
}
static inline void kmem_cache_destroy(struct kmem_cache *s)
{
    s->refcount = 0;
    __bpf_iter_kmem_destroys++;
}
