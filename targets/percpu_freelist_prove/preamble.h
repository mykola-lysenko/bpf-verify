static struct pcpu_freelist_head __bpf_pcpu_head;
static u32 __bpf_pcpu_allocated;

static void *__bpf_percpu_alloc(size_t size)
{
    if (size != sizeof(struct pcpu_freelist_head))
        return 0;
    if (__bpf_pcpu_allocated)
        return 0;
    __bpf_pcpu_allocated = 1;
    __bpf_pcpu_head.first = 0;
    raw_res_spin_lock_init(&__bpf_pcpu_head.lock);
    return &__bpf_pcpu_head;
}

static void __bpf_percpu_free(void *ptr)
{
    (void)ptr;
    __bpf_pcpu_allocated = 0;
}

#define __bpf_hide_ptr(ptr) asm volatile("" : "+r"(ptr))
#define __bpf_memory_barrier() asm volatile("" ::: "memory")
