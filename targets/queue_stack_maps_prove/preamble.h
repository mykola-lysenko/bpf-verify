#pragma clang attribute pop
struct __bpf_queue_stack_alloc {
    struct bpf_queue_stack qs;
    u8 data[32];
};

static struct __bpf_queue_stack_alloc __bpf_qs_alloc;
static u32 __bpf_qs_allocated;

static void __bpf_qs_zero_alloc(void)
{
    __bpf_qs_alloc.qs.map.ops = 0;
    __bpf_qs_alloc.qs.map.key_size = 0;
    __bpf_qs_alloc.qs.map.value_size = 0;
    __bpf_qs_alloc.qs.map.max_entries = 0;
    __bpf_qs_alloc.qs.map.map_flags = 0;
    __bpf_qs_alloc.qs.map.numa_node = 0;
    __bpf_qs_alloc.qs.lock.locked = 0;
    __bpf_qs_alloc.qs.head = 0;
    __bpf_qs_alloc.qs.tail = 0;
    __bpf_qs_alloc.qs.size = 0;
    __bpf_qs_alloc.data[0] = 0;
    __bpf_qs_alloc.data[1] = 0;
    __bpf_qs_alloc.data[2] = 0;
    __bpf_qs_alloc.data[3] = 0;
    __bpf_qs_alloc.data[4] = 0;
    __bpf_qs_alloc.data[5] = 0;
    __bpf_qs_alloc.data[6] = 0;
    __bpf_qs_alloc.data[7] = 0;
}

static void *bpf_map_area_alloc(u64 size, int numa_node)
{
    (void)numa_node;
    if (size > sizeof(__bpf_qs_alloc))
        return 0;
    if (__bpf_qs_allocated)
        return 0;
    __bpf_qs_allocated = 1;
    __bpf_qs_zero_alloc();
    return &__bpf_qs_alloc;
}

static void bpf_map_area_free(void *base)
{
    (void)base;
    __bpf_qs_allocated = 0;
}
