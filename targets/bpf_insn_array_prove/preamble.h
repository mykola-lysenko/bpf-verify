#pragma clang attribute pop
struct __bpf_insn_array_alloc {
    struct bpf_insn_array insn_array;
    struct bpf_insn_array_value values[3];
    long ips[3];
};

static struct __bpf_insn_array_alloc __bpf_insn_array_alloc;
static u8 __bpf_insn_array_allocated;

static void __bpf_insn_array_zero(struct __bpf_insn_array_alloc *storage)
{
    storage->insn_array.map.ops = 0;
    storage->insn_array.map.map_type = 0;
    storage->insn_array.map.key_size = 0;
    storage->insn_array.map.value_size = 0;
    storage->insn_array.map.max_entries = 0;
    storage->insn_array.map.map_flags = 0;
    storage->insn_array.map.numa_node = 0;
    storage->insn_array.map.freeze_mutex.dummy = 0;
    storage->insn_array.map.frozen = false;
    storage->insn_array.used.counter = 0;
    storage->insn_array.ips = storage->ips;
    storage->values[0].orig_off = 0;
    storage->values[0].xlated_off = 0;
    storage->values[0].jitted_off = 0;
    storage->values[0].__pad = 0;
    storage->values[1].orig_off = 0;
    storage->values[1].xlated_off = 0;
    storage->values[1].jitted_off = 0;
    storage->values[1].__pad = 0;
    storage->values[2].orig_off = 0;
    storage->values[2].xlated_off = 0;
    storage->values[2].jitted_off = 0;
    storage->values[2].__pad = 0;
    storage->ips[0] = 0;
    storage->ips[1] = 0;
    storage->ips[2] = 0;
}

static void *bpf_map_area_alloc(u64 size, int numa_node)
{
    (void)numa_node;
    if (size > sizeof(__bpf_insn_array_alloc))
        return 0;
    if (__bpf_insn_array_allocated)
        return 0;
    __bpf_insn_array_allocated = 1;
    __bpf_insn_array_zero(&__bpf_insn_array_alloc);
    return &__bpf_insn_array_alloc;
}

static void bpf_map_area_free(void *base)
{
    (void)base;
    __bpf_insn_array_allocated = 0;
}
