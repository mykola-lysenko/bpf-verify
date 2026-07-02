#pragma clang attribute pop
static struct bpf_array __bpf_map_in_map_meta_array;
static struct bpf_array __bpf_map_in_map_inner_array;
static struct btf __bpf_map_in_map_btf;
static struct btf_record __bpf_map_in_map_record;
static u32 __bpf_map_in_map_puts;
static u8 __bpf_map_in_map_allocated;

const struct bpf_map_ops array_map_ops = {
    .map_meta_equal = __bpf_map_in_map_meta_equal_stub,
};
const struct bpf_map_ops percpu_array_map_ops = {
    .map_meta_equal = __bpf_map_in_map_meta_equal_stub,
};
const struct bpf_map_ops __bpf_map_in_map_no_meta_ops = {
    .map_meta_equal = 0,
};

static bool __bpf_map_in_map_meta_equal_stub(const struct bpf_map *meta0,
                                             const struct bpf_map *meta1)
{
    return bpf_map_meta_equal(meta0, meta1);
}

static void __bpf_map_in_map_zero_map(struct bpf_map *map)
{
    map->ops = 0;
    map->inner_map_meta = 0;
    map->map_type = 0;
    map->key_size = 0;
    map->value_size = 0;
    map->max_entries = 0;
    map->map_flags = 0;
    map->id = 0;
    map->record = 0;
    map->btf = 0;
    map->bypass_spec_v1 = false;
    map->free_after_mult_rcu_gp = false;
    map->free_after_rcu_gp = false;
    map->sleepable_refcnt.counter = 0;
}

static void __bpf_map_in_map_zero_array(struct bpf_array *array)
{
    __bpf_map_in_map_zero_map(&array->map);
    array->elem_size = 0;
    array->index_mask = 0;
}

static struct bpf_map *__bpf_map_get(int fd)
{
    if (fd < 0)
        return ERR_PTR(-EBADF);
    return &__bpf_map_in_map_inner_array.map;
}

static void *__bpf_map_in_map_alloc(size_t size, unsigned int flags)
{
    (void)flags;
    if (size != sizeof(struct bpf_array))
        return 0;
    if (__bpf_map_in_map_allocated)
        return 0;
    __bpf_map_in_map_allocated = 1;
    __bpf_map_in_map_zero_array(&__bpf_map_in_map_meta_array);
    return &__bpf_map_in_map_meta_array;
}

static void __bpf_map_in_map_free(void *ptr)
{
    (void)ptr;
    __bpf_map_in_map_allocated = 0;
}

static inline void bpf_map_put(struct bpf_map *map)
{
    (void)map;
    __bpf_map_in_map_puts++;
}
