    /* drivers/gpu/drm/i915/i915_mmio_range.c: sentinel-terminated range lookup. */
    struct i915_mmio_range ranges[] = {
        { .start = 0x10, .end = 0x1f },
        { .start = 0x40, .end = 0x40 },
        { .start = 0x80, .end = 0x8f },
        { .start = 0, .end = 0 },
    };
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u32 addr = input ? (u32)(*input & 0xff) : 0x14;
    int errors = 0;

    errors |= !i915_mmio_range_table_contains(0x10, ranges);
    errors |= !i915_mmio_range_table_contains(0x1f, ranges);
    errors |= !i915_mmio_range_table_contains(0x40, ranges);
    errors |= i915_mmio_range_table_contains(0x20, ranges);
    errors |= i915_mmio_range_table_contains(0x7f, ranges);

    return errors + i915_mmio_range_table_contains(addr, ranges);
