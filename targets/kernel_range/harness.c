    /* kernel/range.c: range add, merge, and subtract helpers. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x1234;
    struct range ranges[4] = {};
    int errors = 0;
    int nr;
    u64 dyn_start = seed & 7;

    nr = add_range(ranges, 4, 0, 0, 4);
    nr = add_range(ranges, 4, nr, 10, 14);
    errors |= nr != 2;

    nr = add_range_with_merge(ranges, 4, nr, 3, 12);
    errors |= nr != 1;
    errors |= ranges[0].start != 0;
    errors |= ranges[0].end != 14;

    subtract_range(ranges, 4, 4, 8);
    errors |= ranges[0].end != 4;

    nr = add_range(ranges, 4, nr, dyn_start, dyn_start + 1);
    return errors + nr + (int)ranges[0].start + (int)ranges[0].end;