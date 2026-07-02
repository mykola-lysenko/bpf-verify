
    /* refcount: map-seeded live/zero paths for inc_not_zero and dec_and_test. */
    __u32 key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &key);
    int start = input ? (int)(*input & 1) : 1;
    refcount_t r;
    refcount_set(&r, start);
    unsigned int before = refcount_read(&r);
    bool inc = refcount_inc_not_zero(&r);
    bool dec = refcount_dec_and_test(&r);
    return (int)(before + inc + dec + refcount_read(&r));
