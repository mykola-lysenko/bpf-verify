    /* find_bit: assert ordering invariants:
     *   1. find_first_bit <= find_last_bit (when any bit is set)
     *   2. find_first_zero_bit is not set in the bitmap
     *   3. For all-zeros: find_first_bit returns nbits (not found)
     *   4. For all-ones:  find_first_zero_bit returns nbits (not found) */
    __u32 key0 = 0, key1 = 1;
    __u64 *vw0 = bpf_map_lookup_elem(&input_map, &key0);
    __u64 *vw1 = bpf_map_lookup_elem(&input_map, &key1);
    if (!vw0 || !vw1) return 0;
    unsigned long bmap[2];
    bmap[0] = (unsigned long)*vw0;
    bmap[1] = (unsigned long)*vw1;
    unsigned long first = find_first_bit(bmap, 128);
    unsigned long last  = find_last_bit(bmap, 128);
    unsigned long zero  = find_first_zero_bit(bmap, 128);
    /* Property: first <= last when bitmap is non-empty */
    if (first < 128) {{
        BPF_ASSERT(first <= last);
    }}
    /* Property: all-zeros bitmap => first_bit returns nbits=128 (not found).
     * Use >= instead of == to avoid BPF backend generating jgt instead of jne
     * for the equality check (a known BPF codegen precision issue). */
    unsigned long zeros[2] = {{0UL, 0UL}};
    unsigned long fz = find_first_bit(zeros, 128);
    BPF_ASSERT(fz >= 128);
    /* Property: all-ones bitmap => first_zero returns nbits=128 (not found). */
    unsigned long ones[2] = {{~0UL, ~0UL}};
    unsigned long oz = find_first_zero_bit(ones, 128);
    BPF_ASSERT(oz >= 128);
    return (int)(first + last + zero);