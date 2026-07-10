    /* sort: verify the direct swap helpers. The full sort()/sort_r() path is
     * still out of scope because it depends on comparator/swap callbacks,
     * which become indirect calls that the BPF verifier rejects. */
    __u32 key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &key);
    u64 seed = input ? *input : 0x1122334455667788ULL;
    u32 a32 = (u32)seed;
    u32 b32 = (u32)(seed >> 32);
    u64 a64 = seed;
    u64 b64 = seed ^ 0xa5a5a5a5a5a5a5a5ULL;
    char a8[3];
    char b8[3];
    u32 old_a32 = a32, old_b32 = b32;
    u64 old_a64 = a64, old_b64 = b64;
    int errors = 0;

    a8[0] = (char)seed;
    a8[1] = (char)(seed >> 8);
    a8[2] = (char)(seed >> 16);
    b8[0] = (char)(seed >> 24);
    b8[1] = (char)(seed >> 32);
    b8[2] = (char)(seed >> 40);

    swap_words_32(&a32, &b32, sizeof(a32));
    errors |= a32 != old_b32;
    errors |= b32 != old_a32;

    swap_words_64(&a64, &b64, sizeof(a64));
    errors |= a64 != old_b64;
    errors |= b64 != old_a64;

    swap_bytes(a8, b8, sizeof(a8));
    return errors + a8[0] + b8[0];
