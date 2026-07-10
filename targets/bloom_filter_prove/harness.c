    /* bloom_filter_prove: verifier-enforced hash and bitset invariants.
     *
     * The broader bloom_filter harness keeps full push+peek no-false-negative
     * coverage with BPF_ASSERT. BPF_PROVE is focused on properties the verifier
     * can prove for symbolic values without losing dynamic stack-bitset
     * precision.
     */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u32 val = input ? (u32)*input : 0x12345678;

    struct bpf_bloom_filter bloom;
    bloom_filter_init(&bloom, sizeof(u32), 3, 0xdeadbeef);
    BPF_PROVE(bloom.map.value_size == sizeof(u32));
    BPF_PROVE(bloom.bitset_mask == 255);
    BPF_PROVE(bloom.nr_hash_funcs == 3);
    BPF_PROVE(bloom.bitset[0] == 0);
    BPF_PROVE(bloom.bitset[1] == 0);
    BPF_PROVE(bloom.bitset[2] == 0);
    BPF_PROVE(bloom.bitset[3] == 0);

    BPF_PROVE(bloom_map_push_elem(&bloom, &val, 1ULL) == -EINVAL);
    BPF_PROVE(bloom.bitset[0] == 0);
    BPF_PROVE(bloom.bitset[1] == 0);
    BPF_PROVE(bloom.bitset[2] == 0);
    BPF_PROVE(bloom.bitset[3] == 0);

    u32 h0 = bloom_hash(&bloom, &val, sizeof(val), 0);
    u32 h1 = bloom_hash(&bloom, &val, sizeof(val), 1);
    u32 h2 = bloom_hash(&bloom, &val, sizeof(val), 2);
    BPF_PROVE(h0 <= bloom.bitset_mask);
    BPF_PROVE(h1 <= bloom.bitset_mask);
    BPF_PROVE(h2 <= bloom.bitset_mask);

    if (h0 < 64) {
        u64 bit = 1ULL << h0;
        bloom.bitset[0] |= bit;
        BPF_PROVE((bloom.bitset[0] & bit) != 0);
    } else if (h0 < 128) {
        u64 bit = 1ULL << (h0 - 64);
        bloom.bitset[1] |= bit;
        BPF_PROVE((bloom.bitset[1] & bit) != 0);
    } else if (h0 < 192) {
        u64 bit = 1ULL << (h0 - 128);
        bloom.bitset[2] |= bit;
        BPF_PROVE((bloom.bitset[2] & bit) != 0);
    } else {
        u64 bit = 1ULL << (h0 - 192);
        bloom.bitset[3] |= bit;
        BPF_PROVE((bloom.bitset[3] & bit) != 0);
    }

    BPF_PROVE(bloom_map_push_elem(&bloom, &val, BPF_ANY) == 0);
    return (int)(val + h0 + h1 + h2);
