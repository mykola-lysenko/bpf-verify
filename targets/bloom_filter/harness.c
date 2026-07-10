    /* bloom_filter: BPF Bloom filter map -- hash-based probabilistic set.
     *
     * A Bloom filter is a space-efficient probabilistic data structure that
     * tests whether an element is a member of a set. It has no false negatives
     * (if an element was added, it will always be found), but may have false
     * positives (an element not added may occasionally be reported as present).
     *
     * Core invariant verified:
     *   For any element X: if push(X) succeeds, then peek(X) == 0 (found).
     *   This is the fundamental "no false negatives" property.
     *
     * Additional properties:
     *   - An empty filter reports ENOENT for any element.
     *   - After pushing element A, element B (with different hash) may or may
     *     not be found (false positive is possible but not guaranteed).
     *   - The hash function is deterministic: same input -> same bit positions.
     *
     * We use a 256-bit bitset with 3 hash functions and u32-aligned values.
     */
    struct bpf_bloom_filter bloom;
    bloom_filter_init(&bloom, sizeof(u32), 3, 0xdeadbeef);

    /* Property: empty filter reports ENOENT for any element */
    u32 val_a = 0x12345678;
    BPF_ASSERT(bloom_map_peek_elem(&bloom, &val_a) == -ENOENT);

    /* Push val_a and verify it is found (no false negatives) */
    BPF_ASSERT(bloom_map_push_elem(&bloom, &val_a, BPF_ANY) == 0);
    BPF_ASSERT(bloom_map_peek_elem(&bloom, &val_a) == 0);

    /* Push val_b and verify it is found */
    u32 val_b = 0xdeadbeef;
    BPF_ASSERT(bloom_map_push_elem(&bloom, &val_b, BPF_ANY) == 0);
    BPF_ASSERT(bloom_map_peek_elem(&bloom, &val_b) == 0);

    /* Push val_c and verify it is found */
    u32 val_c = 0xc0ffee42;
    BPF_ASSERT(bloom_map_push_elem(&bloom, &val_c, BPF_ANY) == 0);
    BPF_ASSERT(bloom_map_peek_elem(&bloom, &val_c) == 0);

    /* Determinism: pushing val_a again is idempotent (peek still succeeds) */
    BPF_ASSERT(bloom_map_push_elem(&bloom, &val_a, BPF_ANY) == 0);
    BPF_ASSERT(bloom_map_peek_elem(&bloom, &val_a) == 0);

    /* Invalid flags should be rejected */
    BPF_ASSERT(bloom_map_push_elem(&bloom, &val_a, 1ULL) == -EINVAL);

    return 0;
