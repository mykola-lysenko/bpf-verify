    /* lpm_trie: BPF Longest-Prefix-Match trie core algorithm.
     *
     * The BPF verifier has limited precision for pointers persisted through
     * trie memory, so the harness does not do full update+lookup end-to-end.
     * It directly tests the pure matching helpers and selected update
     * return-code paths that stay verifier-trackable.
     *
     * Pure helpers:
     *   1. extract_bit(data, index): extracts bit 'index' from a byte array.
     *   2. longest_prefix_match(trie, node, key): finds the longest common
     *      prefix between a trie node and a lookup key.
     *
     * Both functions operate only on stack-allocated data, which the verifier
     * can fully track. This exercises the heart of the LPM algorithm.
     *
     * Properties verified:
     *   A. extract_bit: bit 0 of 0x80 is 1; bit 7 of 0x01 is 1; bit 0 of 0x00 is 0.
     *   B. longest_prefix_match: 192.168.1.x node vs 192.168.1.5 key -> 24 bits match.
     *   C. longest_prefix_match: 10.0.0.0/8 node vs 192.168.1.5 key -> 0 bits match.
     *   D. longest_prefix_match: exact match 192.168.1.0/24 -> returns min(24,32)=24.
     *   E. trie_update_elem: BPF_EXIST on an empty trie reports ENOENT even at capacity.
     *   F. trie_update_elem: replacement of an existing node is allowed at capacity.
     *   G. trie_delete_elem: invalid key, not-found, and root leaf delete paths.
     */

    /* --- Property A: extract_bit --- */
    u8 data_a[4] = {0x80, 0x00, 0x00, 0x01}; /* 10000000 00000000 00000000 00000001 */
    BPF_ASSERT(extract_bit(data_a, 0) == 1);  /* MSB of 0x80 */
    BPF_ASSERT(extract_bit(data_a, 1) == 0);  /* bit 1 of 0x80 */
    BPF_ASSERT(extract_bit(data_a, 31) == 1); /* LSB of 0x01 */
    BPF_ASSERT(extract_bit(data_a, 8) == 0);  /* MSB of 0x00 */

    /* --- Properties B, C, D: longest_prefix_match --- */
    /* Build a minimal lpm_trie descriptor (data_size=4, max_prefixlen=32) */
    struct lpm_trie trie;
    lpm_trie_init(&trie, 8);

    /* Node: 192.168.1.0/24 */
    struct {
        struct lpm_trie_node hdr;
        u8 addr[4];
        u64 value;
    } node24;
    node24.hdr.prefixlen = 24;
    node24.hdr.flags = 0;
    node24.hdr.child[0] = NULL;
    node24.hdr.child[1] = NULL;
    node24.addr[0] = 192; node24.addr[1] = 168;
    node24.addr[2] = 1;   node24.addr[3] = 0;
    node24.value = 1;

    /* Key: 192.168.1.5/32 */
    struct lpm_key_ipv4 key32;
    lpm_key_set(&key32, 32, 192, 168, 1, 5);

    /* B: 192.168.1.0/24 node vs 192.168.1.5/32 key -> 24 bits match */
    size_t match_b = longest_prefix_match(&trie, &node24.hdr, &key32.hdr);
    BPF_ASSERT(match_b == 24);

    /* Node: 10.0.0.0/8 */
    struct {
        struct lpm_trie_node hdr;
        u8 addr[4];
        u64 value;
    } node8;
    node8.hdr.prefixlen = 8;
    node8.hdr.flags = 0;
    node8.hdr.child[0] = NULL;
    node8.hdr.child[1] = NULL;
    node8.addr[0] = 10;  node8.addr[1] = 0;
    node8.addr[2] = 0;   node8.addr[3] = 0;
    node8.value = 10;

    /* C: 10.0.0.0/8 node vs 192.168.1.5/32 key -> 0 bits match */
    size_t match_c = longest_prefix_match(&trie, &node8.hdr, &key32.hdr);
    BPF_ASSERT(match_c == 0);

    /* D: exact match -- 192.168.1.0/24 node vs 192.168.1.0/24 key -> 24 */
    struct lpm_key_ipv4 key24;
    lpm_key_set(&key24, 24, 192, 168, 1, 0);
    size_t match_d = longest_prefix_match(&trie, &node24.hdr, &key24.hdr);
    BPF_ASSERT(match_d == 24);

    /* E: BPF_EXIST should fail as not-found, not as capacity exhaustion. */
    u64 value = 0x1122334455667788ULL;
    int ret;
    lpm_trie_init(&trie, 1);
    trie.n_entries = trie.map.max_entries;
    ret = trie_update_elem(&trie.map, &key24.hdr, &value, BPF_EXIST);
    BPF_ASSERT(ret == -ENOENT);

    /* F: replacing an existing node does not consume a new map entry. */
    lpm_trie_init(&trie, 1);
    trie.root = &node24.hdr;
    trie.n_entries = trie.map.max_entries;
    ret = trie_update_elem(&trie.map, &key24.hdr, &value, BPF_NOEXIST);
    BPF_ASSERT(ret == -EEXIST);
    BPF_ASSERT(trie.n_entries == trie.map.max_entries);
    ret = trie_update_elem(&trie.map, &key24.hdr, &value, BPF_ANY);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(trie.n_entries == trie.map.max_entries);

    /* G: delete paths that stay within verifier-trackable root state. */
    struct lpm_key_ipv4 del_key24;
    struct lpm_key_ipv4 del_key33;
    lpm_key_set(&del_key24, 24, 192, 168, 1, 0);
    lpm_key_set(&del_key33, 33, 192, 168, 1, 0);
    lpm_trie_init(&trie, 1);
    BPF_ASSERT(trie_delete_elem(&trie.map, &del_key33.hdr) == -EINVAL);
    BPF_ASSERT(trie_delete_elem(&trie.map, &del_key24.hdr) == -ENOENT);

    struct {
        struct lpm_trie_node hdr;
        u8 addr[4];
        u64 value;
    } del_leaf24;
    del_leaf24.hdr.prefixlen = 24;
    del_leaf24.hdr.flags = 0;
    del_leaf24.hdr.child[0] = NULL;
    del_leaf24.hdr.child[1] = NULL;
    del_leaf24.addr[0] = 192; del_leaf24.addr[1] = 168;
    del_leaf24.addr[2] = 1;   del_leaf24.addr[3] = 0;
    del_leaf24.value = 24;
    lpm_trie_init(&trie, 2);
    trie.root = &del_leaf24.hdr;
    trie.n_entries = 1;
    BPF_ASSERT(trie_delete_elem(&trie.map, &del_key24.hdr) == 0);
    BPF_ASSERT(trie.n_entries == 0);
    BPF_ASSERT(trie.root == NULL);

    return (int)(match_b + match_c + match_d);