    /* lpm_trie_prove: verifier-enforced guard invariants.
     *
     * The broader lpm_trie harness covers the update/delete success paths with
     * BPF_ASSERT. BPF_PROVE is intentionally limited to properties the verifier
     * can prove without losing stack/pointer precision through trie nodes.
     */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u8 host = input ? (u8)*input : 5;

    /* Symbolic bit extraction: the selected bits are fixed for any host byte. */
    u8 data_a[4] = {0};
    data_a[0] = 0x80 | (host & 0x7f);
    data_a[1] = host & 0x7f;
    BPF_PROVE(extract_bit(data_a, 0) == 1);
    BPF_PROVE(extract_bit(data_a, 8) == 0);

    struct lpm_trie trie;
    lpm_trie_init(&trie, 1);

    struct lpm_key_ipv4 key24;
    struct lpm_key_ipv4 key33;
    *(u64 *)&key24 = 0x0001a8c000000018ULL;
    *(u64 *)&key33 = 0x0001a8c000000021ULL;

    u64 value = 0x1122334455667788ULL;
    BPF_PROVE(trie_lookup_elem(&trie.map, &key33.hdr) == NULL);
    BPF_PROVE(trie_update_elem(&trie.map, &key33.hdr, &value, BPF_ANY) == -EINVAL);
    BPF_PROVE(trie_update_elem(&trie.map, &key24.hdr, &value, BPF_EXIST + 1) == -EINVAL);
    BPF_PROVE(trie_delete_elem(&trie.map, &key33.hdr) == -EINVAL);
    BPF_PROVE(trie_delete_elem(&trie.map, &key24.hdr) == -ENOENT);

    return host;
