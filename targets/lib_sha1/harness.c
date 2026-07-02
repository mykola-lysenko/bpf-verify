    /* SHA-1 generic block/hash path. */
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&input_map, &key);
    if (!v) return 0;
    u8 data[SHA1_BLOCK_SIZE] = {0};
    u8 out[SHA1_DIGEST_SIZE];
    *(__u64 *)&data[0] = *v;
    sha1(data, sizeof(data), out);
    return out[0];