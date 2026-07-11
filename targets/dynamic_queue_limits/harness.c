    /* dql_init/dql_reset: seed the queue limit so the struct setup stays live. */
    __u32 k0 = 0, k1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    struct dql dql_obj;
    dql_init(&dql_obj, (unsigned int)(a ? *a : 64));
    dql_reset(&dql_obj);
    dql_obj.limit = (unsigned int)(b ? *b : 0);
    return (int)(dql_obj.limit + dql_obj.num_queued + dql_obj.adj_limit);
