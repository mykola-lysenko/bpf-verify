    /* min_heap: heap ordering invariant after push/pop.
     *
     * BPF-friendly heap operations (__bpf_heap_push, __bpf_heap_pop) are
     * defined in EXTRA_PRE_INCLUDE. They call __bpf_int_less/__bpf_int_swap
     * directly (no function pointers) to avoid 'callx' instructions that
     * the BPF verifier rejects.
     *
     * Properties tested:
     *   1. After pushing 3 values, the root (minimum) is <= all pushed values
     *   2. After pop, the new root is >= the popped element
     *   3. Heap size decreases by 1 after pop
     */
    __u32 key0 = 0, key1 = 1, key2 = 2;
    __u64 *v0 = bpf_map_lookup_elem(&input_map, &key0);
    __u64 *v1 = bpf_map_lookup_elem(&input_map, &key1);
    __u64 *v2 = bpf_map_lookup_elem(&input_map, &key2);
    if (!v0 || !v1 || !v2) return 0;
    /* Use small values 1..4 to keep things bounded */
    int vals[3];
    vals[0] = (int)((*v0 & 3) + 1);  /* 1..4 */
    vals[1] = (int)((*v1 & 3) + 1);  /* 1..4 */
    vals[2] = (int)((*v2 & 3) + 1);  /* 1..4 */

    /* Get a pointer to the file-scope heap as min_heap_char */
    min_heap_char *heap = (min_heap_char *)&__bpf_heap_storage;
    __min_heap_init(heap, NULL, 8);

    /* Push 3 values using BPF-friendly push (no function pointers) */
    __bpf_heap_push(heap, &vals[0]);
    __bpf_heap_push(heap, &vals[1]);
    __bpf_heap_push(heap, &vals[2]);

    /* Property 1: root <= all pushed values */
    int *root_ptr = (int *)__min_heap_peek(heap);
    BPF_ASSERT(root_ptr != NULL);
    BPF_ASSERT(*root_ptr <= vals[0]);
    BPF_ASSERT(*root_ptr <= vals[1]);
    BPF_ASSERT(*root_ptr <= vals[2]);

    int root_val = *root_ptr;
    size_t nr_before = heap->nr;

    /* Pop the minimum using BPF-friendly pop (no function pointers) */
    __bpf_heap_pop(heap);

    /* Property 3: size decreased by 1 */
    BPF_ASSERT(heap->nr == nr_before - 1);

    /* Property 2: new root >= popped element */
    if (heap->nr > 0) {
        int *new_root = (int *)__min_heap_peek(heap);
        BPF_ASSERT(new_root != NULL);
        BPF_ASSERT(*new_root >= root_val);
    }
    return root_val;