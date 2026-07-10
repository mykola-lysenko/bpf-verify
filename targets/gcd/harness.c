    /* gcd: verify the zero-operand fast path with a map-seeded value.
     * The full binary-GCD loop remains verifier-incompatible because it is
     * an unbounded for(;;) whose termination is mathematical, not syntactic. */
    __u32 key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &key);
    unsigned long a = input ? (unsigned long)*input : 42;
    volatile unsigned long zero = 0;
    unsigned long r = gcd(a, zero);
    return (int)(r ^ (a >> 32));
