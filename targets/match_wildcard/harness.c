    /* match_wildcard: parser.c's '*'/'?' backtracking matcher. Property:
     * reflexivity on literals -- a string with no metacharacters matches
     * itself, and only itself among equal-length literals. We build a literal
     * pattern/string from a metacharacter-free alphabet and assert
     * match_wildcard(s, s) is true, while a single-char mutation makes it
     * false. execute:true fuzzes this per iteration (0 = pass). */
    __u32 k0 = 0, k1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    __u64 sa = a ? *a : 0x0123456789abcdefULL;
    __u64 sb = b ? *b : 0x1122334455667788ULL;

    /* 64-byte zero-filled buffers: match_wildcard's '*' backtracking re-scans
     * from the last star position, and the verifier explores those paths
     * without knowing the seeded chars aren't wildcards; the generous NUL
     * padding keeps every explored pointer advance in bounds. */
    static const char lit[8] = { 'a','b','c','d','e','f','g','h' };
    char s[64];
    int i;
    for (i = 0; i < 64; i++) s[i] = 0;
    for (i = 0; i < 8; i++)
        s[i] = lit[(sa >> (i * 8)) & 7];

    /* literal self-match must hold */
    BPF_ASSERT(match_wildcard(s, s));

    /* mutate one position to a different literal -> must NOT match (same
     * length, no wildcards, so equality is exact) */
    char t[64];
    for (i = 0; i < 64; i++) t[i] = s[i];
    int pos = (int)(sb & 7);
    t[pos] = lit[(((sb >> 8) & 7) + 1) & 7] == s[pos]
             ? lit[(((sb >> 8) & 7) + 2) & 7] : lit[(((sb >> 8) & 7) + 1) & 7];
    if (t[pos] != s[pos])
        BPF_ASSERT(!match_wildcard(t, s));

    return 0;
