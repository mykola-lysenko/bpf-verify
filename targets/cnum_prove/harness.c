    /* cnum proof harness: verifier-enforced invariants over bounded dynamic
     * ranges. The bounds avoid wraparound so the checked identities are exact
     * and failures are meaningful verifier/property failures.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    u32 lo32 = (u32)(*vp & 0xff);
    u32 len32 = (u32)((*vp >> 8) & 0xff);
    u32 hi32 = lo32 + len32;
    u64 lo64 = *vp & 0xffff;
    u64 len64 = (*vp >> 32) & 0xff;
    u64 hi64 = lo64 + len64;

    struct cnum32 c32 = cnum32_from_urange(lo32, hi32);
    struct cnum32 inter32 = cnum32_intersect(c32, c32);
    struct cnum32 mut32 = c32;
    struct cnum64 c64 = cnum64_from_urange(lo64, hi64);
    struct cnum64 inter64 = cnum64_intersect(c64, c64);
    struct cnum32 from64 = cnum32_from_cnum64(c64);
    struct cnum64 cross = cnum64_cnum32_intersect(c64, from64);

    BPF_PROVE(c32.base == lo32);
    BPF_PROVE(c32.size == len32);
    BPF_PROVE(cnum32_umin(c32) == lo32);
    BPF_PROVE(cnum32_umax(c32) == hi32);
    BPF_PROVE(cnum32_contains(c32, lo32));
    BPF_PROVE(cnum32_contains(c32, hi32));
    BPF_PROVE(cnum32_is_subset(c32, c32));
    BPF_PROVE(inter32.base == c32.base && inter32.size == c32.size);

    cnum32_intersect_with_urange(&mut32, lo32, hi32);
    BPF_PROVE(mut32.base == c32.base && mut32.size == c32.size);

    BPF_PROVE(c64.base == lo64);
    BPF_PROVE(c64.size == len64);
    BPF_PROVE(cnum64_umin(c64) == lo64);
    BPF_PROVE(cnum64_umax(c64) == hi64);
    BPF_PROVE(cnum64_contains(c64, lo64));
    BPF_PROVE(cnum64_contains(c64, hi64));
    BPF_PROVE(cnum64_is_subset(c64, c64));
    BPF_PROVE(inter64.base == c64.base && inter64.size == c64.size);
    BPF_PROVE(from64.base == (u32)lo64 && from64.size == (u32)len64);
    BPF_PROVE(cross.base == c64.base && cross.size == c64.size);

    return (int)(c32.size + c64.size + from64.size);
