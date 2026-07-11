    /* asn1_encoder: exercise the public DER encoders, which pull in the static
     * asn1_encode_length / asn1_encode_oid_digit helpers. Map-seeded inputs keep
     * the encoding + bounds logic live; return the total encoded length. */
    __u32 k0 = 0, k1 = 1, k2 = 2;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    __u64 *c = bpf_map_lookup_elem(&input_map, &k2);
    unsigned char buf[64];
    unsigned char *data = buf, *end = buf + sizeof(buf);

    data = asn1_encode_integer(data, end, (s64)(a ? *a : 0));
    if (IS_ERR(data))
        return 0;
    data = asn1_encode_boolean(data, end, (unsigned char)((b ? *b : 0) & 1));
    if (IS_ERR(data))
        return 0;

    u32 oid[4] = { (u32)(c ? *c : 1) % 3, 40, 3, 4 };
    data = asn1_encode_oid(data, end, oid, 4);
    if (IS_ERR(data))
        return 0;

    return (int)(data - buf);
