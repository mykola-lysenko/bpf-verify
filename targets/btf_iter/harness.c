    /* btf_iter: BTF type/member field offset iteration for IDs and strings. */
    struct {
        struct btf_type type;
        struct btf_member members[2];
    } rec = {};
    struct btf_field_iter it = {};
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;
    u32 *field;
    u32 sum = 0;
    u32 errors = 0;

    rec.type.name_off = 3;
    rec.type.info = (BTF_KIND_STRUCT << 24) | 2;
    rec.members[0].name_off = 5;
    rec.members[0].type = 10 + (seed & 1);
    rec.members[1].name_off = 7;
    rec.members[1].type = 20 + (seed & 1);

    errors |= btf_field_iter_init(&it, &rec.type, BTF_FIELD_ITER_IDS) != 0;
    field = btf_field_iter_next(&it);
    errors |= !field;
    if (field)
        sum += *field;
    field = btf_field_iter_next(&it);
    errors |= !field;
    if (field)
        sum += *field;
    errors |= btf_field_iter_next(&it) != NULL;

    errors |= btf_field_iter_init(&it, &rec.type, BTF_FIELD_ITER_STRS) != 0;
    field = btf_field_iter_next(&it);
    errors |= !field;
    if (field)
        sum += *field;
    field = btf_field_iter_next(&it);
    errors |= !field;
    if (field)
        sum += *field;
    field = btf_field_iter_next(&it);
    errors |= !field;
    if (field)
        sum += *field;
    errors |= btf_field_iter_next(&it) != NULL;

    errors |= btf_field_iter_init(&it, &rec.type, 99) != -EINVAL;

    return (int)(errors + sum + (seed & 1));