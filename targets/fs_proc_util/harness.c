    /* fs/proc/util.c: decimal proc name parser. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 1234;
    char dyn[4];
    char leading_zero[3] = { '0', '1', '2' };
    char nondigit[3] = { '1', 'x', '3' };
    struct qstr q = {};
    unsigned valid;
    unsigned zero_rejected;
    unsigned bad_rejected;

    dyn[0] = '1' + (char)(seed % 8);
    dyn[1] = '0' + (char)((seed >> 8) % 10);
    dyn[2] = '0' + (char)((seed >> 16) % 10);
    dyn[3] = '0' + (char)((seed >> 24) % 10);

    q.name = (const unsigned char *)dyn;
    q.len = sizeof(dyn);
    valid = name_to_int(&q);

    q.name = (const unsigned char *)leading_zero;
    q.len = sizeof(leading_zero);
    zero_rejected = name_to_int(&q);

    q.name = (const unsigned char *)nondigit;
    q.len = sizeof(nondigit);
    bad_rejected = name_to_int(&q);

    return (int)(valid + zero_rejected + bad_rejected);