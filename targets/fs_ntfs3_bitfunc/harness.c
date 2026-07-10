    /* fs/ntfs3/bitfunc.c: first-byte bit range set/clear checks. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0xa5;
    u8 clear_map[2];
    u8 set_map[2];
    bool clear_ok;
    bool set_ok;
    bool clear_fail;
    bool set_fail;

    clear_map[0] = (u8)seed & (u8)~0x0e;
    clear_map[1] = (u8)(seed >> 8);
    set_map[0] = ((u8)seed) | 0x0e;
    set_map[1] = (u8)(seed >> 16);

    clear_ok = are_bits_clear(clear_map, 1, 3);
    set_ok = are_bits_set(set_map, 1, 3);
    clear_fail = are_bits_clear(set_map, 1, 3);
    set_fail = are_bits_set(clear_map, 1, 3);

    return (int)(clear_ok + set_ok + clear_fail + set_fail +
                 clear_map[0] + set_map[0]);
