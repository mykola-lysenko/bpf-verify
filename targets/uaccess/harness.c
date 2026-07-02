    __u32 key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &key);
    u64 seed = input ? *input : 0x0102030405060708ULL;
    u8 src[8];
    u8 dst[8];
    int user_word = (int)(seed >> 32);
    int got = 0;
    int i;

    for (i = 0; i < 8; i++) {
        src[i] = (u8)(seed >> (i * 8));
        dst[i] = 0xaa;
    }

    BPF_ASSERT(copy_from_user(dst, (const void __user *)src, 4) == 0);
    BPF_ASSERT(dst[0] == src[0] && dst[3] == src[3]);

    BPF_ASSERT(copy_to_user((void __user *)(dst + 4), src + 4, 4) == 0);
    BPF_ASSERT(dst[4] == src[4] && dst[7] == src[7]);

    BPF_ASSERT(raw_copy_from_user(dst, (const void __user *)(src + 2), 2) == 0);
    BPF_ASSERT(dst[0] == src[2] && dst[1] == src[3]);

    BPF_ASSERT(get_user(got, (int __user *)&user_word) == 0);
    BPF_ASSERT(got == user_word);
    BPF_ASSERT(put_user(0x5a, (u8 __user *)&dst[0]) == 0);
    BPF_ASSERT(dst[0] == 0x5a);

    BPF_ASSERT(clear_user((void __user *)dst, 4) == 0);
    BPF_ASSERT(dst[0] == 0 && dst[3] == 0);
    BPF_ASSERT(copy_to_user((void __user *)dst, src, 17) == 17);

    return dst[0] + dst[4] + got;
