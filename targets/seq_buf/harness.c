    __u32 key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &key);
    u64 seed = input ? *input : 0x1020304050607080ULL;
    char buf[32];
    char small[4];
    u8 mem[4];
    struct seq_buf s;
    struct seq_buf tiny;
    int overflow_ret;
    int errors = 0;

    mem[0] = (u8)seed;
    mem[1] = (u8)(seed >> 8);
    mem[2] = (u8)(seed >> 16);
    mem[3] = (u8)(seed >> 24);

    seq_buf_init(&s, buf, sizeof(buf));
    errors |= seq_buf_puts(&s, "ok");
    BPF_ASSERT(seq_buf_used(&s) == 2);
    errors |= seq_buf_putmem(&s, mem, sizeof(mem));
    errors |= seq_buf_putc(&s, (unsigned char)(seed >> 32));
    errors |= seq_buf_putmem(&s, mem + 2, 2);
    errors |= seq_buf_putmem_hex(&s, mem, sizeof(mem));
    BPF_ASSERT(!seq_buf_has_overflowed(&s));
    BPF_ASSERT(seq_buf_used(&s) == 18);
    BPF_ASSERT(buf[0] == 'o' && buf[1] == 'k');

    seq_buf_init(&tiny, small, sizeof(small));
    errors |= seq_buf_putmem(&tiny, mem, sizeof(small));
    BPF_ASSERT(seq_buf_used(&tiny) == sizeof(small));
    overflow_ret = seq_buf_putc(&tiny, 'x');
    BPF_ASSERT(overflow_ret < 0);
    BPF_ASSERT(seq_buf_has_overflowed(&tiny));
    BPF_ASSERT(seq_buf_used(&tiny) == sizeof(small));

    return errors + (int)seq_buf_used(&s) + buf[0];
