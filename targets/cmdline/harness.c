    /* cmdline.c command-line parser helpers. */
    char opt_buf[] = "42,7-9";
    char *p = opt_buf;
    int val = 0;
    int ret = get_option(&p, &val);
    BPF_ASSERT(ret == 2);
    BPF_ASSERT(val == 42);

    int ints[5] = {0};
    char *tail = get_options("1,3-5", 5, ints);
    BPF_ASSERT(*tail == '\0');
    BPF_ASSERT(ints[0] == 4);
    BPF_ASSERT(ints[1] == 1);
    BPF_ASSERT(ints[2] == 3);
    BPF_ASSERT(ints[3] == 4);
    BPF_ASSERT(ints[4] == 5);

    char *endp = NULL;
    unsigned long long bytes = memparse("2K", &endp);
    BPF_ASSERT(bytes == 2048);
    BPF_ASSERT(*endp == '\0');

    BPF_ASSERT(parse_option_str("foo,bar,baz", "bar"));
    return val + ints[0] + (int)(bytes >> 10);