
    /* ratelimit: test that ___ratelimit allows the first burst messages */
    struct ratelimit_state rs;
    ratelimit_state_init(&rs, 1000, 5);
    /* First call should always be allowed (burst not yet exhausted) */
    BPF_ASSERT(___ratelimit(&rs, "test"));
    return 0;
