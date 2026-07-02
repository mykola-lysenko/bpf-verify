
    /* nh: test NH hash */
    u32 key[272] = {0};
    u8 msg[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    __le64 hash[4];
    nh(key, msg, 16, hash);
    (void)hash[0];
    return 0;
