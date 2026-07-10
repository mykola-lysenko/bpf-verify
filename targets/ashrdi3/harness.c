    /* __ashrdi3 is arithmetic shift right for 64-bit */
    long long val = -1024LL;
    long long r = __ashrdi3(val, 2);
    return (int)r;
