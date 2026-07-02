    /* dql_init sets up a dql struct - avoids jiffies read in dql_completed */
    struct dql dql_obj;
    dql_init(&dql_obj, 64);
    /* Only test dql_init and dql_reset - dql_completed reads jiffies (extern) */
    dql_reset(&dql_obj);
    return (int)dql_obj.limit;