
    /* scatterlist: test sg_init_table and sg_nents */
    struct scatterlist sgl[4];
    sg_init_table(sgl, 4);
    int n = sg_nents(sgl);
    if (n != 4) { *(volatile int *)0 = 0; }
    return 0;
