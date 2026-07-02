
    /* mpih_submul1: multiply-subtract test */
    unsigned long res[2] = {100, 0};
    unsigned long s1[2] = {3, 0};
    mpihelp_submul_1(res, s1, 2, 5);
    (void)res[0];
    return 0;
