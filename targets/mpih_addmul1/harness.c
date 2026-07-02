
    /* mpih_addmul1: multiply-accumulate test */
    unsigned long res[2] = {0, 0};
    unsigned long s1[2] = {3, 0};
    mpihelp_addmul_1(res, s1, 2, 5);
    (void)res[0];
    return 0;
