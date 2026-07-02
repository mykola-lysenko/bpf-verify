
    /* kfifo: test kfifo_in and kfifo_out round-trip */
    DECLARE_KFIFO(fifo, unsigned int, 8);
    INIT_KFIFO(fifo);
    unsigned int val = 42;
    unsigned int out = 0;
    kfifo_in(&fifo, &val, 1);
    kfifo_out(&fifo, &out, 1);
    if (out != 42) { *(volatile int *)0 = 0; }
    return 0;
