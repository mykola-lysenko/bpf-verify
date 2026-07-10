    /* kernel/time/timecounter.c: prove cycle delta, wrap, and adjtime paths. */
    struct __bpf_timecounter_hw hw = {};
    struct timecounter tc = {};
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 now, future, past;

    hw.cc.read = __bpf_timecounter_read;
    hw.cc.mask = CYCLECOUNTER_MASK(8);
    hw.cc.mult = 2;
    hw.cc.shift = 1;
    hw.now = 250;

    timecounter_init(&tc, &hw.cc, 1000);
    BPF_PROVE(tc.cc == &hw.cc);
    BPF_PROVE(tc.cycle_last == 250);
    BPF_PROVE(tc.nsec == 1000);
    BPF_PROVE(tc.mask == 1);
    BPF_PROVE(tc.frac == 0);

    hw.now = 5;
    now = timecounter_read(&tc);
    BPF_PROVE(now == 1011);
    BPF_PROVE(tc.cycle_last == 5);

    hw.now = 10;
    now = timecounter_read(&tc);
    BPF_PROVE(now == 1016);
    BPF_PROVE(tc.cycle_last == 10);

    future = timecounter_cyc2time(&tc, 14);
    BPF_PROVE(future == 1020);
    past = timecounter_cyc2time(&tc, 7);
    BPF_PROVE(past == 1013);

    timecounter_adjtime(&tc, -10);
    BPF_PROVE(tc.nsec == 1006);

    if (input) {
        hw.now = 100;
        timecounter_init(&tc, &hw.cc, *input & 0xff);
        hw.now = (100 + (*input & 31)) & hw.cc.mask;
        now = timecounter_read(&tc);
        return (int)(now + future + past);
    }
    return (int)(now + future + past);
