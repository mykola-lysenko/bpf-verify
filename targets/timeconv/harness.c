    /* kernel/time/timeconv.c: prove representative UTC calendar conversions
     * and keep a map-seeded offset path live so the target code is not
     * optimized into a constant. */
    struct tm tm = {};
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    int offset = input ? (int)(*input & 63) : 0;

    time64_to_tm(0, 0, &tm);
    BPF_PROVE(tm.tm_year == 70);
    BPF_PROVE(tm.tm_mon == 0);
    BPF_PROVE(tm.tm_mday == 1);
    BPF_PROVE(tm.tm_hour == 0);
    BPF_PROVE(tm.tm_min == 0);
    BPF_PROVE(tm.tm_sec == 0);
    BPF_PROVE(tm.tm_wday == 4);
    BPF_PROVE(tm.tm_yday == 0);

    time64_to_tm(951782400LL, 0, &tm);
    BPF_PROVE(tm.tm_year == 100);
    BPF_PROVE(tm.tm_mon == 1);
    BPF_PROVE(tm.tm_mday == 29);
    BPF_PROVE(tm.tm_wday == 2);
    BPF_PROVE(tm.tm_yday == 59);

    time64_to_tm(2147483647LL, 0, &tm);
    BPF_PROVE(tm.tm_year == 138);
    BPF_PROVE(tm.tm_mon == 0);
    BPF_PROVE(tm.tm_mday == 19);
    BPF_PROVE(tm.tm_hour == 3);
    BPF_PROVE(tm.tm_min == 14);
    BPF_PROVE(tm.tm_sec == 7);

    time64_to_tm(-1LL, 0, &tm);
    BPF_PROVE(tm.tm_year == 69);
    BPF_PROVE(tm.tm_mon == 11);
    BPF_PROVE(tm.tm_mday == 31);
    BPF_PROVE(tm.tm_hour == 23);
    BPF_PROVE(tm.tm_min == 59);
    BPF_PROVE(tm.tm_sec == 59);

    time64_to_tm(0, offset, &tm);
    return (int)(tm.tm_sec + tm.tm_min + tm.tm_hour + tm.tm_yday);
