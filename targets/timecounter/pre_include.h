#define _LINUX_TIMECOUNTER_H
#define CYCLECOUNTER_MASK(bits) (u64)((bits) < 64 ? ((1ULL << (bits)) - 1) : -1)

struct cyclecounter {
    u64 (*read)(struct cyclecounter *cc);
    u64 mask;
    u32 mult;
    u32 shift;
};
struct timecounter {
    struct cyclecounter *cc;
    u64 cycle_last;
    u64 nsec;
    u64 mask;
    u64 frac;
};
struct __bpf_timecounter_hw {
    struct cyclecounter cc;
    u64 now;
};
static inline
u64 cyclecounter_cyc2ns(const struct cyclecounter *cc, u64 cycles,
                        u64 mask, u64 *frac)
{
    u64 ns = cycles;

    ns = (ns * cc->mult) + *frac;
    *frac = ns & mask;
    return ns >> cc->shift;
}
static inline
void timecounter_adjtime(struct timecounter *tc, s64 delta)
{
    tc->nsec += delta;
}
static inline
u64 cc_cyc2ns_backwards(const struct cyclecounter *cc, u64 cycles, u64 frac)
{
    return ((cycles * cc->mult) - frac) >> cc->shift;
}
static inline
u64 timecounter_cyc2time(const struct timecounter *tc, u64 cycle_tstamp)
{
    const struct cyclecounter *cc = tc->cc;
    u64 delta = (cycle_tstamp - tc->cycle_last) & cc->mask;
    u64 nsec = tc->nsec, frac = tc->frac;

    if (delta > cc->mask / 2) {
        delta = (tc->cycle_last - cycle_tstamp) & cc->mask;
        nsec -= cc_cyc2ns_backwards(cc, delta, frac);
    } else {
        nsec += cyclecounter_cyc2ns(cc, delta, tc->mask, &frac);
    }

    return nsec;
}
static inline
u64 __bpf_timecounter_read(struct cyclecounter *cc)
{
    return ((struct __bpf_timecounter_hw *)cc)->now;
}

#define timecounter_init static inline timecounter_init
#define timecounter_read static inline timecounter_read
