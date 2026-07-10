#pragma clang attribute pop
#pragma clang attribute pop

static __attribute__((__noinline__)) int __bpf_liveness_arg_track_probe(void)
{
    struct bpf_verifier_env env = {};
    struct arg_track none = { .frame = ARG_NONE };
    struct arg_track unvisited = { .frame = ARG_UNVISITED };
    struct arg_track a, b, c, imp, old;
    s16 out = 0;
    int ret = 0;

    a = arg_single(0, -8);
    if (a.frame != 0 || a.off_cnt != 1 || a.off[0] != -8)
        return -1;
    ret += a.off_cnt;

    c = __arg_track_join(unvisited, a);
    if (c.frame != 0 || c.off_cnt != 1 || c.off[0] != -8)
        return -2;
    ret += c.off_cnt;

    b = arg_single(2, -16);
    c = __arg_track_join(a, b);
    if (c.frame != ARG_IMPRECISE || c.mask != (BIT(0) | BIT(2)))
        return -3;
    ret += c.mask;

    imp = arg_join_imprecise(c, arg_single(1, -24));
    if (imp.frame != ARG_IMPRECISE ||
        imp.mask != (BIT(0) | BIT(1) | BIT(2)))
        return -4;
    ret += imp.mask;

    if (!arg_is_visited(&a) || arg_is_visited(&unvisited))
        return -5;
    if (!arg_is_fp(&a) || !arg_is_fp(&imp) || arg_is_fp(&none))
        return -6;
    ret += 1;

    old = unvisited;
    if (!arg_track_join(&env, 1, 2, BPF_REG_1, &old, a))
        return -7;
    if (old.frame != 0 || old.off_cnt != 1 || old.off[0] != -8)
        return -8;
    ret += old.off_cnt;

    old = a;
    if (!arg_track_join(&env, 2, 3, BPF_REG_1, &old, b))
        return -9;
    if (old.frame != ARG_IMPRECISE || old.mask != (BIT(0) | BIT(2)))
        return -10;
    ret += old.mask;

    a = arg_single(1, -32);
    b = arg_single(1, -16);
    c = __arg_track_join(a, b);
    if (c.frame != 1 || c.off_cnt != 2 ||
        c.off[0] != -32 || c.off[1] != -16)
        return -15;
    ret += c.off_cnt;

    old = c;
    b = arg_single(1, -16);
    c = __arg_track_join(old, b);
    if (c.frame != 1 || c.off_cnt != 2 ||
        c.off[0] != -32 || c.off[1] != -16)
        return -16;
    ret += c.off_cnt;

    a = (struct arg_track){
        .off = { -64, -48, -32, -16 },
        .frame = 1,
        .off_cnt = 4,
    };
    b = arg_single(1, -8);
    c = __arg_track_join(a, b);
    if (c.frame != 1 || c.off_cnt != 0)
        return -17;
    ret += c.frame + 1;

    old = arg_single(1, -32);
    b = arg_single(1, -16);
    if (!arg_track_join(&env, 4, 5, BPF_REG_2, &old, b))
        return -18;
    if (old.frame != 1 || old.off_cnt != 2 ||
        old.off[0] != -32 || old.off[1] != -16)
        return -19;
    ret += old.off_cnt;

    if (arg_track_join(&env, 5, 6, BPF_REG_2, &old, b))
        return -20;
    ret += 1;

    a = arg_single(0, -64);
    b = none;
    arg_track_alu64(&a, &b);
    if (a.frame != 0 || a.off_cnt != 0)
        return -11;
    ret += a.frame + 1;

    a = none;
    b = arg_single(2, -72);
    arg_track_alu64(&a, &b);
    if (a.frame != 2 || a.off_cnt != 0)
        return -12;
    ret += a.frame;

    a = arg_single(0, -8);
    b = arg_single(1, -8);
    arg_track_alu64(&a, &b);
    if (a.frame != ARG_IMPRECISE || a.mask != (BIT(0) | BIT(1)))
        return -13;
    ret += a.mask;

    if (arg_add(-32, 24, &out) || out != -8)
        return -14;
    ret += (int)(-out);

    return ret;
}
