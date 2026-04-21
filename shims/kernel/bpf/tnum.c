// SPDX-License-Identifier: GPL-2.0-only
/* tnum-shim.c: BPF-compatible shim for kernel/bpf/tnum.c
 *
 * tnum.c defines all functions as non-static and returning struct tnum by value
 * (StructRet ABI). The BPF backend rejects non-static StructRet functions.
 *
 * This shim redefines all tnum functions as static __always_inline, which:
 * 1. Forces the compiler to inline every call site (no StructRet in the BPF ELF).
 * 2. Avoids the need for any external symbol resolution.
 *
 * The function bodies are copied verbatim from kernel/bpf/tnum.c (Linux 6.1).
 * Only the storage class and inline qualifier are added.
 */
#include <linux/types.h>
#include <asm-generic/bitops/fls64.h>

/* struct tnum: tristate number -- tracks known/unknown bits of a value.
 * value: the known bit values (0 or 1 for known bits, 0 for unknown bits).
 * mask:  1 = bit is unknown, 0 = bit is known.
 */
struct tnum {
    u64 value;
    u64 mask;
};

#define TNUM(_v, _m) (struct tnum){.value = (_v), .mask = (_m)}

/* A completely unknown value */
static const struct tnum tnum_unknown = { .value = 0, .mask = -1 };

static __always_inline struct tnum tnum_const(u64 value)
{
    return TNUM(value, 0);
}

static __always_inline struct tnum tnum_range(u64 min, u64 max)
{
    u64 chi = min ^ max, delta;
    u8 bits = fls64(chi);

    if (bits > 63)
        return tnum_unknown;
    delta = (1ULL << bits) - 1;
    return TNUM(min & ~delta, delta);
}

static __always_inline struct tnum tnum_lshift(struct tnum a, u8 shift)
{
    return TNUM(a.value << shift, a.mask << shift);
}

static __always_inline struct tnum tnum_rshift(struct tnum a, u8 shift)
{
    return TNUM(a.value >> shift, a.mask >> shift);
}

static __always_inline struct tnum tnum_arshift(struct tnum a, u8 min_shift, u8 insn_bitness)
{
    if (insn_bitness == 32)
        return TNUM((u32)(((s32)a.value) >> min_shift),
                    (u32)(((s32)a.mask)  >> min_shift));
    else
        return TNUM((s64)a.value >> min_shift,
                    (s64)a.mask  >> min_shift);
}

static __always_inline struct tnum tnum_add(struct tnum a, struct tnum b)
{
    u64 sm, sv, sigma, chi, mu;

    sm = a.mask + b.mask;
    sv = a.value + b.value;
    sigma = sm + sv;
    chi = sigma ^ sv;
    mu = chi | a.mask | b.mask;
    return TNUM(sv & ~mu, mu);
}

static __always_inline struct tnum tnum_sub(struct tnum a, struct tnum b)
{
    u64 dv, alpha, beta, chi, mu;

    dv = a.value - b.value;
    alpha = dv + a.mask;
    beta = dv - b.mask;
    chi = alpha ^ beta;
    mu = chi | a.mask | b.mask;
    return TNUM(dv & ~mu, mu);
}

static __always_inline struct tnum tnum_and(struct tnum a, struct tnum b)
{
    u64 alpha, beta, v;

    alpha = a.value | a.mask;
    beta = b.value | b.mask;
    v = a.value & b.value;
    return TNUM(v, alpha & beta & ~v);
}

static __always_inline struct tnum tnum_or(struct tnum a, struct tnum b)
{
    u64 v, mu;

    v = a.value | b.value;
    mu = a.mask | b.mask;
    return TNUM(v, mu & ~v);
}

static __always_inline struct tnum tnum_xor(struct tnum a, struct tnum b)
{
    u64 v, mu;

    v = a.value ^ b.value;
    mu = a.mask | b.mask;
    return TNUM(v & ~mu, mu);
}

static __always_inline struct tnum tnum_mul(struct tnum a, struct tnum b)
{
    u64 acc_v = a.value * b.value;
    struct tnum acc_m = TNUM(0, 0);

    while (a.value || a.mask) {
        if (a.value & 1)
            acc_m = tnum_add(acc_m, TNUM(0, b.mask));
        else if (a.mask & 1)
            acc_m = tnum_add(acc_m, TNUM(0, b.value | b.mask));
        a = tnum_rshift(a, 1);
        b = tnum_lshift(b, 1);
    }
    return tnum_add(TNUM(acc_v, 0), acc_m);
}

static __always_inline struct tnum tnum_intersect(struct tnum a, struct tnum b)
{
    u64 v, mu;

    v = a.value | b.value;
    mu = a.mask & b.mask;
    return TNUM(v & ~mu, mu);
}

static __always_inline struct tnum tnum_cast(struct tnum a, u8 size)
{
    a.value &= (1ULL << (size * 8)) - 1;
    a.mask  &= (1ULL << (size * 8)) - 1;
    return a;
}

static __always_inline bool tnum_is_aligned(struct tnum a, u64 size)
{
    if (!size)
        return true;
    return !((a.value | a.mask) & (size - 1));
}

static __always_inline bool tnum_in(struct tnum a, struct tnum b)
{
    if (b.mask & ~a.mask)
        return false;
    b.value &= ~a.mask;
    return a.value == b.value;
}

/* tnum_strn / tnum_sbin: string formatting -- not exercised in the BPF harness
 * (snprintf is not available in BPF context). Provided as stubs. */
static __always_inline int tnum_strn(char *str, __kernel_size_t size, struct tnum a)
{
    (void)str; (void)size; (void)a;
    return 0;
}

static __always_inline int tnum_sbin(char *str, __kernel_size_t size, struct tnum a)
{
    (void)str; (void)size; (void)a;
    return 0;
}

static __always_inline struct tnum tnum_subreg(struct tnum a)
{
    return tnum_cast(a, 4);
}

static __always_inline struct tnum tnum_clear_subreg(struct tnum a)
{
    return tnum_lshift(tnum_rshift(a, 32), 32);
}

static __always_inline struct tnum tnum_const_subreg(struct tnum a, u32 value)
{
    return tnum_or(tnum_clear_subreg(a), tnum_const(value));
}
