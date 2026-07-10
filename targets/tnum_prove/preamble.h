/* Proof wrappers are forced inline so BPF_PROVE can reason through the
 * struct-by-value tnum operations after they write into pointer outputs. */
static __attribute__((always_inline))
void tnum_const_to_ptr(u64 value, struct tnum *out)
{ *out = tnum_const(value); }
static __attribute__((always_inline))
void tnum_add_to_ptr(struct tnum a, struct tnum b, struct tnum *out)
{ *out = tnum_add(a, b); }
static __attribute__((always_inline))
void tnum_sub_to_ptr(struct tnum a, struct tnum b, struct tnum *out)
{ *out = tnum_sub(a, b); }
static __attribute__((always_inline))
void tnum_and_to_ptr(struct tnum a, struct tnum b, struct tnum *out)
{ *out = tnum_and(a, b); }
static __attribute__((always_inline))
void tnum_or_to_ptr(struct tnum a, struct tnum b, struct tnum *out)
{ *out = tnum_or(a, b); }
static __attribute__((always_inline))
void tnum_xor_to_ptr(struct tnum a, struct tnum b, struct tnum *out)
{ *out = tnum_xor(a, b); }
static __attribute__((always_inline))
void tnum_lshift_to_ptr(struct tnum a, u8 shift, struct tnum *out)
{ *out = tnum_lshift(a, shift); }
static __attribute__((always_inline))
void tnum_rshift_to_ptr(struct tnum a, u8 shift, struct tnum *out)
{ *out = tnum_rshift(a, shift); }
static __attribute__((always_inline))
void tnum_intersect_to_ptr(struct tnum a, struct tnum b, struct tnum *out)
{ *out = tnum_intersect(a, b); }
static __attribute__((always_inline))
void tnum_union_to_ptr(struct tnum a, struct tnum b, struct tnum *out)
{ *out = tnum_union(a, b); }
static __attribute__((always_inline))
bool tnum_in_wrap(struct tnum a, struct tnum b)
{ return tnum_in(a, b); }
