/* Pointer-based wrappers for tnum operations.
 * The shim gives tnum functions internal linkage so StructRet calls stay on
 * the static subprogram path. The wrappers themselves are __noinline so the
 * BPF verifier sees them as separate functions with pointer outputs. */
static __attribute__((__noinline__))
void tnum_const_to_ptr(u64 value, struct tnum *out)
{ *out = tnum_const(value); }
static __attribute__((__noinline__))
void tnum_add_to_ptr(struct tnum a, struct tnum b, struct tnum *out)
{ *out = tnum_add(a, b); }
static __attribute__((__noinline__))
void tnum_and_to_ptr(struct tnum a, struct tnum b, struct tnum *out)
{ *out = tnum_and(a, b); }
static __attribute__((__noinline__))
void tnum_or_to_ptr(struct tnum a, struct tnum b, struct tnum *out)
{ *out = tnum_or(a, b); }
static __attribute__((__noinline__))
bool tnum_in_wrap(struct tnum a, struct tnum b)
{ return tnum_in(a, b); }
