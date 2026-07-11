# BPF global functions vs `always_inline` in this pipeline

When a harness calls a real kernel function, the function can be verified in one
of two ways. Understanding which — and why we lean on `always_inline` — matters,
because global functions are a real, encouraged BPF feature and their absence
here is a *pipeline* limitation, not a BPF one.

## The two subprogram models

- **Static subprogram** — a `static` (or effectively-static) function verified
  *in the caller's context*: the verifier tracks the concrete arguments the
  harness passes (e.g. a specific `char buf[64]` on the stack). Restrictions: it
  may not **return a pointer into the caller's stack** ("cannot return stack
  pointer to the caller"), and the pinned clang BPF backend rejects passing **>5
  arguments** via the stack to one.
- **Global function** (`__noinline`, external linkage) — verified **once,
  independently**, for *all* valid inputs described by its BTF argument types.
  Stronger and more general than a per-call check, and it needs no harness. This
  is the feature customers are encouraged to use.

## Why global functions are effectively OFF here

**The pipeline strips `.BTF.ext`** (`compile_harness` runs
`llvm-objcopy --remove-section=.BTF.ext`). That section carries the *func-info*
the verifier uses to recognize a global function and resolve its argument BTF.
With it stripped, every non-static function **degrades to a static subprogram**.

Demonstrated directly — a global fn `gfn(unsigned char *buf)` that reads
`buf[7]`:

| Build | Verdict | Interpretation |
|-------|---------|----------------|
| `.BTF.ext` **stripped** (default) | success | static subprogram, uses the harness's concrete `buf[8]` |
| `.BTF.ext` **kept** | failure: `R1 invalid mem access 'mem_or_null'` | true global fn — unsized pointer can't be bounded |

We strip `.BTF.ext` to avoid the verifier looking up the program's ctx type in
`btf_vmlinux` (absent on this UML kernel). That is the tradeoff that disables
global functions.

## Global-function ABI limits (measured, `.BTF.ext` kept)

| Argument shape | Verdict | Reason |
|----------------|---------|--------|
| scalar in, scalar out | **success** | scalars are fully supported |
| unsized pointer (`unsigned char *b`) | **failure** `invalid mem access 'mem_or_null'` | verifier can't bound it |
| sized buffer (`void *b, u32 b__sz`) | **failure** `arg#0 reference type UNKNOWN size cannot be determined` | the `__sz` convention needs resolvable arg BTF; fragile in our stripped/rebuilt BTF |

**Consequence for real kernel code:** even with global functions enabled, most
kernel functions don't fit the ABI. They bound buffers with `ptr + end` (a
*second pointer*) or an **un-annotated** `len`, not the `void *buf, u32 buf__sz`
convention, so their pointer accesses are rejected. Global functions cleanly
verify only kernel functions with scalar / typed-struct-pointer signatures.

**And global functions can be *harder*, not easier.** They are verified for
*all* inputs, whereas a static subprogram is verified against the harness's
concrete context. A PoC verifying `int_sqrt` (a pure scalar function) as a
global function (`-fno-inline` + kept `.BTF.ext`) hit the **1,000,000-insn
verifier limit** — the bit-loop explored symbolically over an unconstrained
input blows the complexity budget. (`-fno-inline` was too broad to isolate
cleanly, but the direction is real.) So global functions trade concrete-context
tractability for all-inputs generality; that trade sometimes loses. This is a
third reason `always_inline` + a bounded harness persists.

## So: is `always_inline` overkill?

Two distinct uses, only one related to the above:

1. **Shim-helper inlining** (most of the 41 uses): `__always_inline` on our own
   `memset`/`memmove`/`strnlen`/`memcpy` stubs, so they inline instead of
   becoming unresolved externs libbpf rejects. Standard and necessary;
   independent of global functions.
2. **Kernel-function workaround** (`gf128hash`, `zlib_inflate`, `asn1_encode`,
   the >5-arg targets): forcing the *real* function inline to sidestep the
   static-subprogram limits (pointer return, >5 stack args). Here a global
   function *would* be the cleaner tool — but it's off (stripped `.BTF.ext`) and
   the signatures usually don't fit the global-fn ABI anyway.

`always_inline` is therefore **not lazy** in the current setup — it's a
workaround for global functions being disabled plus real signatures not fitting.
It is, however, *coarse*: it bloats the verified program and loses the
independent, all-inputs guarantee a global function gives.

## Policy (be precise with `always_inline`)

- Reach for `always_inline` on a **target kernel function** only when it
  genuinely needs it: it returns a pointer into caller memory, takes >5 stack
  args, or bounds a buffer via an end-pointer. Otherwise prefer a **plain static
  subprogram** (no annotation) — it verifies with the harness's concrete args.
- `__always_inline` on **shim helpers** (memcpy-family) is fine and expected.
- Note *why* in the target's `pre_include.h`, so the choice is auditable.

## Roadmap item: actually enable global functions

The real precision win is not "avoid `always_inline`" but **enabling global
functions** for the subset of kernel functions whose signatures fit:

1. Keep `.BTF.ext` and solve the ctx-type lookup (e.g. per-program: a socket
   filter's ctx is `__sk_buff`; provide/repair the BTF the verifier needs, or
   verify global funcs in an object whose *main* program is trivial).
2. Classify candidate functions by signature; route scalar / typed-struct-pointer
   ones through **global-function** verification (independent, all-inputs) and
   keep the harness+`always_inline` path only for the rest.
3. This also turns the pipeline into a **characterization tool for the
   global-function feature itself** — exactly the kind of benign
   compiler/verifier-capability finding this project exists to produce.
