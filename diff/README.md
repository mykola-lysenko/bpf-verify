# diff/ — native-vs-BPF differential testing

The project's thesis is *compile real kernel code to BPF and verify it in the
UML kernel*. This leg closes the loop on **correctness**: it compiles the same
kernel function two ways and checks they compute the same thing.

- **BPF side:** the function is compiled to BPF exactly as the pipeline does it
  (same shim tree, cflags, includes), verified, and run in the UML guest via
  `BPF_PROG_TEST_RUN`.
- **Native side:** the same function is compiled as ordinary host code
  (`userspace/khost.h` shim) and run directly — the trusted reference.

Both sides are fed **identical** inputs from one deterministic generator
(`tools/diff_seed.h`) and their outputs are diffed. A divergence means the BPF
toolchain produced a program that computes a different result than native for
real kernel code — i.e. a **BPF backend miscompilation** or a
verifier-accepted-but-incorrect program. The BPF backend is far less mature
than the verifier, so this is where a silent-wrong-answer bug is most plausible,
and it stays entirely on-thesis (no external fuzzer, native execution is the
oracle).

## How a result is observed

The BPF program returns a **32-bit fold** of its 64-bit result
(`r ^ (r >> 32)`) via the program return value; the native side folds
identically. The fold makes any 64-bit divergence visible in the 32-bit return
and is the identity for results that already fit in 32 bits. (A per-iteration
fold collision is possible but a *persistent* divergence is caught with
overwhelming probability across many iterations.)

## Adding a target

A target reuses the pipeline's `targets/<name>` BPF build config and adds:

| File | Purpose |
|------|---------|
| `diff/<name>/compute.h` | `static __u64 diff_compute(const __u64 in[4])` — the shared computation, calling the target's function(s). Included at file scope on both sides after the kernel source. |
| `diff/<name>/native.flags` | Host compiler flags for the native build: shim include, `-I$KSRC/include`, any `-U/-D` the target needs, and `-DDIFF_KSRC="…"` pointing at the kernel `.c`. May reference `$REPO`, `$KSRC`, `$HERE`. |
| `diff/<name>/base` | *Optional* name of a different `targets/<base>` whose BPF build config to reuse — so several diff targets can exercise different functions from one source file (e.g. `mul_div` reuses `div64`). |
| `diff/<name>/harness.c` | *Optional* BPF harness body override; the default (read 4 inputs, fold-return `diff_compute`) suits most targets. |

Run one target:

```bash
# same BPF_* env as the pipeline; BPF_KSRC etc. auto-default to the submodule build
bash tools/diff.sh <name> --iters 200000
```

## Current targets

| Target | Function | What it stresses |
|--------|----------|------------------|
| `bitrev` | `bitrev32` | bit-reversal codegen (plumbing proof) |
| `div64`  | `div64_u64` | 64-bit division lowering (fallback path), a classic BPF-backend weak spot |
| `xxhash` | `xxh64` | 64-bit multiply-by-prime lowering |
| `crc16`  | `crc16` | table-lookup + shift/xor loop codegen |
| `crc_ccitt` | `crc_ccitt` | CRC-CCITT table lookup |
| `int_pow` | `int_pow` | 64-bit multiply loop (bounded exponent) |

All agree with native over 100k inputs each.

## Targets that can't be differentially tested (boundary findings)

The differential requires the BPF side to *load and run*, which excludes code
the BPF toolchain rejects. Two attempted targets hit real boundaries and are
recorded in `../FINDINGS_EXECUTION.md`:

- `mul_u64_add_u64_div_u64` — the verifier rejects the `-U__SIZEOF_INT128__`
  128-bit long-division fallback with "infinite loop detected" (its termination
  is bit-count-based, not syntactically bounded).
- `div64_s64` — the BPF backend refuses to compile it: "unsupported signed
  division, please convert to unsigned div/mod" (`math64.h`).

These belong to the userspace leg, not the in-UML differential.

Results (including the validation that a planted divergence is caught with the
exact reproducing seed) are recorded in `../FINDINGS_EXECUTION.md`.
