# userspace/ — sanitizer-backed property & differential fuzzing

The BPF verifier and the in-kernel execution leg (`tools/bpf_runner.c`) can only
reach code that *loads* as a BPF program. Many of the most bug-rich kernel
functions can't: decompressors and parsers have unbounded loops the verifier
rejects, and memory-safety bugs are best caught by AddressSanitizer, not by a
program returning `-1`. This directory compiles isolated kernel `lib/` functions
as ordinary host code under **ASan + UBSan** and fuzzes them for property
violations and out-of-bounds accesses.

This complements the in-kernel leg rather than replacing it:

| | in-kernel execution leg | userspace leg (here) |
|---|---|---|
| runs | verified BPF programs, in UML | host binaries under ASan/UBSan |
| reaches | only code the verifier accepts | any self-contained `lib/` function |
| catches | asserted property returns `-1` | property violation **and** OOB memory access |
| oracle | `BPF_ASSERT` in the harness | `fuzz_case()` return + sanitizer traps |

## Layout

| Path | Purpose |
|------|---------|
| `khost.h` | Host shim: kernel types + primitives (`fls`, `do_div`, `likely`, …). Force-included. Keeps real libc `memcpy`/`memset` so ASan instruments genuine memory ops. |
| `fuzz.h` | Fuzzing framework: reproducible per-iteration PRNG, corner-value biasing, `fuzz_u64()`/`fuzz_bytes()`/`fuzz_range()`. |
| `fuzz_main.c` | Driver `main()`: iteration loop, repro reporting, exit status. |
| `shim/linux/*.h` | Minimal replacements for kernel infra headers so real `.c` files include cleanly (real API headers like `linux/lz4.h` still come from the kernel tree). |
| `harnesses/<name>.c` | One target: defines `fuzz_case()` + `fuzz_name`. Includes the real kernel source (preferred, tracks upstream) or copies a small function verbatim. |
| `harnesses/<name>.flags` | Optional per-harness compiler flags (may reference `$KSRC`, `$HERE`, `$REPO`). |
| `run.sh` | Build each harness with ASan+UBSan and run it. |

## Running

```bash
# all harnesses (kernel tree auto-located in the submodule build, or set BPF_KSRC)
bash userspace/run.sh --iters 5000000

# one harness, more iterations
bash userspace/run.sh --iters 50000000 reciprocal_div
```

A harness exits non-zero (and prints a reproducer: iteration index + base seed)
on a property violation; ASan/UBSan abort immediately on any memory-safety or
UB violation.

## Writing a harness

`fuzz_case()` returns 0 on success, non-zero on a property violation, and pulls
inputs from `fuzz_u64()` / `fuzz_bytes()` / `fuzz_range()`. Prefer including the
real kernel `.c` via a `-D<NAME>_SRC="..."` path in the `.flags` file so the
harness tracks upstream; when copying a function verbatim instead, note it so it
can be re-checked against the kernel source.

Good oracles, in rough order of bug-finding power:
1. **Differential** — compare against a trusted reference (`reciprocal_divide`
   vs real `/`).
2. **Round-trip** — `decode(encode(x)) == x` (`lz4_roundtrip`).
3. **Postcondition** — a documented invariant (`int_sqrt`: `y² ≤ x < (y+1)²`).
4. **Safety under corruption** — feed a valid structure, mutate it, require no
   OOB (`lz4_roundtrip` property 2, `lz4_decompress`).

## Current targets & results

See `../FINDINGS_EXECUTION.md`. All current targets are mainline, well-fuzzed
code and pass clean — the negatives are legitimate evidence, and the framework
is ready to point at less-travelled code as it is added.
