# Execution-Leg Findings

Findings from the fuzz-execution leg (`tools/bpf_runner.c`, Phase 3 of the
pipeline) and from userspace differential/property fuzzing of the same target
sources. Unlike the verifier-characterization notes in
`BPF_Verification_Findings.md`, these come from *running* the code on real
inputs, so a failure here is a concrete, reproducible defect — and a
"does not reproduce" is a real negative result worth recording.

## Methodology

- **In-kernel execution.** Verified harnesses that opt in (`execute: true`)
  and follow the strict return contract (0 = pass, non-zero only via
  `BPF_ASSERT`) are run via `BPF_PROG_TEST_RUN` inside the uml-veristat UML
  guest, with `input_map` seeded from corner values then a pseudo-random
  stream. A non-zero return on any input is a candidate finding.
- **Userspace fuzzing.** For targets the verifier cannot accept (complexity
  limits, unbounded loops), the function body is compiled for the host and
  fuzzed directly. This sidesteps the verifier entirely and is the right tool
  for algorithmic properties on code that will never load as BPF.
- **Native-vs-BPF differential** (`diff/`, `tools/diff.sh`). The same kernel
  function is compiled to BPF (verified + run in UML) and to native host code,
  fed identical inputs from one generator, and the outputs are diffed. A
  divergence is a BPF-backend miscompilation or a verifier-accepted-incorrect
  program — the on-thesis complement to the property leg, using native
  execution as the oracle.

## Negative results (claims that did NOT reproduce)

### `rational_best_approximation` bound overshoot — NOT REPRODUCED

`BPF_Verification_Findings.md` (Phase 4) noted that
`rational_best_approximation()` "can technically overshoot the bounds
`max_n`/`max_d` for certain inputs." Tested against current bpf-next
(`lib/math/rational.c`, the 2019 Piepho semi-convergent rewrite):

- 50,000,000 random inputs (`given_numerator ∈ [0,1e5)`,
  `given_denominator ∈ [1,1e5]`, `max_numerator ∈ [1,255]`,
  `max_denominator ∈ [1,63]`): **0 overshoots**.
- Exhaustive small-domain sweep (`gn ∈ [0,150]`, `gd ∈ [1,150]`,
  `mn,md ∈ [1,45]`), 45,866,250 cases: **0 overshoots**.

Conclusion: the current implementation always returns
`best_numerator <= max_numerator` and `best_denominator <= max_denominator`.
The overshoot property holds; the earlier note does not reflect a defect in
the current kernel and should not be reported upstream. (The semi-convergent
term `t = min((max_denominator - d0) / d1, (max_numerator - n0) / n1)` is by
construction the largest step that keeps both fields within bounds.)

### Userspace sanitizer/property fuzzing — clean (no defects found)

All userspace harnesses (`userspace/harnesses/`, ASan + UBSan) pass with zero
failures against current bpf-next. These are mainline, heavily-fuzzed functions
(most are covered by OSS-Fuzz upstream), so clean runs are the expected and
legitimate result — they exercise and validate the framework:

| Target | Property | Iterations | Result |
|---|---|---|---|
| `reciprocal_div` | `reciprocal_divide(a, R(d)) == a / d` (differential vs real division, full 32-bit) | 20,000,000 | 0 failures |
| `int_sqrt` | `y² ≤ x < (y+1)²` (exact floor(sqrt), full u64 range) | 20,000,000 | 0 failures |
| `lz4_roundtrip` | `decompress(compress(x)) == x`, and mutated frames never OOB (ASan) | 3,000,000 | 0 failures |
| `lz4_decompress` | random/corrupt input never OOB (ASan) | 2,000,000 | 0 failures |
| `glob` | `glob_match(pat, str)` never reads past either NUL, adversarial metachar-heavy inputs (ASan) | 5,000,000 | 0 failures |
| `cpio` | `find_cpio_data()` never reads past the archive buffer, structured+corrupt "newc" headers (ASan) | 3,000,000 | 0 failures |
| `mldsa` | `mldsa_verify()` (ML-DSA/Dilithium post-quantum signature verify) never reads OOB while unpacking a malformed signature + public key (ASan) | 1,000,000 | 0 failures |
| `asn1` | `asn1_ber_decoder()` never reads past the buffer parsing malformed BER/DER (real OOB CVE history: CVE-2016-2053); driven with the generated rsapubkey grammar (ASan) | 3,000,000 | 0 failures |

The value of the leg is the capability plus the property/differential oracles;
it is ready to point at less-travelled kernel code as targets are added.

### BPF verifier abstract-domain soundness (`tnum`) — sound (no violation found)

`userspace/harnesses/tnum_soundness.c` fuzzes the verifier's own tristate-number
domain (`kernel/bpf/tnum.c`) for **soundness**: for random small tnums `a`, `b`,
it enumerates `gamma(a)` and `gamma(b)` *exhaustively* and checks that every
concrete `OP(x, y)` is contained in `tnum_OP(a, b)` for
`OP ∈ {add, sub, and, or, xor, mul, lshift, rshift}`. An escape would be a real,
reportable verifier bug (the verifier could conclude a register cannot hold a
value it actually can).

- 5,000,000 iterations (each a complete soundness proof for its tnum pair, up to
  6 unknown bits per operand): **0 violations**.
- Detector validated by construction: injecting a deliberately-unsound
  `tnum_or` (dropping one bit of uncertainty) is caught at the first iteration
  with a concrete witness `(x, y, OP(x,y), tnum_OP(a,b))`.

Coverage note: the exhaustive check is complete only within the small-tnum
regime (≤ 6 unknown bits per operand); it is a strong soundness check there but
not a proof for arbitrary tnums. Runs continuously in CI, so it re-checks every
kernel/LLVM bump.

### Native-vs-BPF differential — agree (no miscompilation found)

`diff/` compiles the same kernel function to BPF (verified + run in UML) and to
native host code, feeds both identical inputs, and diffs the outputs. A
divergence would be a BPF-backend miscompilation of real kernel code.

| Target | Function | Iterations | Result |
|---|---|---|---|
| `bitrev` | `bitrev32` | 100,000 | native and BPF agree |
| `div64` | `div64_u64` (64-bit division fallback, `-U__SIZEOF_INT128__`) | 100,000 | native and BPF agree |
| `xxhash` | `xxh64` (64-bit multiply-by-prime) | 100,000 | native and BPF agree |
| `crc16` | `crc16` (table lookup + shift/xor loop) | 100,000 | native and BPF agree |
| `crc_ccitt` | `crc_ccitt` (CRC-CCITT table) | 100,000 | native and BPF agree |
| `int_pow` | `int_pow` (64-bit multiply loop, bounded exp) | 100,000 | native and BPF agree |

Detector validated by construction: injecting a one-off perturbation on the BPF
side (`+1` on the result) is caught at every iteration with the exact
reproducing inputs. The BPF backend correctly compiles these targets, including
64-bit division and multiply — historical weak spots — matching native exactly.

Two attempted targets could not be differentially tested because the BPF
toolchain rejects them (real boundaries, consistent with the verifier
characterization study):

- `mul_u64_add_u64_div_u64` — the verifier rejects the `-U__SIZEOF_INT128__`
  128-bit long-division fallback: *"infinite loop detected at insn 222"* (277
  insns; termination is bit-count-based, not syntactic — same class as
  `rational_best_approximation`).
- `div64_s64` — the BPF backend refuses to compile it: *"unsupported signed
  division, please convert to unsigned div/mod"* (`math64.h`). Signed 64-bit
  division still isn't emitted here (clang 22.1.8).
- `aes_encrypt` (lib/crypto/aes.c) — exceeds the BPF 512-byte stack limit
  (*"BPF stack limit is exceeded"*): the expanded `struct aes_key` round keys
  plus the working state don't fit. A curation-scanner candidate the
  heuristics can't reject (struct sizes aren't visible statically); AES is
  BPF-stack-bound, not just complex.

## Confirmed findings

_None yet._
