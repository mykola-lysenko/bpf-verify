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

## Confirmed findings

_None yet._
