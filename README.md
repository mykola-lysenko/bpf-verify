# bpf-verify

A pipeline for compiling Linux kernel `lib/` source files to BPF bytecode and formally verifying them with the in-kernel BPF verifier via `veristat`, complemented by native-vs-BPF differential testing and host-side sanitizer fuzzing of the same kernel functions.

## Overview

This project systematically compiles kernel library functions (CRC, MPI, string ops, compression, crypto, verifier internals, etc.) as BPF programs and runs them through the BPF verifier to characterize what the verifier can and cannot prove about real kernel code. Around that core it adds three complementary bug-finding legs that run the *same* sources through independent oracles.

## Structure

| Path | Description |
|------|-------------|
| `pipeline.py` | Pipeline driver: compiles each target in `targets/ORDER` to a BPF `.o`, then runs `veristat`. Targets are grouped into three suites — `compat`, `coverage`, and `proof` — selectable with `--suite` |
| `targets/` | Per-target configuration: `targets/<name>/target.json` (source paths, suite, flags), `harness.c` (harness body), optional `pre_include.h`/`preamble.h`. `targets/harness_template.c` is the shared harness skeleton; `targets/_shared/` holds pre-include snippets used by several targets |
| `shims/` | Shadow kernel-header tree that stubs out infrastructure (atomics, spinlocks, printk, per-CPU, MM) the BPF backend cannot compile, plus per-target shim subtrees (`backtrack/`, `cpumask/`, `check_btf/`, …) for the deeper verifier-internal `proof` targets |
| `diff/` | Native-vs-BPF differential targets (compile a function both ways, diff the results — catches BPF-backend miscompilation); see `diff/README.md` |
| `userspace/` | Host-compiled ASan/UBSan property & differential fuzzing for code the verifier can't load; see `userspace/README.md` |
| `tools/curate.py` | Curation scanner: ranks kernel functions as candidate targets by leg and bug expected-value → `analysis/curation.md` |
| `scripts/` | CI gates: `check_results.py` (baseline comparison), `check_shim_drift.py` (shim vs kernel-source drift) |
| `BPF_Verification_Findings.md`, `FINDINGS_EXECUTION.md` | Verifier-characterization findings and execution/differential-leg findings |
| `test_compile.py` | Helper script for testing individual target compilation |

## Suites

| Suite | What it holds | Harness |
|-------|---------------|---------|
| `compat` | Kernel functions that compile and verify with the default (no-op) harness | `return 0;` |
| `coverage` | Functions exercised by a custom harness that calls into them (some with `BPF_ASSERT` property checks) | custom |
| `proof` | BPF verifier internals (`tnum`, `cnum`, liveness, states, backtrack, guard/invariant helpers) proven via `BPF_PROVE(...)` | `prove` |

## Requirements

- Linux kernel source tree (set `BPF_KSRC` or default `~/bpf-next-0aa637869`)
- LLVM/clang with BPF target support. The uml-veristat submodule builds a matching toolchain under `deps/bpf-uml-selftests/uml-veristat/.build/llvm-install/`; point `BPF_CLANG`/`BPF_LLVM_OBJCOPY` there (the CI workflow does this automatically)
- [uml-veristat](https://github.com/mykola-lysenko/bpf-uml-selftests) (included as a git submodule under `deps/`)

## Setup

```bash
git clone --recurse-submodules https://github.com/mykola-lysenko/bpf-verify.git
cd bpf-verify

# Or if already cloned:
git submodule update --init --recursive

# One-time setup (installs LLVM, fetches kernel source, builds uml-veristat):
./setup.sh
```

## Usage

```bash
python3 pipeline.py --compile-only            # compile only
python3 pipeline.py                           # compile + verify with uml-veristat
python3 pipeline.py --suite proof             # only the verifier-proof suite
python3 pipeline.py --suite compat,coverage   # a subset (repeatable/comma-separated)
python3 pipeline.py --list-targets            # list selected targets and exit
```

Results are written to `output2/results.txt` (human-readable) and
`output2/results.json` (per-target machine-readable stats). CI gates every
run against the committed per-target baseline:

```bash
python3 scripts/check_results.py output2/results.json      # compare against baseline/
python3 scripts/check_results.py output2/results.json --update-baseline
```

The differential and userspace legs run independently of veristat:

```bash
bash tools/diff.sh              # native-vs-BPF differential targets (diff/)
bash userspace/run.sh           # ASan/UBSan property fuzzing (userspace/)
```

To use a custom veristat binary instead of uml-veristat:
```bash
BPF_VERISTAT=/path/to/veristat BPF_VERISTAT_SUDO=1 python3 pipeline.py
```

## Current Status

- **212 targets** in `targets/ORDER` compile and pass the BPF verifier on the
  pinned toolchain, 0 FAIL: `compat` (55), `coverage` (117), `proof` (40).
  This is upstream's 214-target suite minus `cnum`/`cnum_prove`, which are
  parked (dirs kept, out of `ORDER`) as a documented aggregate-return BPF
  boundary — see [`FINDINGS_EXECUTION.md`](FINDINGS_EXECUTION.md). The
  authoritative per-target numbers are `baseline/results.json` and the latest
  CI run's `veristat-results` artifact.
- The differential (`diff/`) and userspace (`userspace/`) legs run the same
  kernel sources through native-execution and sanitizer oracles; findings are
  recorded in [`FINDINGS_EXECUTION.md`](FINDINGS_EXECUTION.md).

## Findings Summary

See [`BPF_Verification_Findings.md`](BPF_Verification_Findings.md) for detailed
per-target analysis across all phases, and
[`FINDINGS_EXECUTION.md`](FINDINGS_EXECUTION.md) for the execution/differential
and sanitizer legs.
