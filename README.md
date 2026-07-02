# bpf-verify

A pipeline for compiling Linux kernel `lib/` source files to BPF bytecode and formally verifying them with the in-kernel BPF verifier via `veristat`.

## Overview

This project systematically compiles kernel library functions (CRC, MPI, string ops, compression, crypto, etc.) as BPF programs and runs them through the BPF verifier to characterize what the verifier can and cannot prove about real kernel code.

## Structure

| File | Description |
|------|-------------|
| `pipeline.py` | Pipeline driver: compiles each target listed in `targets/ORDER` to a BPF `.o` file, then runs `veristat` |
| `targets/` | Per-target configuration: `targets/<name>/target.json` (source paths, flags), `harness.c` (harness body), optional `pre_include.h`/`preamble.h`. `targets/harness_template.c` is the shared harness skeleton; `targets/_shared/` holds pre-include snippets used by several targets |
| `shims/` | Shadow kernel-header tree that stubs out infrastructure (atomics, spinlocks, printk, per-CPU, MM) the BPF backend cannot compile |
| `BPF_Verification_Findings.md` | Detailed findings from each phase of the verification campaign |
| `test_compile.py` | Helper script for testing individual target compilation |

## Requirements

- Linux kernel source tree (set `BPF_KSRC` or default `~/bpf-next-0aa637869`)
- LLVM/clang 23+ with BPF target support (`BPF_CLANG`, default `/usr/bin/clang-23`)
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
python3 pipeline.py --compile-only   # compile only
python3 pipeline.py                  # compile + verify with uml-veristat
```

Results are written to `output2/results.txt` (human-readable) and
`output2/results.json` (per-target machine-readable stats). CI gates every
run against the committed per-target baseline:

```bash
python3 scripts/check_results.py output2/results.json      # compare against baseline/
python3 scripts/check_results.py output2/results.json --update-baseline
```

To use a custom veristat binary instead of uml-veristat:
```bash
BPF_VERISTAT=/path/to/veristat BPF_VERISTAT_SUDO=1 python3 pipeline.py
```

## Current Status

The current baseline is **156 targets compiled and verified, 0 skipped**
(see [`PROGRESS.md`](PROGRESS.md) for the running log). The authoritative
per-target numbers are `baseline/results.json` and the latest CI run's
`veristat-results` artifact; targets that could not be made
verifier-compatible are documented in the findings and kept as disabled
directories under `targets/` (not listed in `targets/ORDER`).

## Findings Summary

See [`BPF_Verification_Findings.md`](BPF_Verification_Findings.md) for detailed per-target analysis across all phases.
