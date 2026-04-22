# bpf-verify

A pipeline for compiling Linux kernel `lib/` source files to BPF bytecode and formally verifying them with the in-kernel BPF verifier via `veristat`.

## Overview

This project systematically compiles kernel library functions (CRC, MPI, string ops, compression, crypto, etc.) as BPF programs and runs them through the BPF verifier to characterize what the verifier can and cannot prove about real kernel code.

## Structure

| File | Description |
|------|-------------|
| `pipeline.py` | Main pipeline: compiles 86+ kernel lib targets to BPF `.o` files, then runs `veristat` |
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

Results are written to `output2/results.txt`.

To use a custom veristat binary instead of uml-veristat:
```bash
BPF_VERISTAT=/path/to/veristat BPF_VERISTAT_SUDO=1 python3 pipeline.py
```

## Current Status (as of Phase 4)

- **77 OK** / 18 FAIL out of 95 targets
- All 18 remaining failures are due to known BPF backend limitations (stack size, memcpy on stack buffers, global function pointers)

## Findings Summary

See [`BPF_Verification_Findings.md`](BPF_Verification_Findings.md) for detailed per-target analysis across all four phases.
