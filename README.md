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

- Linux kernel source tree at `/home/ubuntu/linux-6.1.102` (or update `KSRC` in `pipeline.py`)
- LLVM/clang with BPF target support at `/home/ubuntu/llvm-project/build/bin/clang`
- `veristat` binary at `./veristat`
- BPF header shims at `/tmp/bpf-asm-shim2/`

## Usage

```bash
python3 pipeline.py
```

Results are written to `output2/results.txt`.

## Current Status (as of Phase 4)

- **77 OK** / 18 FAIL out of 95 targets
- All 18 remaining failures are due to known BPF backend limitations (stack size, memcpy on stack buffers, global function pointers)

## Findings Summary

See [`BPF_Verification_Findings.md`](BPF_Verification_Findings.md) for detailed per-target analysis across all four phases.
