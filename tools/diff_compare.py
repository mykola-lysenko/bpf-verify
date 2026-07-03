#!/usr/bin/env python3
"""Compare native and BPF differential output files, byte-for-byte per u64.

Reports the first divergences with the exact seed inputs that produced them
(recomputed from the shared diff_seed.h generator, kept in sync here).

Usage: diff_compare.py <native.bin> <bpf.bin> --base S [--max-report K]
"""
import argparse
import struct
import sys

# Mirror of tools/diff_seed.h -- MUST stay in sync.
NINPUTS = 4
CORNERS = [
    0, 1, 2, 3, (1 << 64) - 1, (1 << 64) - 2,
    0x8000000000000000, 0x7fffffffffffffff,
    0xffffffff, 0x100000000, 0x80000000, 0x7fffffff,
    0xff, 0x100, 0xffff, 0x10000,
]
MASK = (1 << 64) - 1


def mix(z):
    z &= MASK
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & MASK
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & MASK
    return (z ^ (z >> 31)) & MASK


def gen_inputs(base, it):
    out = [0] * NINPUTS
    nc = len(CORNERS)
    if it < nc * nc:
        out[0] = CORNERS[it % nc]
        out[1] = CORNERS[(it // nc) % nc]
        for k in range(2, NINPUTS):
            out[k] = mix((base + 0x9e3779b97f4a7c15 * (it * NINPUTS + k + 1)) & MASK)
    else:
        for k in range(NINPUTS):
            out[k] = mix((base + 0x9e3779b97f4a7c15 * (it * NINPUTS + k + 1)) & MASK)
    return out


def load(path):
    with open(path, "rb") as f:
        data = f.read()
    n = len(data) // 8
    return list(struct.unpack(f"<{n}Q", data[: n * 8]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("native")
    ap.add_argument("bpf")
    ap.add_argument("--base", type=lambda s: int(s, 0), default=0x1234567)
    ap.add_argument("--max-report", type=int, default=10)
    args = ap.parse_args()

    nat = load(args.native)
    bpf = load(args.bpf)
    n = min(len(nat), len(bpf))
    if len(nat) != len(bpf):
        print(f"::warning::length mismatch native={len(nat)} bpf={len(bpf)}; "
              f"comparing first {n}")

    mismatches = 0
    for i in range(n):
        if nat[i] != bpf[i]:
            if mismatches < args.max_report:
                ins = gen_inputs(args.base, i)
                print(f"DIVERGE iter={i} inputs={[hex(x) for x in ins]} "
                      f"native=0x{nat[i]:x} bpf=0x{bpf[i]:x}")
            mismatches += 1

    if mismatches:
        print(f"\n{mismatches}/{n} iterations diverge -- BPF backend "
              f"miscompilation or verifier-accepted incorrect result")
        return 1
    print(f"{n} iterations: native and BPF agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
