# BPF Verify Pipeline Progress

**Current status:** 114 compiled, 114 verified, 0 skipped.

## Recent baseline

- Full local pipeline after the `lib/crypto/` pass: 114 compiled, 114 verified, 0 skipped.
- CI guardrails now fail on compile failures, verifier failures, skipped objects, and object-open failures.

## Target plan

1. Add `kernel/bpf/range_tree.c`.
2. Return to harder `lib/crypto/` files separately if needed.

## Notes for `cmdline.c`

- `cmdline.c` needs local bounded replacements for `simple_strtoull`, `simple_strtol`, `strlen`, `strncmp`, and `skip_spaces` to avoid pulling in large dependencies such as `lib/vsprintf.c` and `lib/string_helpers.c`.
- The cmdline helpers should be forced inline for BPF verification because `get_option()`/`get_options()` update `char **` cursors, and the verifier rejects pointer writes into caller stack frames across subprogram calls.

## Notes for `lib/crypto/`

- Added active verifier targets for `lib/crypto/sha1.c`, `lib/crypto/gf128hash.c`, and `lib/crypto/gf128mul.c`.
- Deferred `md5.c` and `des.c` because clang times out compiling those full translation units in this harness.
- Deferred `blake2b.c` because the generic compression frame exceeds the BPF stack limit.
- Deferred `sha3.c` because it needs separate include-shim work around `__ffs`/`utils.c`.
