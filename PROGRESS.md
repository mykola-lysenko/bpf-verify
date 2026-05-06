# BPF Verify Pipeline Progress

**Current status:** 111 compiled, 111 verified, 0 skipped.

## Recent baseline

- Full local pipeline after `cmdline.c`: 111 compiled, 111 verified, 0 skipped.
- CI guardrails now fail on compile failures, verifier failures, skipped objects, and object-open failures.

## Target plan

1. Return to `lib/crypto/` coverage next.
2. Add `kernel/bpf/range_tree.c` after the crypto pass.

## Notes for `cmdline.c`

- `cmdline.c` needs local bounded replacements for `simple_strtoull`, `simple_strtol`, `strlen`, `strncmp`, and `skip_spaces` to avoid pulling in large dependencies such as `lib/vsprintf.c` and `lib/string_helpers.c`.
- The cmdline helpers should be forced inline for BPF verification because `get_option()`/`get_options()` update `char **` cursors, and the verifier rejects pointer writes into caller stack frames across subprogram calls.
