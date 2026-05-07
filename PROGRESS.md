# BPF Verify Pipeline Progress

**Current status:** 121 compiled, 121 verified, 0 skipped.

## Recent baseline

- Full local pipeline after adding `kernel/bpf/reuseport_array.c`: 121 compiled, 121 verified, 0 skipped.
- CI guardrails now fail on compile failures, verifier failures, skipped objects, and object-open failures.

## Target plan

1. Continue with `kernel/bpf/` files first.
2. Save deferred `lib/` and `lib/crypto/` files as the second step.

## Notes for `cmdline.c`

- `cmdline.c` needs local bounded replacements for `simple_strtoull`, `simple_strtol`, `strlen`, `strncmp`, and `skip_spaces` to avoid pulling in large dependencies such as `lib/vsprintf.c` and `lib/string_helpers.c`.
- The cmdline helpers should be forced inline for BPF verification because `get_option()`/`get_options()` update `char **` cursors, and the verifier rejects pointer writes into caller stack frames across subprogram calls.

## Notes for `lib/crypto/`

- Added active verifier targets for `lib/crypto/sha1.c`, `lib/crypto/gf128hash.c`, and `lib/crypto/gf128mul.c`.
- Deferred `md5.c` and `des.c` because clang times out compiling those full translation units in this harness.
- Deferred `blake2b.c` because the generic compression frame exceeds the BPF stack limit.
- Deferred `sha3.c` because it needs separate include-shim work around `__ffs`/`utils.c`.

## Notes for `kernel/bpf/range_tree.c`

- Added the real `kernel/bpf/range_tree.c` target with `lib/rbtree.c` included under internal linkage to avoid unsupported indirect callback opcodes.
- The harness verifies empty-tree lookup, range size calculation, best-fit `range_tree_find()`, and first-range `range_tree_set()` insertion.
- Full set/find/clear round-trips remain verifier-limited because rb-tree pointers stored in `.bss` allocator nodes are reloaded as scalars.

## Notes for `kernel/bpf/percpu_freelist.c`

- Added the real `kernel/bpf/percpu_freelist.c` target with one-CPU percpu and rqspinlock stubs.
- The harness verifies init success/failure, LIFO push/pop behavior, empty-pop behavior, and bounded `pcpu_freelist_populate()`.

## Notes for `kernel/bpf/queue_stack_maps.c`

- Added the real `kernel/bpf/queue_stack_maps.c` target with focused BPF map metadata, BTF ID, rqspinlock, and map-area allocation stubs.
- The harness verifies FIFO queue push/peek/pop, empty-pop zeroing, stack peek/pop, full-map replacement with `BPF_EXIST`, validation failures, and allocator success/free.

## Notes for `kernel/bpf/bpf_insn_array.c`

- Added the real `kernel/bpf/bpf_insn_array.c` target with focused BPF map, program, BTF, atomic, and allocation stubs.
- The harness verifies allocation checks, lookup/update/delete, BTF checks, direct value address calculation, frozen-map init/release, offset adjustment/removal, ready checks, and JIT instruction pointer updates.

## Notes for `kernel/bpf/map_in_map.c`

- Added the real `kernel/bpf/map_in_map.c` target with focused BPF map, BTF record, array-map, and allocation stubs.
- The harness verifies metadata allocation/copying, array-specific metadata preservation, metadata equality, nested-map rejection, unsupported-map rejection, bad-fd handling, deferred-free flags, put accounting, and sys-lookup id return.
- `bpf_map_fd_get_ptr()` remains intentionally out of scope because the real path invokes `ops->map_meta_equal` through an indirect function pointer, which is not valid BPF verifier input.

## Notes for `kernel/bpf/dispatcher.c`

- Added the real `kernel/bpf/dispatcher.c` target with bounded dispatcher slots and modeled refcount, mutex, JIT image allocation, and text-copy surfaces.
- The harness verifies add/remove refcount transitions, duplicate registration handling, full-dispatcher rejection, arch fallback from `bpf_dispatcher_prepare()`, and allocation/list transitions through `bpf_dispatcher_change_prog()`.
- The dispatcher helpers are forced inline for this harness because BPF subprograms cannot store pointers into the caller's stack frame.

## Notes for `kernel/bpf/reuseport_array.c`

- Added the real `kernel/bpf/reuseport_array.c` target with focused BPF map, socket, reuseport, RCU, lock, fd, and map-area stubs.
- The harness verifies allocation checks/allocation, memory accounting, lookup, fd cookie lookup, update validation, update early error paths, delete, next-key, detach cleanup, and free cleanup.
- Dynamic keys are used only on non-dereferencing paths; BPF loses pointer type information when a socket pointer is loaded from a variable-index stack slot and then dereferenced.
- Keep BPF-core targets first; likely follow-ups are smaller map infrastructure files before returning to deferred `lib/` work.
