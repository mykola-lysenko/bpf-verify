# BPF Verify Pipeline Progress

**Current status:** 212 targets in `targets/ORDER` compile on the pinned
toolchain (upstream's 214-target suite minus the two `cnum` toolchain-boundary
targets), grouped as compat 55 / coverage 118 / proof 41. Verdict parity is
confirmed by the uml-veristat run and recorded in `baseline/results.json`.

## Merge + port (upstream suites → targets/ layout)

- Merged the upstream "big push" (proof + coverage suites, per-target shim
  subtrees) into this branch's differential/userspace/execution/curation work.
  The upstream monolithic `pipeline.py` was projected into this branch's
  `targets/<name>/` layout via `tools/extract_origin_targets.py`; suites match
  upstream exactly (55/118/41). The differential (`diff/`), userspace
  (`userspace/`), execution, and curation legs are unchanged and orthogonal.
- Two pinned-toolchain adaptations (clang 22.1.8, bpf-next `abef15c5`), see
  `FINDINGS_EXECUTION.md`: `zlib_inflate` needs `always_inline` on its 6-arg
  helper; `cnum`/`cnum_prove` are parked (aggregate-return BPF boundary).

## Recent baseline (pre-merge, monolithic pipeline)

- Full local pipeline after adding the best-next utility batch (`dp_utils.c`, `open_alliance_helpers.c`, `ghes_helpers.c`, `cudbg_common.c`, `vidtv_common.c`, `net/ceph` hash helpers, `fs/proc/util.c`, `fs/ntfs3/bitfunc.c`, and `kernel/range.c`): 156 compiled, 156 verified, 0 skipped.
- Previous full local pipeline after tightening legacy constant-folded harnesses (`bcd`, `gcd`, CRC16 variants, `sort`, `seq_buf`, `timeconv`, and `refcount`): 146 compiled, 146 verified, 0 skipped.
- Full local pipeline after adding selected `drivers/` utility targets (`cxd2880_common.c`, `i915_mmio_range.c`, `dc_spl_filters.c`, and `mcp251xfd-crc16.c`): 146 compiled, 146 verified, 0 skipped.
- Full local pipeline after adding top-level `crypto/tea.c`, `crypto/arc4.c`, and `crypto/sm4_generic.c`: 142 compiled, 142 verified, 0 skipped.
- Previous full local pipeline after adding `kernel/time/timeconv.c` and `kernel/time/timecounter.c`: 139 compiled, 139 verified, 0 skipped.
- Previous full local pipeline after adding `kernel/bpf/mprog.c` and `kernel/bpf/tcx.c`: 137 compiled, 137 verified, 0 skipped.
- Previous full local pipeline after adding the small `kernel/bpf/` support batch (`bpf_lsm_proto.c`, `sysfs_btf.c`, `bpf_cgrp_storage.c`, `bpf_task_storage.c`, and `bpf_inode_storage.c`): 135 compiled, 135 verified, 0 skipped.
- Previous full local pipeline after adding the remaining iterator targets (`cgroup_iter.c`, `kmem_cache_iter.c`, `task_iter.c`, `bpf_iter.c`, and `btf_iter.c`): 130 compiled, 130 verified, 0 skipped.
- Previous full local pipeline after adding `kernel/bpf/prog_iter.c`, `kernel/bpf/link_iter.c`, `kernel/bpf/map_iter.c`, and `kernel/bpf/dmabuf_iter.c`: 125 compiled, 125 verified, 0 skipped.
- Previous full local pipeline after adding `kernel/bpf/reuseport_array.c`: 121 compiled, 121 verified, 0 skipped.
- CI guardrails now fail on compile failures, verifier failures, skipped objects, and object-open failures.

## Target plan

1. Park additional `kernel/bpf/` files for now; return later.
2. Continue the narrow `drivers/` pass only for pure helpers, parsers, CRC/table logic, and range/descriptor utilities.
3. Save additional `lib/` files as a second step; broad driver coverage is too dependent on MMIO, IRQ, DMA, firmware, and bus scaffolding.

## Notes for `cmdline.c`

- `cmdline.c` needs local bounded replacements for `simple_strtoull`, `simple_strtol`, `strlen`, `strncmp`, and `skip_spaces` to avoid pulling in large dependencies such as `lib/vsprintf.c` and `lib/string_helpers.c`.
- The cmdline helpers should be forced inline for BPF verification because `get_option()`/`get_options()` update `char **` cursors, and the verifier rejects pointer writes into caller stack frames across subprogram calls.

## Notes for legacy harness coverage cleanup

- Reworked legacy harnesses for `bcd`, `gcd`, `crc16`, `crc-ccitt`, `crc-itu-t`, `sort`, `seq_buf`, `timeconv`, and `refcount` so they no longer collapse to constant-only two-instruction verifier programs.
- The BCD, CRC, `seq_buf`, `timeconv`, and `refcount` harnesses now use map-seeded inputs so target logic remains live in the BPF program.
- The CRC variants, `sort`, and `seq_buf` use focused `noinline` source shims where clang would otherwise inline and constant-fold the target code back into the harness.
- `gcd` intentionally covers the zero-operand fast path only; the full binary-GCD loop remains verifier-incompatible because its termination is mathematical rather than syntactically bounded.
- `sort` intentionally covers the direct swap helpers only; the full `sort()`/`sort_r()` callback path still depends on indirect comparator/swap calls, which are not valid BPF verifier input.
- `seq_buf_putmem_hex()` remains out of this cleanup pass because the verifier loses stack bounds through its internal formatting loop when it is kept as a separate subprogram; `seq_buf_putmem()` and `seq_buf_putc()` are covered.

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

## Notes for `kernel/bpf/*_iter.c`

- Added real-source targets for `prog_iter.c`, `link_iter.c`, `map_iter.c`, and `dmabuf_iter.c` with shared iterator, seq_file, BPF registration, map attach, kfunc, and dma-buf traversal stubs.
- Added real-source targets for the remaining iterator files: `cgroup_iter.c`, `kmem_cache_iter.c`, `task_iter.c`, `bpf_iter.c`, and `btf_iter.c`.
- The harnesses use map-provided runtime seeds plus volatile stub counters so iterator start/next/show/stop and attach paths are not constant-folded away.
- Covered BPF program/link/map sequence iteration, stop-path behavior, iterator registration, map iterator attach validation/fdinfo/link-info, `bpf_map_sum_elem_count()`, dma-buf seq resume/fini behavior, and dma-buf kfunc iterator transitions.
- The second iterator batch covers cgroup attach validation and seq traversal, slab cache kfunc/list traversal, task/task_file sequence paths, the core numeric iterator, and BTF field iteration.
- `bpf_iter.c` intentionally verifies the built-in numeric iterator path only; the file/link read path remains compiled but is not invoked because it is driven by indirect seq_file callbacks that are not valid verifier input.
- `task_iter.c` intentionally skips VMA sequence traversal in the harness; task attach, task/task_file seq paths, registration, and open-coded task iterator kfuncs are covered.

## Notes for small `kernel/bpf/` support files

- Added real-source targets for `bpf_lsm_proto.c`, `sysfs_btf.c`, `bpf_cgrp_storage.c`, `bpf_task_storage.c`, and `bpf_inode_storage.c`.
- `bpf_lsm_proto.c` covers the nullable `mmap_file` BPF LSM hook definition.
- `sysfs_btf.c` covers BTF sysfs mmap accept/reject paths; `btf_vmlinux_init()` remains compiled but is not invoked because the real init path depends on linker-provided BTF section symbols.
- The storage harnesses cover fd/pidfd/cgroup lookup, update, delete, helper get/delete, map allocation/free wrapper paths, and object free teardown using focused local-storage stubs rather than the full `bpf_local_storage.c` implementation.

## Notes for `kernel/bpf/mprog.c` and `kernel/bpf/tcx.c`

- Added real-source targets for `mprog.c` and `tcx.c` using shared BPF program/link metadata and TCX netdevice stubs.
- `mprog.c` covers attach, replace, relative insert, detach, query, revision mismatch, duplicate attach, and prog/link release accounting.
- `tcx.c` covers netdevice attach/query/detach, missing-device attach rejection, link attach/detach, and uninstall cleanup.
- `tcx.c` intentionally uses focused inlined mprog stubs because the real mprog implementation is verified separately; reloading stored kernel pointers from `.bss` causes the BPF verifier to treat them as scalars before TCX dereferences them.

## Notes for `kernel/time/`

- Added real-source targets for `timeconv.c` and `timecounter.c`.
- `timeconv.c` uses verifier-enforced compile-time proofs for representative UTC conversions: Unix epoch, 2000-02-29, 2038 boundary, and pre-epoch `-1`.
- `timecounter.c` covers init, wraparound cycle delta conversion, forward/backward `timecounter_cyc2time()`, `timecounter_adjtime()`, and a small dynamic map-seeded read path.
- `timekeeping_debug.c` was tested and left out of this batch because even with debugfs/per-CPU shims it pulls scheduler/PID internals through the include chain; that is not a good small `kernel/time/` target.

## Notes for top-level `crypto/`

- Added real-source targets for `crypto/tea.c`, `crypto/arc4.c`, and `crypto/sm4_generic.c`.
- `crypto/tea.c` covers TEA, XTEA, and XETA setkey/encrypt/decrypt round-trips with map-seeded input.
- `crypto/sm4_generic.c` covers SM4 setkey/encrypt/decrypt through the top-level Crypto API wrapper, with `crypto/sm4.c` included in the same translation unit and a local `rol32` shim.
- `crypto/arc4.c` covers lskcipher init/setkey and the continuation wrapper's zero-length crypt path. The non-zero ARC4 data path remains verifier-limited because `arc4_ctx` is too large for stack placement, and when placed in global data the verifier reloads `ctx->x`/`ctx->y` as unbounded scalars before indexing `S[]`.

## Notes for selected `drivers/` utility files

- Added real-source targets for `drivers/media/dvb-frontends/cxd2880/cxd2880_common.c`, `drivers/gpu/drm/i915/i915_mmio_range.c`, `drivers/gpu/drm/amd/display/dc/sspl/dc_spl_filters.c`, and `drivers/net/can/spi/mcp251xfd/mcp251xfd-crc16.c`.
- `cxd2880_common.c` covers two's-complement sign-extension edge cases plus a map-seeded dynamic value/bit-length path; `linux/delay.h` is blocked because it is unused by this helper and pulls scheduler internals.
- `i915_mmio_range.c` covers sentinel-terminated range table hits, misses, single-register ranges, and a dynamic lookup.
- `dc_spl_filters.c` covers bounded S1.10 to S1.12 coefficient conversion; the AMD display type header is shimmed because the function only needs `NUM_PHASES_COEFF`, `SPL_NAMESPACE`, and `uint16_t`.
- `mcp251xfd-crc16.c` covers empty CRC seed behavior and split-buffer vs single-buffer CRC equivalence; the private driver header is blocked to avoid full CAN/SPI/regmap dependencies.

## Notes for best-next utility batch

- Added real-source targets for `drivers/gpu/drm/msm/dp/dp_utils.c`, `drivers/net/phy/open_alliance_helpers.c`, `drivers/acpi/apei/ghes_helpers.c`, `drivers/net/ethernet/chelsio/cxgb4/cudbg_common.c`, `drivers/media/test-drivers/vidtv/vidtv_common.c`, `net/ceph/crush/hash.c`, `net/ceph/ceph_hash.c`, `fs/ntfs3/bitfunc.c`, and `kernel/range.c`.
- Added a focused shim for `fs/proc/util.c` because the real file's local `internal.h` has no include guard and pulls broad procfs/MM/scheduler state; the shim keeps the real `name_to_int()` logic.
- The new harnesses cover DisplayPort parity/header packing, OPEN Alliance TDR decoding, CXL CPER validation/setup, Chelsio debug-buffer accounting, vidtv bounded memory wrappers, Ceph hash helpers, proc decimal-name parsing, NTFS3 first-byte bit-range checks, and range add/merge/subtract.
- `ghes_helpers.c` keeps the CPER record on stack so the verifier can track `dvsec_len`, while large work-data output lives in a BPF array map to stay under the stack limit.
