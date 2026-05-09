# BPF Verify Opportunities

Current baseline: 156 compiled, 156 verified, 0 skipped.

This is the working backlog for finding the next Linux kernel source files that
are worth turning into BPF verifier harnesses. It intentionally favors files
with real logic, bounded control flow, small state, and limited dependency
surface. It deprioritizes driver registration, probe/remove paths, IRQ/DMA/MMIO
plumbing, callback-heavy APIs, and code that would only become another
compile-only target.

## Selection Rules

- Prefer pure helpers, parsers, checksums, hashes, table lookups, range logic,
  bit manipulation, and bounded transforms.
- Seed harnesses from `input_map` so clang cannot fold target code into a
  constant return.
- Keep target source live with focused `noinline` shims when useful, but avoid
  making the verifier chase large kernel subsystems.
- Treat callback tables, indirect function calls, unbounded mathematical loops,
  variadic functions, and large stack state as blockers unless there is a clear
  smaller subpath to verify.
- For broad subsystems, verify the algorithmic helpers first and skip the
  registration/sysfs/debugfs/probe surfaces.

## Completed Best Batch

These candidates are now implemented and verified in the 156-target baseline.
Keep the details here as a record of why they were selected and what the
harnesses should continue to cover.

1. `drivers/gpu/drm/msm/dp/dp_utils.c`
   - Covers DisplayPort parity generation and SDP header packing.
   - Expected harness: map-seeded `u32`, call `msm_dp_utils_get_g0_value()`,
     `msm_dp_utils_get_g1_value()`, `msm_dp_utils_calculate_parity()`, and
     `msm_dp_utils_pack_sdp_header()`.
   - Risk: likely only small `FIELD_PREP` and struct shims.

2. `drivers/net/phy/open_alliance_helpers.c`
   - Covers OPEN Alliance TDR status and distance decoding.
   - Expected harness: feed a map-seeded register value and exercise all status
     cases plus the resolution-not-possible distance path.
   - Risk: header shim for ethtool result constants and field masks.

3. `drivers/acpi/apei/ghes_helpers.c`
   - Covers CXL CPER protocol-error validation and work-data setup.
   - Expected harness: build small protocol error records on stack, validate
     missing/valid fields, and prove severity/data copy paths.
   - Risk: CXL/AER type shims and logging stubs.

4. `drivers/net/ethernet/chelsio/cxgb4/cudbg_common.c`
   - Covers debug-buffer bounds, compression-buffer selection, clear, and
     output offset accounting.
   - Expected harness: stack `cudbg_init` and `cudbg_buffer` objects, then test
     success, no-space, compressed, and uncompressed paths.
   - Risk: private header shims, but target logic is small.

5. `drivers/media/test-drivers/vidtv/vidtv_common.c`
   - Covers bounded memcpy/memset wrappers that guard output-buffer limits.
   - Expected harness: stack buffers with safe and overflow offsets.
   - Risk: `memcpy`/`memset` lowering and ratelimited logging stubs.

6. `net/ceph/crush/hash.c`
   - Pure Jenkins hash helpers for one to five `u32` inputs.
   - Expected harness: call all exported `crush_hash32*()` variants with
     map-seeded values and invalid hash type cases.
   - Risk: very low; mostly constants and switch paths.

7. `net/ceph/ceph_hash.c`
   - Pure string hash variants with bounded byte loops.
   - Expected harness: map-seeded 16-byte string, call Linux and Jenkins modes,
     plus invalid type/name paths.
   - Risk: bounded loop size must stay small.

8. `fs/proc/util.c`
   - Tiny decimal parser in `name_to_int()`.
   - Expected harness: prove valid, leading-zero, nondigit, and overflow-ish
     paths using stack `qstr` values.
   - Risk: very low.

9. `fs/ntfs3/bitfunc.c`
   - Pure bit-range checks: `are_bits_clear()` and `are_bits_set()`.
   - Expected harness: stack bitmap with map-seeded offset/length in a small
     range.
   - Risk: pointer-to-integer alignment check may need either bounded aligned
     stack placement or a local shim.

10. `kernel/range.c`
    - Range add, merge, subtract, and sort helpers.
    - Expected harness: cover `add_range()`, `add_range_with_merge()`, and
      `subtract_range()` first.
    - Risk: `clean_sort_range()` and `sort_range()` call `sort()` with a
      comparator callback, so those paths should stay out initially.

## Next Candidate Batch

These are the strongest follow-ups after the completed 156-target baseline.
They keep the same strategy: pure logic first, bounded state, and no broad
registration/probe plumbing.

1. `fs/isofs/util.c`
   - ISO9660 date conversion; should pair well with existing `kernel/time/`
     coverage and mostly needs time helper exposure.

2. `fs/f2fs/hash.c`
   - Filename TEA hash with useful edge cases; keep casefold/encryption paths
     stubbed or out of scope initially.

3. `net/ipv6/ip6_checksum.c`
   - Target `csum_ipv6_magic()` only; skip skb-heavy checksum setters.

4. `net/netfilter/nft_range.c`
   - Target `nft_range_eval()` with small register/value shims; skip netlink
     init/dump paths.

5. `net/batman-adv/bitarray.c`
   - Sequence-window bitmap update logic with compact state and likely good
     bug-finding value.

6. `block/t10-pi.c`
   - Protection-information tuple verification/set helpers; target tuple logic
     before full bio iteration.

7. `block/blk-ia-ranges.c`
   - Independent-access range validation/changing logic; skip sysfs paths.

8. `crypto/crc32.c`
   - Compact shash wrapper over `crc32_le`; useful top-level Crypto API
     wrapper coverage.

9. `crypto/crc32c.c`
   - Same wrapper shape as CRC32 with a different primitive.

10. `drivers/gpu/drm/amd/display/dc/core/dc_vm_helper.c`
    - VMID usage helpers; skip HWSS function-pointer setup paths initially.

## Drivers Backlog

High-confidence or medium-risk driver utility files:

- `drivers/gpu/drm/msm/dp/dp_utils.c`: pure parity/header packing.
- `drivers/net/phy/open_alliance_helpers.c`: pure register-field decoding.
- `drivers/acpi/apei/ghes_helpers.c`: CXL CPER validation/copy helpers.
- `drivers/net/ethernet/chelsio/cxgb4/cudbg_common.c`: buffer accounting.
- `drivers/media/test-drivers/vidtv/vidtv_common.c`: bounded memory wrappers.
- `drivers/gpu/drm/amd/display/dc/core/dc_vm_helper.c`: VMID usage helpers;
  skip HWSS function-pointer setup paths initially.
- `drivers/net/ethernet/altera/altera_utils.c`: MMIO bit set/clear/test;
  requires local `csrrd32()`/`csrwr32()` register-array stubs.
- `drivers/pci/controller/dwc/pcie-qcom-common.c`: PCIe DBI bitfield
  programming; requires DBI read/write stubs and a bounded link-speed model.
- `drivers/net/wireless/mediatek/mt7601u/util.c`: skb header-pad helpers;
  requires a small `sk_buff` and `skb_push`/`skb_pull`/`skb_cow` model.
- `drivers/gpu/drm/i915/i915_timer_util.c`: timer active/cancel/set helpers;
  requires timer/jiffies stubs, less bug-finding value than pure parsers.

Driver files to avoid for now:

- `drivers/media/pci/tw5864/tw5864-util.c`: large retry loops around MMIO
  state; likely poor verifier value.
- `drivers/interconnect/qcom/icc-common.c`: allocation and OF xlate plumbing.
- `drivers/nfc/s3fwrn5/phy_common.c`: mutex, GPIO, and sleep sequencing.
- Broad driver `probe()`, bus, IRQ, DMA, firmware, and regmap files unless a
  small helper can be isolated.

## Top-Level `crypto/` Backlog

Best hash/wrapper candidates:

- `crypto/crc32.c`: shash wrapper over `crc32_le`; likely straightforward.
- `crypto/crc32c.c`: same shape as CRC32 with different primitive.
- `crypto/xxhash_generic.c`: wrapper around existing `lib/xxhash.c` logic.
- `crypto/sm3.c`: shash wrapper over `lib/crypto/sm3.c`.
- `crypto/sha3.c`: shash wrapper over `lib/crypto/sha3.c`; also revisits the
  previously parked SHA3 include-shim work.
- `crypto/sha1.c`, `crypto/sha256.c`, `crypto/sha512.c`: shash wrappers around
  library primitives.
- `crypto/md4.c`, `crypto/md5.c`, `crypto/rmd160.c`: hash wrappers with
  export/import paths; MD5 also has HMAC-MD5 state handling.

Cipher candidates after hash wrappers:

- `crypto/aes.c`: compact wrapper around AES library implementation.
- `crypto/blowfish_generic.c`: encrypt/decrypt plus shared common key schedule.
- `crypto/des_generic.c`: compact but may need DES table/header shims.
- `crypto/twofish_generic.c`, `crypto/cast5_generic.c`,
  `crypto/cast6_generic.c`, `crypto/seed.c`, `crypto/serpent_generic.c`,
  `crypto/aria_generic.c`, and `crypto/camellia_generic.c`: useful but larger
  key schedule/table state.

Crypto modes and framework-heavy files to save for later:

- `crypto/ecb.c`, `crypto/cbc.c`, `crypto/pcbc.c`, `crypto/ctr.c`,
  `crypto/xctr.c`, `crypto/cmac.c`, `crypto/xcbc.c`, and `crypto/hmac.c`.
- `crypto/lskcipher.c`, `crypto/skcipher.c`, `crypto/shash.c`,
  `crypto/ahash.c`, `crypto/aead.c`, `crypto/api.c`, and `crypto/algapi.c`.
- Public-key/ECC files such as `crypto/ecc.c`, `crypto/ecdsa.c`,
  `crypto/rsa.c`, and `crypto/dh.c` unless we isolate a small arithmetic helper.

## `net/` Backlog

Good algorithmic candidates:

- `net/ceph/crush/hash.c`: pure Jenkins hash.
- `net/ceph/ceph_hash.c`: bounded string hashing.
- `net/ipv6/ip6_checksum.c`: target `csum_ipv6_magic()` only; skip
  `udp6_set_csum()` because it is skb-state heavy.
- `net/netfilter/nft_range.c`: target `nft_range_eval()` only; skip netlink
  init/dump paths.
- `net/batman-adv/bitarray.c`: sequence-window bitmap update logic with debug
  stubs.
- `net/netfilter/ipset/pfxlen.c`: prefix-length lookup tables.
- `net/9p/trans_common.c`, `net/rxrpc/utils.c`, and `net/caif/cfutill.c`:
  small utility files worth scouting.

Medium-risk network candidates:

- `net/bluetooth/ecdh_helper.c`: useful crypto helper, but depends on ECC
  surfaces.
- `net/core/ieee8021q_helpers.c`: helper logic but likely pulls netdevice/VLAN
  types.
- `net/netfilter/utils.c`, `net/netfilter/nf_nat_ovs.c`,
  `net/netfilter/nft_ct_fast.c`: useful if small packet/tuple structs can be
  shimmed.

## `fs/` Backlog

Good candidates:

- `fs/proc/util.c`: `name_to_int()` parser.
- `fs/isofs/util.c`: ISO9660 date conversion via `mktime64()`.
- `fs/ntfs3/bitfunc.c`: bit clear/set range checks.
- `fs/f2fs/hash.c`: TEA filename hash; casefold/encryption paths can stay out.
- `fs/ext4/hash.c`: TEA, half-MD4, legacy filename hash; high bug value but
  heavier headers than F2FS.
- `fs/nls/nls_ucs2_utils.c`: UCS-2 uppercase table/range helpers.
- `fs/ceph/util.c`: small Ceph utility helpers, worth scouting.
- `fs/smb/common/cifs_md4.c`: crypto-style MD4 helper.

Lower-priority filesystem candidates:

- `fs/qnx4/bitmap.c`, `fs/minix/bitmap.c`, `fs/hfs/bitmap.c`,
  `fs/hfsplus/bitmap.c`, and `fs/omfs/bitmap.c`: bitmap logic but often tied
  to buffer-head/superblock reads.
- `fs/verity/hash_algs.c`: framework wrapper around crypto hash APIs.
- `fs/ntfs3/lib/decompress_common.c`: possible but compression-style state.

## `block/`, `mm/`, And Generic `kernel/`

Good candidates:

- `kernel/range.c`: range add/merge/subtract; avoid callback sort paths first.
- `block/t10-pi.c`: T10 protection-information tuple verification/set helpers;
  target static tuple helpers first, not full bio iteration.
- `block/blk-ia-ranges.c`: independent-access range validation/changing logic;
  skip sysfs registration paths.
- `mm/interval_tree.c`: interval-tree wrappers; likely needs rbtree and VMA
  struct shims.

Medium-risk candidates:

- `mm/page_counter.c`: meaningful accounting logic but atomic-heavy.
- `mm/page_frag_cache.c`: compact allocator accounting but page/netmem types.
- `mm/mmzone.c`: zone iteration helpers, but global node-data modeling is
  required.
- `mm/memtest.c`: memory-pattern test logic, but real path depends on memblock
  and physical mappings.

## Parked `kernel/bpf/` Opportunities

We intentionally parked additional BPF-core files, but these remain the most
interesting later targets:

- `kernel/bpf/const_fold.c`: verifier constant-folding logic; likely high
  value if a small expression model can be built.
- `kernel/bpf/cfg.c`: control-flow graph helpers; useful but graph state can
  grow quickly.
- `kernel/bpf/backtrack.c`: verifier precision/backtracking logic; high value,
  high shim cost.
- `kernel/bpf/cpumask.c`: kfunc helper surface; medium shim cost.
- `kernel/bpf/crypto.c`: BPF crypto wrapper logic; likely depends on Crypto API
  stubs.
- `kernel/bpf/ringbuf.c`: map/ring buffer algorithms; meaningful but pointer
  aliasing and allocator shims are likely hard.
- `kernel/bpf/stackmap.c`, `kernel/bpf/arraymap.c`, `kernel/bpf/hashtab.c`,
  `kernel/bpf/devmap.c`, and `kernel/bpf/cpumap.c`: map algorithms with
  increasing allocator, RCU, and pointer-storage complexity.
- `kernel/bpf/log.c`, `kernel/bpf/states.c`, `kernel/bpf/liveness.c`,
  `kernel/bpf/fixups.c`, and `kernel/bpf/relo_core.c`: verifier internals with
  high bug-finding value, but likely require narrow copied/shimmed slices.

## `lib/` Second-Step Backlog

Good new `lib/` candidates:

- `lib/crypto/hash_info.c`: data-table sanity for hash names and digest sizes.
- `lib/random32.c`: `prandom_u32_state()` and bounded `prandom_bytes_state()`.
- `lib/parser.c`: token and substring parsing; needs bounded string helpers.
- `lib/asn1_decoder.c` and `lib/asn1_encoder.c`: parsers/encoders, likely good
  bug-finding targets if bounded.
- `lib/bootconfig.c`: parser logic, likely high value but larger.
- `lib/buildid.c`: ELF/build-id parsing, likely shim-heavy but interesting.
- `lib/earlycpio.c`: archive parsing.
- `lib/fdt*.c`: flattened-device-tree helpers; good parser target family.
- `lib/reed_solomon/*.c`: encode/decode logic; table/state size must be checked.
- `lib/xz/*.c` and `lib/842/*.c`: compression/decompression internals; high
  complexity but possible if bounded helper paths are isolated.

Existing harnesses worth coverage cleanup:

- CRC/checksum family: `crc32`, `crc4`, `crc64`, `crc_t10dif`, `checksum`.
- String/parser family: `glob`, `kstrtox`, `string`, `ts_fsm`, `ts_kmp`,
  `uuid`, `ucs2_string`.
- Data-structure family: `bsearch`, `llist`, `list_sort`, `rbtree`,
  `timerqueue`, `linear_ranges`, `dynamic_queue_limits`, `packing`.
- Crypto family: `arc4`, `lib_aes`, `lib_chacha`, `lib_poly1305`,
  `lib_blake2s`, `nh`, `siphash`, `xxhash`.
- Compression/MPI family: `lz4_*`, `lzo_*`, `zlib_*`, `zstd_*`, `mpi_*`,
  `mpih_*`; these should be treated as second-pass cleanup because many were
  originally reduced to compile-only or wrapper-only paths for verifier limits.

Coverage-cleanup targets to deprioritize:

- `lcm`: blocked by `gcd()` unbounded loop unless we only test trivial
  zero-operand paths.
- `memweight`: pointer-to-integer alignment checks conflict with BPF pointer
  typing.
- `min_heap` and full `sort()`/`sort_r()` style APIs: callback/indirect-call
  architecture is not verifier input.
- Large compression harnesses unless the goal is specifically to improve
  compile coverage rather than search for kernel bugs.

## Recommended Order

1. Do the drivers/net/fs pure-helper batch:
   `dp_utils`, `open_alliance_helpers`, `ghes_helpers`, `cudbg_common`,
   `vidtv_common`, `crush/hash`, `ceph_hash`, `proc/util`, and `ntfs3/bitfunc`.
2. Add top-level `crypto/` hash wrappers:
   `crc32`, `crc32c`, `xxhash_generic`, `sm3`, `sha3`, and one SHA wrapper.
3. Return to `lib/` cleanup for the small constant-folded families:
   CRC/checksum, parser/string, and data-structure helpers.
4. Revisit parked `kernel/bpf/` with one narrow verifier-internal file at a
   time, starting with `const_fold.c` or `cfg.c`.
5. Save broad drivers, block/mm, crypto framework, and compression internals
   for focused probes after the smaller batches are exhausted.
