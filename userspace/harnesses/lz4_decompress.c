// SPDX-License-Identifier: GPL-2.0-only
/*
 * ASAN/UBSan fuzzer for the kernel's LZ4 decompressor on MALFORMED input.
 *
 * LZ4_decompress_safe() is contractually required to never read past the end
 * of the source buffer nor write past the end of the destination buffer, even
 * for adversarial/corrupt input (it guards compressed kernels, initramfs, BPF
 * map values, etc.). We feed it random and mutated byte streams and let
 * AddressSanitizer catch any out-of-bounds access. A clean run over millions
 * of inputs is evidence for the safety contract; an ASAN report is a bug.
 *
 * The buffers are heap-allocated so ASAN has real redzones on both ends: an
 * over-read of source or over-write of dest traps immediately.
 */
#include "fuzz.h"
#include <stdlib.h>

/* Pull in the real kernel decompressor. lz4defs.h / lz4.h are satisfied by the
 * userspace/shim tree plus khost.h; -I to the kernel lz4 dir is added by the
 * KLZ4_SRC define in run.sh so the source path is not hard-coded here. */
#include KLZ4_SRC

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen)
{
	/* Small buffers keep redzones close so OOB is caught precisely, while
	 * the sizes still exercise literal-copy, match-copy, and wildcopy paths. */
	int src_size = (int)fuzz_range(in, 0, 512);
	int dst_capacity = (int)fuzz_range(in, 0, 1024);

	char *src = malloc(src_size ? src_size : 1);
	char *dst = malloc(dst_capacity ? dst_capacity : 1);
	if (!src || !dst) {
		free(src);
		free(dst);
		return 0;
	}
	fuzz_bytes(in, src, src_size);

	/* Return value is intentionally ignored -- a negative return for
	 * malformed input is correct behavior. We are asserting only that the
	 * call performs no out-of-bounds memory access (checked by ASAN). */
	volatile int r = LZ4_decompress_safe(src, dst, src_size, dst_capacity);
	(void)r;

	free(src);
	free(dst);
	return 0; /* ASAN aborts on any memory-safety violation */
}

const char *fuzz_name = "lz4_decompress";
