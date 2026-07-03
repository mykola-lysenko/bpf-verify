// SPDX-License-Identifier: GPL-2.0-only
/*
 * ASAN/UBSan fuzzer for find_cpio_data() (lib/earlycpio.c) on corrupt archives.
 *
 * find_cpio_data() walks an in-memory "newc" cpio archive parsing 8-hex-digit
 * header fields (name size, file size, mode, magic) and computing offsets into
 * the buffer. Attacker-controlled sizes feed pointer arithmetic and a
 * strscpy() of the entry name, so a corrupt archive is a natural place for an
 * out-of-bounds read. The archive lives in a heap buffer with tight ASan
 * redzones; any read past its end traps.
 *
 * Random bytes never match the "070701" magic, so most iterations build a
 * structurally-valid header (magic + hex fields) and fuzz the field values,
 * driving the parser into the size/offset arithmetic and the name-copy path.
 * Using an empty search path makes the name comparison always match, reaching
 * the strscpy() copy.
 */
#include "fuzz.h"
#include <stdlib.h>
#include <string.h>

#include KCPIO_SRC

/* newc header: 6-char magic + 12 fields x 8 hex chars = 110 bytes. */
#define CPIO_HDR 110

static void put_hex8(char *p, uint32_t v)
{
	static const char hx[] = "0123456789abcdef";
	for (int i = 7; i >= 0; i--) { p[i] = hx[v & 0xf]; v >>= 4; }
}

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen)
{
	(void)msg; (void)msglen;
	int structured = (fuzz_u64(in) & 3) != 0; /* 3/4 structured, 1/4 random */
	size_t len = (size_t)fuzz_range(in, 0, 400);
	char *data = malloc(len ? len : 1);
	if (!data)
		return 0;

	if (structured && len >= CPIO_HDR) {
		/* magic 070700/070701/070702 (the parser accepts a range) */
		memcpy(data, "070701", 6);
		char *f = data + 6;
		for (int i = 0; i < 12; i++) {   /* fuzz every 8-hex field */
			put_hex8(f, (uint32_t)fuzz_u64(in));
			f += 8;
		}
		/* bias mode toward S_IFREG (0100000) so the name-copy path is
		 * reached; C_MODE is field index 1 (offset 6 + 1*8). */
		if ((fuzz_u64(in) & 1))
			put_hex8(data + 6 + 8, 0100000);
		/* fill the rest with fuzzed bytes (rarely a NUL -> stresses the
		 * unbounded name read) */
		for (size_t i = CPIO_HDR; i < len; i++)
			data[i] = (char)fuzz_u64(in);
	} else {
		fuzz_bytes(in, data, len);
	}

	long nextoff = 0;
	/* empty path -> name comparison length 0 always matches, reaching the
	 * name strscpy(); return value ignored, ASan enforces safety. */
	volatile struct cpio_data cd = find_cpio_data("", data, len, &nextoff);
	(void)cd;

	free(data);
	return 0;
}

const char *fuzz_name = "cpio";
