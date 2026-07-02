// SPDX-License-Identifier: GPL-2.0-only
/*
 * Property fuzzer for int_sqrt(): for y = int_sqrt(x),
 *   y*y <= x < (y+1)*(y+1)
 * i.e. y is exactly floor(sqrt(x)). Checked across the full unsigned-long
 * range including boundary and overflow-adjacent values. (Unbounded loop, so
 * this cannot be an in-kernel execute:true target -- userspace is the tool.)
 * __int128 is used for the squares so the (y+1)^2 check cannot overflow.
 */
#include "fuzz.h"

#include KINT_SQRT_SRC

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen)
{
	unsigned long x = (unsigned long)fuzz_u64(in);
	unsigned long y = int_sqrt(x);
	__uint128_t y2 = (__uint128_t)y * y;
	__uint128_t y1 = (__uint128_t)(y + 1) * (y + 1);
	if (!(y2 <= x && (__uint128_t)x < y1)) {
		snprintf(msg, msglen,
			 "int_sqrt(%lu) = %lu but y^2=%llu (y+1)^2=%llu",
			 x, y, (unsigned long long)y2, (unsigned long long)y1);
		return 1;
	}
	return 0;
}

const char *fuzz_name = "int_sqrt";
