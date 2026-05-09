/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm-generic/param.h */
#ifndef __BPF_ASM_GENERIC_PARAM_SHIM_H
#define __BPF_ASM_GENERIC_PARAM_SHIM_H

#include <uapi/asm-generic/param.h>

/*
 * The standalone shim autoconf may not match the checked-out kernel tree.
 * Keep HZ aligned with include/generated/timeconst.h, which is generated for
 * the UAPI default HZ value in this source tree.
 */
#undef HZ
#define HZ		__USER_HZ
#define USER_HZ		__USER_HZ
#define CLOCKS_PER_SEC	(USER_HZ)

#endif /* __BPF_ASM_GENERIC_PARAM_SHIM_H */
