/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm/param.h — wraps asm-generic/param.h */
#ifndef _ASM_PARAM_H
#define _ASM_PARAM_H
#include <uapi/asm-generic/param.h>
#ifndef HZ
# define HZCONFIG_HZ
#endif
#ifndef USER_HZ
# define USER_HZ100
#endif
#ifndef CLOCKS_PER_SEC
# define CLOCKS_PER_SEC(USER_HZ)
#endif
#endif /* _ASM_PARAM_H */
