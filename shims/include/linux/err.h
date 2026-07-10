/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: linux/err.h */
#ifndef _LINUX_ERR_H
#define _LINUX_ERR_H

#include <linux/compiler.h>

#ifndef MAX_ERRNO
#define MAX_ERRNO	4095
#endif

#ifndef IS_ERR_VALUE
#define IS_ERR_VALUE(x)	((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
#endif

#ifndef ERR_PTR
#define ERR_PTR(error)	((void *)(long)(error))
#endif

#ifndef IOMEM_ERR_PTR
#define IOMEM_ERR_PTR(error)	((void __iomem *)ERR_PTR(error))
#endif

#ifndef PTR_ERR
#define PTR_ERR(ptr)	((long)(ptr))
#endif

#ifndef IS_ERR
#define IS_ERR(ptr)	IS_ERR_VALUE(ptr)
#endif

#ifndef IS_ERR_OR_NULL
#define IS_ERR_OR_NULL(ptr)	(!(ptr) || IS_ERR(ptr))
#endif

#ifndef PTR_ERR_OR_ZERO
#define PTR_ERR_OR_ZERO(ptr)	(IS_ERR(ptr) ? PTR_ERR(ptr) : 0)
#endif

#endif /* _LINUX_ERR_H */
