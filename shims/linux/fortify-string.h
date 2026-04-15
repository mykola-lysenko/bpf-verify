/* BPF shim: linux/fortify-string.h
 * The real fortify-string.h uses __diagnose_as_builtin__ and __overloadable
 * attributes that are not supported by the BPF clang backend.
 * Block it and provide minimal string function declarations.
 */
#ifndef _LINUX_FORTIFY_STRING_H_
#define _LINUX_FORTIFY_STRING_H_

#include <linux/string.h>

/* Provide no-op stubs for fortify panic functions */
static inline void fortify_panic(const char *name) { }

#endif /* _LINUX_FORTIFY_STRING_H_ */
