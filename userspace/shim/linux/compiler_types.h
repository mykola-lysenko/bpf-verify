#ifndef _SHIM_LINUX_COMPILER_TYPES_H
#define _SHIM_LINUX_COMPILER_TYPES_H

/* Token paste, as in the kernel's compiler_types.h -- used by width-templated
 * code such as kernel/bpf/cnum_defs.h (FN(name) = cnum##T##_##name). */
#ifndef ___PASTE
#define ___PASTE(a, b) a##b
#endif
#ifndef __PASTE
#define __PASTE(a, b) ___PASTE(a, b)
#endif

#endif
