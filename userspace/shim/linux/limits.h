#ifndef _SHIM_LINUX_LIMITS_H
#define _SHIM_LINUX_LIMITS_H
#include <limits.h>

/* Kernel fixed-width limit macros (linux/limits.h), needed by width-templated
 * code such as kernel/bpf/cnum_defs.h (UT_MAX/ST_MAX/ST_MIN). */
#ifndef U8_MAX
#define U8_MAX   ((unsigned char)~0U)
#endif
#ifndef S8_MAX
#define S8_MAX   ((signed char)(U8_MAX >> 1))
#endif
#ifndef S8_MIN
#define S8_MIN   ((signed char)(-S8_MAX - 1))
#endif
#ifndef U16_MAX
#define U16_MAX  ((unsigned short)~0U)
#endif
#ifndef S16_MAX
#define S16_MAX  ((short)(U16_MAX >> 1))
#endif
#ifndef S16_MIN
#define S16_MIN  ((short)(-S16_MAX - 1))
#endif
#ifndef U32_MAX
#define U32_MAX  ((unsigned int)~0U)
#endif
#ifndef S32_MAX
#define S32_MAX  ((int)(U32_MAX >> 1))
#endif
#ifndef S32_MIN
#define S32_MIN  ((int)(-S32_MAX - 1))
#endif
#ifndef U64_MAX
#define U64_MAX  ((unsigned long long)~0ULL)
#endif
#ifndef S64_MAX
#define S64_MAX  ((long long)(U64_MAX >> 1))
#endif
#ifndef S64_MIN
#define S64_MIN  ((long long)(-S64_MAX - 1))
#endif

#endif
