#ifndef _SHIM_LINUX_MINMAX_H
#define _SHIM_LINUX_MINMAX_H

/* The kernel's linux/minmax.h uses __careful_cmp / __UNIQUE_ID, which need
 * compiler-plugin/statement-expression machinery unavailable in this userspace
 * build. Provide simple, side-effect-unsafe min/max/swap (adequate for the
 * width-templated cnum/tnum code, which passes plain scalars). khost.h may
 * already define these; the guards keep whichever came first. */
#ifndef min
#define min(a, b)  ((a) < (b) ? (a) : (b))
#endif
#ifndef max
#define max(a, b)  ((a) > (b) ? (a) : (b))
#endif
#ifndef swap
#define swap(a, b) do { typeof(a) __swap_tmp = (a); (a) = (b); (b) = __swap_tmp; } while (0)
#endif

#endif
