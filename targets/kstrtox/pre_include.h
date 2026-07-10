/* kstrtox.c uses ULLONG_MAX and INT_MAX but BPF -nostdinc omits limits.h. */
#ifndef ULLONG_MAX
#define ULLONG_MAX (~0ULL)
#endif
#ifndef LLONG_MAX
#define LLONG_MAX  ((long long)(ULLONG_MAX >> 1))
#endif
#ifndef LLONG_MIN
#define LLONG_MIN  (-LLONG_MAX - 1)
#endif
#ifndef INT_MAX
#define INT_MAX    ((int)(~0U >> 1))
#endif
#ifndef INT_MIN
#define INT_MIN    (-INT_MAX - 1)
#endif
#ifndef UINT_MAX
#define UINT_MAX   (~0U)
#endif
/* min() is used by kstrtox.c but may not be defined yet when ctype.c is
 * included. Provide a safe fallback. */
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
