#ifndef _SHIM_LINUX_SWAB_H
#define _SHIM_LINUX_SWAB_H
#include "khost.h"
#define swab16(x) __builtin_bswap16(x)
#define swab32(x) __builtin_bswap32(x)
#define swab64(x) __builtin_bswap64(x)
#endif
