#ifndef _SHIM_LINUX_STDDEF_H
#define _SHIM_LINUX_STDDEF_H
/* system <stddef.h> (via khost) provides NULL/offsetof/size_t; <stdbool.h>
 * provides bool/true/false. Block the kernel enum that redefines false/true. */
#include <stddef.h>
#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER) + sizeof(((TYPE *)0)->MEMBER))
#endif
#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) (sizeof(((TYPE *)0)->MEMBER))
#endif
#endif
