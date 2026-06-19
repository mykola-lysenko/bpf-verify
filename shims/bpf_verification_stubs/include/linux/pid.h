/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PID_H
#define _LINUX_PID_H

enum pid_type {
	PIDTYPE_PID = 0,
	PIDTYPE_TGID = 1,
	PIDTYPE_PGID = 2,
};

/* pid.h is the final include in bpf_verification_stubs.c.  Start the
 * target-only source function attributes here so shim header helpers stay
 * inline, while the real source stubs remain visible to the verifier.
 */
#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
#pragma clang attribute push(__attribute__((__noinline__)), apply_to=function)

#endif /* _LINUX_PID_H */
