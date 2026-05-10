// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF verification source for the optional linux/uaccess.h copy model.
 *
 * The default uaccess shim remains fail-closed. This source opts into the
 * bounded stack-backed copy behavior so the verifier covers the implementation
 * without changing unrelated targets.
 */

#define BPF_VERIFY_UACCESS_COPY
#define BPF_VERIFY_UACCESS_NOINLINE
#include <linux/uaccess.h>
