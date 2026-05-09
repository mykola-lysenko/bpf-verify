/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/*
 * BPF shim: linux/packing.h
 *
 * The real header declares several helpers with more than five arguments.
 * Apply internal_linkage to those declarations so the BPF backend can accept
 * the translation unit, while keeping the real header as the source of truth.
 */
#ifndef __BPF_LINUX_PACKING_SHIM_H
#define __BPF_LINUX_PACKING_SHIM_H

/* Preload dependency headers so the attribute scope below applies only to the
 * packing helper declarations, not unrelated inline functions/declarations. */
#include <linux/array_size.h>
#include <linux/bitops.h>
#include <linux/build_bug.h>
#include <linux/minmax.h>
#include <linux/stddef.h>
#include <linux/types.h>

#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
#include_next <linux/packing.h>
#pragma clang attribute pop

#endif /* __BPF_LINUX_PACKING_SHIM_H */
