/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * BPF shim: linux/mpi.h
 *
 * Keep the real public MPI header as the source of truth, but mark its
 * function declarations internal_linkage. The MPI source shims later apply the
 * same attribute to selected definitions, and Clang requires the first
 * declaration to carry a consistent linkage attribute.
 */
#ifndef __BPF_LINUX_MPI_SHIM_H
#define __BPF_LINUX_MPI_SHIM_H

/* Preload dependencies so the attribute scope below applies to MPI function
 * declarations only, not unrelated helper declarations from dependency
 * headers. */
#include <linux/types.h>
#include <linux/scatterlist.h>

#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
#include_next <linux/mpi.h>
#pragma clang attribute pop

#endif /* __BPF_LINUX_MPI_SHIM_H */
