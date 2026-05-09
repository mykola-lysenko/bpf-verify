/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF shim: linux/seq_buf.h
 *
 * Use the real seq_buf public header while avoiding linux/seq_file.h's VFS
 * dependency chain. The real seq_buf.h only needs seq_file/path as pointer
 * types for declarations that the BPF harness does not call.
 */
#ifndef __BPF_LINUX_SEQ_BUF_SHIM_H
#define __BPF_LINUX_SEQ_BUF_SHIM_H

#include <linux/stdarg.h>
#include <linux/types.h>

struct path;
struct seq_file;

#ifndef _LINUX_SEQ_FILE_H
#define _LINUX_SEQ_FILE_H
#endif

#include_next <linux/seq_buf.h>

#endif /* __BPF_LINUX_SEQ_BUF_SHIM_H */
