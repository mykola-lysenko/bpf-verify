/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BTF surface for kernel/bpf/check_btf.c. */
#ifndef _LINUX_BTF_H
#define _LINUX_BTF_H

#include <linux/bpf.h>
#include <linux/errno.h>

#ifndef NULL
#define NULL ((void *)0)
#endif
#ifndef ERR_PTR
#define ERR_PTR(error) ((void *)(long)(error))
#endif

#define BTF_INFO_KIND(info) (((info) >> 24) & 0x7f)
#define BTF_INFO_VLEN(info) ((info) & 0xffffff)
#define BTF_INFO_ENC(kind, vlen) (((kind) << 24) | (vlen))

enum {
	BTF_KIND_INT = 1,
	BTF_KIND_STRUCT = 4,
	BTF_KIND_ENUM = 6,
	BTF_KIND_FUNC = 12,
	BTF_KIND_FUNC_PROTO = 13,
	BTF_KIND_ENUM64 = 19,
};

enum {
	BTF_FUNC_STATIC = 0,
	BTF_FUNC_GLOBAL = 1,
	BTF_FUNC_EXTERN = 2,
};

struct btf_type {
	u32 name_off;
	u32 info;
	union {
		u32 size;
		u32 type;
	};
};

struct btf {
	int fd;
};

static struct btf __check_btf_obj = {
	.fd = 1,
};

static const struct btf_type __check_btf_type_func = {
	.name_off = 1,
	.info = BTF_INFO_ENC(BTF_KIND_FUNC, BTF_FUNC_GLOBAL),
	.type = 2,
};
static const struct btf_type __check_btf_type_func_proto = {
	.name_off = 2,
	.info = BTF_INFO_ENC(BTF_KIND_FUNC_PROTO, 0),
	.type = 3,
};
static const struct btf_type __check_btf_type_int = {
	.name_off = 3,
	.info = BTF_INFO_ENC(BTF_KIND_INT, 0),
	.size = 4,
};
static const struct btf_type __check_btf_type_struct = {
	.name_off = 6,
	.info = BTF_INFO_ENC(BTF_KIND_STRUCT, 0),
	.size = 8,
};

static inline const struct btf_type *btf_type_by_id(const struct btf *btf,
						    u32 id)
{
	(void)btf;
	if (id == 2)
		return &__check_btf_type_func_proto;
	if (id == 3)
		return &__check_btf_type_int;
	if (id == 6)
		return &__check_btf_type_struct;
	return &__check_btf_type_func;
}

static inline bool btf_type_is_func(const struct btf_type *t)
{
	return t && BTF_INFO_KIND(t->info) == BTF_KIND_FUNC;
}

static inline bool btf_type_is_func_proto(const struct btf_type *t)
{
	return t && BTF_INFO_KIND(t->info) == BTF_KIND_FUNC_PROTO;
}

static inline bool btf_type_is_small_int(const struct btf_type *t)
{
	return t && BTF_INFO_KIND(t->info) == BTF_KIND_INT && t->size <= 8;
}

static inline bool btf_is_any_enum(const struct btf_type *t)
{
	u32 kind;

	if (!t)
		return false;
	kind = BTF_INFO_KIND(t->info);
	return kind == BTF_KIND_ENUM || kind == BTF_KIND_ENUM64;
}

static inline const struct btf_type *
btf_type_skip_modifiers(const struct btf *btf, u32 id, u32 *res_id)
{
	if (res_id)
		*res_id = id;
	return btf_type_by_id(btf, id);
}

static inline const char *btf_name_by_offset(const struct btf *btf, u32 off)
{
	(void)btf;
	if (!off)
		return NULL;
	return "check_btf";
}

static inline struct btf *btf_get_by_fd(int fd)
{
	if (fd <= 0)
		return ERR_PTR(-EINVAL);
	return &__check_btf_obj;
}

static inline bool btf_is_kernel(const struct btf *btf)
{
	(void)btf;
	return false;
}

static inline void btf_put(struct btf *btf)
{
	(void)btf;
}

static inline int bpf_core_apply(struct bpf_core_ctx *ctx,
				 const struct bpf_core_relo *relo,
				 u32 index, struct bpf_insn *insn)
{
	(void)ctx;
	(void)relo;
	(void)index;
	(void)insn;
	return 0;
}

#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)

#endif /* _LINUX_BTF_H */
