/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BTF-ID surface for kernel/bpf/crypto.c. */
#ifndef _LINUX_BTF_IDS_H
#define _LINUX_BTF_IDS_H

#include <linux/types.h>

struct btf_kfunc_id_set {
	void *owner;
	const void *set;
};

struct btf_id_dtor_kfunc {
	u32 btf_id;
	u32 kfunc_btf_id;
};

#define BTF_KFUNCS_START(name) static u32 name[] = {
#define BTF_ID_FLAGS(kind, name, ...) (__LINE__),
#define BTF_KFUNCS_END(name) };

#define BTF_ID_LIST(name) static u32 name[2];
#define BTF_ID(kind, name)

static inline int register_btf_kfunc_id_set(int prog_type,
					    const struct btf_kfunc_id_set *set)
{
	(void)set;
	return prog_type > 0 ? 0 : -EINVAL;
}

static inline int
register_btf_id_dtor_kfuncs(const struct btf_id_dtor_kfunc *dtors,
			    u32 add_cnt, void *owner)
{
	(void)dtors;
	(void)owner;
	return add_cnt ? 0 : -EINVAL;
}

#endif /* _LINUX_BTF_IDS_H */
