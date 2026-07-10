/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BTF_IDS_H
#define _LINUX_BTF_IDS_H

#include <linux/types.h>

struct btf_kfunc_id_set {
	void *owner;
	const void *set;
};

#define BTF_KFUNCS_START(name)	static u32 name[] = {
#define BTF_ID_FLAGS(kind, name, ...)	(__LINE__),
#define BTF_KFUNCS_END(name)	};

#define BTF_SET_START(name)	static u32 name[] = {
#define BTF_ID(kind, name)	(__LINE__),
#define BTF_SET_END(name)	};

static inline bool btf_id_set_contains(const u32 *set, u32 id)
{
	(void)set;
	(void)id;
	return false;
}

static inline int register_btf_kfunc_id_set(int prog_type,
					    const struct btf_kfunc_id_set *set)
{
	(void)set;
	return prog_type > 0 ? 0 : -1;
}

#endif /* _LINUX_BTF_IDS_H */
