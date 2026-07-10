/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local crypto type surface for kernel/bpf/crypto.c. */
#ifndef _BPF_CRYPTO_H
#define _BPF_CRYPTO_H

#include <linux/types.h>

struct module;

struct bpf_crypto_type {
	void *(*alloc_tfm)(const char *algo);
	void (*free_tfm)(void *tfm);
	int (*has_algo)(const char *algo);
	int (*setkey)(void *tfm, const u8 *key, unsigned int keylen);
	int (*setauthsize)(void *tfm, unsigned int authsize);
	int (*encrypt)(void *tfm, const u8 *src, u8 *dst, unsigned int len, u8 *iv);
	int (*decrypt)(void *tfm, const u8 *src, u8 *dst, unsigned int len, u8 *iv);
	unsigned int (*ivsize)(void *tfm);
	unsigned int (*statesize)(void *tfm);
	u32 (*get_flags)(void *tfm);
	struct module *owner;
	char name[14];
};

#endif /* _BPF_CRYPTO_H */
