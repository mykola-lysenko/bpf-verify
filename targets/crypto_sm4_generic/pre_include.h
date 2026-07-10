#define _CRYPTO_ALGAPI_H
#define _LINUX_CRYPTO_H
#define _LINUX_INIT_H
#define _LINUX_MM_H
#define __init
#define __exit
#define MODULE_ALIAS_CRYPTO(name)
#define CRYPTO_ALG_TYPE_CIPHER 0x00000001

struct crypto_tfm {
    u8 ctx[256] __attribute__((aligned(8)));
};

struct cipher_alg {
    unsigned int cia_min_keysize;
    unsigned int cia_max_keysize;
    int (*cia_setkey)(struct crypto_tfm *tfm, const u8 *key,
                      unsigned int keylen);
    void (*cia_encrypt)(struct crypto_tfm *tfm, u8 *dst, const u8 *src);
    void (*cia_decrypt)(struct crypto_tfm *tfm, u8 *dst, const u8 *src);
};

struct crypto_alg {
    const char *cra_name;
    const char *cra_driver_name;
    int cra_priority;
    u32 cra_flags;
    unsigned int cra_blocksize;
    unsigned int cra_ctxsize;
    unsigned int cra_alignmask;
    void *cra_module;
    union {
        struct cipher_alg cipher;
    } cra_u;
};

static inline
void *crypto_tfm_ctx(struct crypto_tfm *tfm)
{
    return tfm->ctx;
}

static inline
int crypto_register_alg(struct crypto_alg *alg)
{
    return 0;
}

static inline
void crypto_unregister_alg(struct crypto_alg *alg)
{
}

static inline
int crypto_register_algs(struct crypto_alg *algs, unsigned int count)
{
    return 0;
}

static inline
void crypto_unregister_algs(struct crypto_alg *algs, unsigned int count)
{
}
#include <linux/errno.h>
static inline
u32 __bpf_rol32(u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((0 - shift) & 31));
}
#define rol32(word, shift) __bpf_rol32((word), (shift))
#undef __alias
#define __alias(symbol)
#include "{ksrc}/crypto/sm4.c"
