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
#define _CRYPTO_INTERNAL_SKCIPHER_H
#define _LINUX_SCHED_H
#define CRYPTO_LSKCIPHER_FLAG_CONT 0x00000001
#define pr_warn_ratelimited(fmt, ...) do { } while (0)

#include <crypto/arc4.h>

struct crypto_lskcipher {
    int dummy;
};

struct lskcipher_alg {
    struct {
        struct crypto_alg base;
        unsigned int min_keysize;
        unsigned int max_keysize;
        unsigned int statesize;
    } co;
    int (*setkey)(struct crypto_lskcipher *tfm, const u8 *key,
                  unsigned int keylen);
    int (*encrypt)(struct crypto_lskcipher *tfm, const u8 *src, u8 *dst,
                   unsigned int nbytes, u8 *siv, u32 flags);
    int (*decrypt)(struct crypto_lskcipher *tfm, const u8 *src, u8 *dst,
                   unsigned int nbytes, u8 *siv, u32 flags);
    int (*init)(struct crypto_lskcipher *tfm);
};

struct task_struct {
    char comm[16];
    long pid;
};

static struct task_struct __bpf_current = {
    .comm = "bpf-verify",
    .pid = 1,
};
static struct arc4_ctx __bpf_arc4_ctx;
static struct arc4_ctx __bpf_arc4_siv;

#define current (&__bpf_current)

static inline
void *crypto_lskcipher_ctx(struct crypto_lskcipher *tfm)
{
    return &__bpf_arc4_ctx;
}

static inline
int crypto_register_lskcipher(struct lskcipher_alg *alg)
{
    return 0;
}

static inline
void crypto_unregister_lskcipher(struct lskcipher_alg *alg)
{
}
