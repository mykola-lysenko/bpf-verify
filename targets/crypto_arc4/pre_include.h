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
