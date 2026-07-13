/* Host shim: linux/jump_label.h
 * Static-key machinery (self-modifying-code branch patching) is meaningless
 * in host reference builds; keys degrade to their compile-time defaults.
 * gcd.c uses a TRUE key to select the __ffs-based algorithm -- the same path
 * the BPF side takes -- so the differential compares like with like. */
#ifndef _SHIM_LINUX_JUMP_LABEL_H
#define _SHIM_LINUX_JUMP_LABEL_H
struct static_key_true { int v; };
struct static_key_false { int v; };
#define DECLARE_STATIC_KEY_TRUE(name)  extern struct static_key_true name
#define DEFINE_STATIC_KEY_TRUE(name)   struct static_key_true name = { 1 }
#define DECLARE_STATIC_KEY_FALSE(name) extern struct static_key_false name
#define DEFINE_STATIC_KEY_FALSE(name)  struct static_key_false name = { 0 }
#define static_branch_likely(k)        1
#define static_branch_unlikely(k)      0
#endif
