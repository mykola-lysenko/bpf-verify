/* Block linux/bpf.h: it pulls in linux/percpu.h, linux/mm_types.h, etc.
 * The shim provides struct bpf_insn and all BPF constants directly. */
#define _LINUX_BPF_H 1
/* Block linux/kernel.h to avoid the __printf(3,4) conflict with clang
 * system headers.  The shim provides its own disasm.h replacement. */
#define _LINUX_KERNEL_H
/* Stub verbose() as a no-op: print_bpf_insn() uses a variadic callback
 * (bpf_insn_print_t) with >5 arguments, which the BPF backend rejects.
 * We only verify func_id_name() and the string tables, not print_bpf_insn.
 * Stubbing verbose() allows the whole file to compile without errors. */
#define verbose(priv, fmt, ...) ((void)(priv))
/* Stub snprintf: disasm.c uses it only to format fallback strings into
 * a caller-supplied buffer (buff).  Returning 0 is safe -- the caller
 * always returns buff regardless of the return value. */
#define snprintf(buf, size, fmt, ...) (0)
/* Stub strcpy: used once in print_bpf_insn for the "unknown" fallback. */
static __always_inline char *__bpf_strcpy(char *d, const char *s)
{
    char *r = d;
    while ((*d++ = *s++));
    return r;
}
#define strcpy(d, s) __bpf_strcpy(d, s)
/* Provide __stringify since linux/stringify.h is blocked by _LINUX_KERNEL_H. */
#ifndef __stringify
#define __stringify(x) #x
#endif
/* Provide BUILD_BUG_ON as a no-op (used in __func_get_name). */
#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(cond) ((void)(cond))
#endif
