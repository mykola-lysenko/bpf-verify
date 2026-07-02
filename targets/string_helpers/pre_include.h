
/* Provide hex_to_bin as a static inline to avoid extern BTF reference */
static inline int hex_to_bin(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}
/* string_helpers.c includes linux/export.h, linux/kernel.h, linux/string.h.
 * Block heavy headers and provide minimal stubs. */
#define _LINUX_EXPORT_H
#define MODULE_LICENSE(x)
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
/* string_get_size uses snprintf (variadic, not BPF-compatible). Stub it out. */
#define string_get_size __bpf_string_get_size_stub
/* kasprintf uses variadic args - stub it */
#define kasprintf(gfp, fmt, ...) ((char *)0)
/* Block sprintf.h to avoid conflict with our snprintf macro.
 * kernel.h includes sprintf.h, so we must block it before kernel.h is processed. */
#define _LINUX_SPRINTF_H
#define _LINUX_KERNEL_SPRINTF_H_
/* Block string_helpers.h to avoid conflict with our string_get_size macro */
#define _LINUX_STRING_HELPERS_H
#define _LINUX_STRING_HELPERS_H_
/* Ensure size_t is defined since we block string_helpers.h */
#ifndef __SIZE_TYPE__
typedef unsigned long size_t;
#endif
/* Provide UNESCAPE_* and ESCAPE_* constants from string_helpers.h */
#define UNESCAPE_SPACE    (1 << 0)
#define UNESCAPE_OCTAL    (1 << 1)
#define UNESCAPE_HEX      (1 << 2)
#define UNESCAPE_SPECIAL  (1 << 3)
#define UNESCAPE_ANY      (UNESCAPE_SPACE | UNESCAPE_OCTAL | UNESCAPE_HEX | UNESCAPE_SPECIAL)
#define ESCAPE_SPACE      (1 << 0)
#define ESCAPE_SPECIAL    (1 << 1)
#define ESCAPE_NULL       (1 << 2)
#define ESCAPE_OCTAL      (1 << 3)
#define ESCAPE_ANY        (ESCAPE_SPACE | ESCAPE_OCTAL | ESCAPE_SPECIAL | ESCAPE_NULL)
#define ESCAPE_NP         (1 << 4)
#define ESCAPE_ANY_NP     (ESCAPE_ANY | ESCAPE_NP)
#define ESCAPE_HEX        (1 << 5)
#define ESCAPE_NA         (1 << 6)
#define ESCAPE_NAP        (1 << 7)
#define ESCAPE_APPEND     (1 << 8)
/* kfree_strarray declaration to avoid conflicting types */
extern void kfree_strarray(char **array, unsigned long n);
enum string_size_units {
    STRING_UNITS_10 = 0,
    STRING_UNITS_2 = 1,
    STRING_UNITS_MASK = 1,
    STRING_UNITS_NO_SPACE = (1 << 30),
    STRING_UNITS_NO_BYTES = (1 << 31),
};
/* Now define snprintf as a macro stub (sprintf.h is blocked, so no conflict) */
#define snprintf(buf, size, fmt, ...) (0)
#define scnprintf(buf, size, fmt, ...) (0)
/* UNESCAPE_* flags are passed via -D; define fallbacks */
#ifndef UNESCAPE_SPACE
#define UNESCAPE_SPACE   1
#endif
#ifndef UNESCAPE_OCTAL
#define UNESCAPE_OCTAL   2
#endif
#ifndef UNESCAPE_HEX
#define UNESCAPE_HEX     4
#endif
#ifndef UNESCAPE_SPECIAL
#define UNESCAPE_SPECIAL 8
#endif
#ifndef UNESCAPE_ANY
#define UNESCAPE_ANY     0xf
#endif
