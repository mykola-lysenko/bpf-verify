/* SPDX-License-Identifier: GPL-2.0 */
/* BPF verification shim source for lib/seq_buf.c
 *
 * This replaces the kernel's lib/seq_buf.c for BPF compilation.
 * It provides only the BPF-safe functions:
 *   seq_buf_vprintf, seq_buf_puts, seq_buf_putc, seq_buf_putmem,
 *   seq_buf_putmem_hex
 *
 * The following functions are intentionally OMITTED because they are
 * incompatible with BPF:
 *   seq_buf_printf    -- variadic function (BPF rejects variadic definitions)
 *   seq_buf_hex_dump  -- calls seq_buf_printf (variadic) + hex_dump_to_buffer
 *   seq_buf_path      -- calls d_path() and mangle_path() (VFS operations)
 *   seq_buf_to_user   -- calls copy_to_user() (user-space memory access)
 *   seq_buf_print_seq -- calls seq_write() (struct seq_file, VFS)
 *   seq_buf_bprintf   -- calls bstr_printf() (binary format string, complex)
 *
 * The harness body tests seq_buf_puts, seq_buf_putc, seq_buf_putmem, and
 * seq_buf_putmem_hex, which cover the core buffer-management logic.
 *
 * vsnprintf is stubbed as a no-op so seq_buf_vprintf can compile without
 * pulling in the full kernel printf machinery.
 */

#include <linux/types.h>
#include <linux/seq_buf.h>

/* Suppress extern declarations of strlen/memcpy so the BPF backend uses
 * its builtins instead of generating BTF extern references. */
#define __HAVE_ARCH_STRLEN
#define __HAVE_ARCH_MEMCPY
static inline __kernel_size_t strlen(const char *s)
{ __kernel_size_t n = 0; while (s[n]) n++; return n; }
static inline void *memcpy(void *d, const void *s, __kernel_size_t n)
{ unsigned char *dd = d; const unsigned char *ss = s;
  __kernel_size_t i; for (i = 0; i < n; i++) dd[i] = ss[i]; return d; }

/* vsnprintf stub: seq_buf_vprintf calls vsnprintf to format into the buffer.
 * For BPF verification purposes we stub it as a no-op that returns 0. */
static inline int vsnprintf(char *buf, __kernel_size_t size, const char *fmt, __builtin_va_list args)
{
    (void)buf; (void)size; (void)fmt; (void)args;
    return 0;
}

/* seq_buf_can_fit is a static inline in seq_buf.h. Provide it here in case
 * the shim header does not expose it. */
static inline bool seq_buf_can_fit(struct seq_buf *s, size_t len)
{
    return s->len + len <= s->size;
}

int seq_buf_vprintf(struct seq_buf *s, const char *fmt, __builtin_va_list args)
{
    int len;
    if (s->size == 0)
        return -1;
    if (s->len < s->size) {
        len = vsnprintf(s->buffer + s->len, s->size - s->len, fmt, args);
        if (s->len + (size_t)len < s->size) {
            s->len += len;
            return 0;
        }
    }
    seq_buf_set_overflow(s);
    return -1;
}

int seq_buf_puts(struct seq_buf *s, const char *str)
{
    size_t len = strlen(str);
    if (s->size == 0)
        return -1;
    len += 1;
    if (seq_buf_can_fit(s, len)) {
        memcpy(s->buffer + s->len, str, len);
        s->len += len - 1;
        return 0;
    }
    seq_buf_set_overflow(s);
    return -1;
}

int seq_buf_putc(struct seq_buf *s, unsigned char c)
{
    if (s->size == 0)
        return -1;
    if (seq_buf_can_fit(s, 1)) {
        s->buffer[s->len++] = c;
        return 0;
    }
    seq_buf_set_overflow(s);
    return -1;
}

int seq_buf_putmem(struct seq_buf *s, const void *mem, unsigned int len)
{
    if (s->size == 0)
        return -1;
    if (seq_buf_can_fit(s, len)) {
        memcpy(s->buffer + s->len, mem, len);
        s->len += len;
        return 0;
    }
    seq_buf_set_overflow(s);
    return -1;
}

#define MAX_MEMHEX_BYTES    8U
#define HEX_CHARS           (MAX_MEMHEX_BYTES*2 + 1)

int seq_buf_putmem_hex(struct seq_buf *s, const void *mem, unsigned int len)
{
    unsigned char hex[HEX_CHARS];
    const unsigned char *data = mem;
    unsigned int start_len;
    int i, j;
    if (s->size == 0)
        return -1;
    while (len) {
        start_len = len < MAX_MEMHEX_BYTES ? len : MAX_MEMHEX_BYTES;
        for (i = (int)start_len - 1, j = 0; i >= 0; i--) {
            hex[j++] = "0123456789abcdef"[(data[i] >> 4) & 0xf];
            hex[j++] = "0123456789abcdef"[data[i] & 0xf];
        }
        if (j == 0 || (unsigned)j/2 > len)
            break;
        hex[j++] = ' ';
        seq_buf_putmem(s, hex, j);
        if (seq_buf_has_overflowed(s))
            return -1;
        len -= start_len;
        data += start_len;
    }
    return 0;
}
