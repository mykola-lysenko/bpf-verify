/* SPDX-License-Identifier: GPL-2.0 */
/* BPF verification shim for linux/seq_buf.h
 * Replaces the kernel's seq_buf.h to avoid extern declarations of functions
 * that are BPF-incompatible (variadic seq_buf_printf, VFS seq_buf_path,
 * user-space seq_buf_to_user). The struct definition and all static inline
 * helpers are preserved verbatim.
 */
#ifndef _LINUX_SEQ_BUF_H
#define _LINUX_SEQ_BUF_H

/* seq_buf.h normally includes linux/fs.h for loff_t and struct path.
 * We include linux/types.h instead (lighter weight) since we don't need
 * the full VFS type system. */
#include <linux/types.h>

/* Provide a type-safe min() macro since linux/minmax.h may not be available
 * in the shim include path. */
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

struct seq_buf {
	char			*buffer;
	size_t			size;
	size_t			len;
	loff_t			readpos;
};

static inline void seq_buf_clear(struct seq_buf *s)
{
	s->len = 0;
	s->readpos = 0;
}

static inline void
seq_buf_init(struct seq_buf *s, char *buf, unsigned int size)
{
	s->buffer = buf;
	s->size = size;
	seq_buf_clear(s);
}

static inline bool
seq_buf_has_overflowed(struct seq_buf *s)
{
	return s->len > s->size;
}

static inline void
seq_buf_set_overflow(struct seq_buf *s)
{
	s->len = s->size + 1;
}

static inline unsigned int
seq_buf_buffer_left(struct seq_buf *s)
{
	if (seq_buf_has_overflowed(s))
		return 0;
	return s->size - s->len;
}

static inline unsigned int seq_buf_used(struct seq_buf *s)
{
	return min(s->len, s->size);
}

static inline void seq_buf_terminate(struct seq_buf *s)
{
	if (WARN_ON(s->size == 0))
		return;
	if (seq_buf_buffer_left(s))
		s->buffer[s->len] = 0;
	else
		s->buffer[s->size - 1] = 0;
}

static inline size_t seq_buf_get_buf(struct seq_buf *s, char **bufp)
{
	WARN_ON(s->len > s->size + 1);
	if (s->len < s->size) {
		*bufp = s->buffer + s->len;
		return s->size - s->len;
	}
	*bufp = NULL;
	return 0;
}

static inline void seq_buf_commit(struct seq_buf *s, int num)
{
	if (num < 0) {
		seq_buf_set_overflow(s);
	} else {
		BUG_ON(s->len + num > s->size);
		s->len += num;
	}
}

/* Extern declarations for the BPF-safe functions only.
 * seq_buf_printf (variadic), seq_buf_hex_dump, seq_buf_path, seq_buf_to_user
 * are intentionally omitted; they are handled via the shim source file.
 * Use __builtin_va_list instead of va_list to avoid requiring <stdarg.h>. */
extern int seq_buf_vprintf(struct seq_buf *s, const char *fmt, __builtin_va_list args);
extern int seq_buf_puts(struct seq_buf *s, const char *str);
extern int seq_buf_putc(struct seq_buf *s, unsigned char c);
extern int seq_buf_putmem(struct seq_buf *s, const void *mem, unsigned int len);
extern int seq_buf_putmem_hex(struct seq_buf *s, const void *mem, unsigned int len);

#endif /* _LINUX_SEQ_BUF_H */
