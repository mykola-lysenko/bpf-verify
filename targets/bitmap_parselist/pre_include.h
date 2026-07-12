/* DOCUMENTED VERIFIER BOUNDARY (expect_failure target) -- see harness.c.
 *
 * bitmap-str.c pulls linux/mm.h transitively, but only uses it for kasprintf in
 * a sysfs formatting helper (bitmap_print_bitmask_to_buf) that we don't
 * exercise. Blocking mm.h / huge_mm.h avoids the deep MM header chain (maple
 * tree, large-folio, per-CPU rss_stat, seqcounts) that mm.h would otherwise
 * require -- none of which the bitmap string parser actually needs. See
 * analysis/shim_completeness_and_bpf_boundaries.md (third pass). */
#define _LINUX_MM_H
#define _LINUX_HUGE_MM_H
#include <linux/slab.h>
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
/* kasprintf is variadic (BPF can't compile a variadic definition) and lives
 * behind the blocked mm.h chain. It is referenced only by the unexercised
 * bitmap_print_bitmask_to_buf path, so macro-replace it with a NULL result --
 * this swallows the varargs and avoids both an unresolved extern and a variadic
 * definition. */
#define kasprintf(gfp, ...) ((char *)0)
/* _ctype table (isdigit/isspace in the parse path) lives in lib/ctype.c;
 * include it verbatim so the exercised parse path stays real rather than
 * stubbed. (lib/kstrtox.c is NOT includable: its overflow detection needs
 * __multi3 128-bit multiply, unavailable on BPF -- _parse_integer is provided
 * in preamble.h instead.) */
#include "{ksrc}/lib/ctype.c"
