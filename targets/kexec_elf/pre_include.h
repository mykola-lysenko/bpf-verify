/* kexec_elf.c: ELF header/program-header parsing (elf_read_ehdr /
 * elf_read_phdr and their sanity checks) -- fixed-layout buffer parsing with
 * per-field endian conversion, the first target from the beyond-lib/ curation
 * sweep (kernel/ root).
 *
 * The blockers were all include-chain, not code: linux/elf.h pulls asm/elf.h
 * -> fsgsbase/msr -> the whole x86 arch world (inline asm), and kexec.h pulls
 * the kexec machinery. Both blocked; the handful of macros/types the parser
 * actually consumes are provided here. uapi/linux/elf.h must come FIRST:
 * linux/elf.h tests `#if ELF_CLASS == ELFCLASS32` and with ELFCLASS* not yet
 * defined the preprocessor evaluates 0 == 0 and picks the 32-bit layout. */
#define _LINUX_KEXEC_H
#define LINUX_KEXEC_H
#define _ASM_X86_ELF_H
#include <linux/errno.h>
#include <uapi/linux/elf.h>
/* from the blocked asm/elf.h (x86_64) */
#define ELF_CLASS ELFCLASS64
#define ELF_DATA  ELFDATA2LSB
#define ELF_ARCH  EM_X86_64
#define elf_check_arch(x) ((x)->e_machine == EM_X86_64)
#define KEXEC_BUF_MEM_UNKNOWN 0
/* minimal kexec surface used by kexec_elf.c (from the blocked kexec.h);
 * elf64_* directly -- linux/elf.h's elfhdr/elf_phdr macros don't exist yet
 * here, and the source's mentions expand to elf64_* once it is parsed. */
struct kexec_elf_info {
	const char *buffer;
	const struct elf64_hdr *ehdr;
	const struct elf64_phdr *proghdrs;
};
struct kexec_buf {
	void *image;
	void *buffer;
	unsigned long bufsz, mem, memsz, buf_align, buf_min, buf_max;
	int top_down;
};
static inline int kexec_add_buffer(struct kexec_buf *kbuf) { (void)kbuf; return 0; }

/* Endian converters + mem-family come out-of-line under the BPF/gnu89 inline
 * model; provide them (host is little-endian: le* identity, be* byteswap). */
static inline __u16 le16_to_cpu(__u16 v){ return v; }
static inline __u32 le32_to_cpu(__u32 v){ return v; }
static inline __u64 le64_to_cpu(__u64 v){ return v; }
static inline __u16 be16_to_cpu(__u16 v){ return __builtin_bswap16(v); }
static inline __u32 be32_to_cpu(__u32 v){ return __builtin_bswap32(v); }
static inline __u64 be64_to_cpu(__u64 v){ return __builtin_bswap64(v); }
static inline void *memcpy(void *d, const void *s, __kernel_size_t n)
{ unsigned char *dd=d; const unsigned char *ss=s; while(n--) *dd++=*ss++; return d; }
static inline void *memset(void *d, int c, __kernel_size_t n)
{ unsigned char *dd=d; while(n--) *dd++=(unsigned char)c; return d; }
static inline int memcmp(const void *a, const void *b, __kernel_size_t n)
{ const unsigned char *pa=a,*pb=b; while(n--){ if(*pa!=*pb) return (int)*pa-(int)*pb; pa++; pb++; } return 0; }
