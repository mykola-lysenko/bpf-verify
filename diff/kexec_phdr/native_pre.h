/* Native-side pre-source shim for kexec_elf.c (BPF side gets the equivalent
 * from targets/kexec_elf/pre_include.h; khost.h already provides the endian
 * converters + memcpy/memset, so only the kexec/ELF surface is here). */
#define _LINUX_KEXEC_H
#define LINUX_KEXEC_H
#define _ASM_X86_ELF_H
#define _LINUX_ELF_H          /* block linux/elf.h (pulls host-absent asm/elf.h) */
#include <linux/errno.h>
#include <linux/types.h>
#include <stdint.h>
/* uapi/linux/elf.h uses the __sNN spellings; the host shim only has sNN. */
typedef int16_t __s16; typedef int32_t __s32; typedef int64_t __s64;
#include <uapi/linux/elf.h>
/* the elfhdr/elf_phdr aliases linux/elf.h would provide (ELF_CLASS==64) */
#define elfhdr    elf64_hdr
#define elf_phdr  elf64_phdr
#define elf_note  elf64_note
#define elf_shdr  elf64_shdr
#define elf_addr_t Elf64_Off
#ifndef ELF_CLASS
#define ELF_CLASS ELFCLASS64
#define ELF_DATA  ELFDATA2LSB
#define ELF_ARCH  EM_X86_64
#endif
#ifndef elf_check_arch
#define elf_check_arch(x) ((x)->e_machine == EM_X86_64)
#endif
#define KEXEC_BUF_MEM_UNKNOWN 0
struct kexec_elf_info {
	const char *buffer;
	const struct elf64_hdr *ehdr;
	const struct elf64_phdr *proghdrs;
};
struct kexec_buf {
	void *image; void *buffer;
	unsigned long bufsz, mem, memsz, buf_align, buf_min, buf_max;
	int top_down;
};
static inline int kexec_add_buffer(struct kexec_buf *kbuf) { (void)kbuf; return 0; }
