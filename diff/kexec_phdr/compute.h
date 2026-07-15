/* kexec_phdr: parse an ELF64 program header via elf_read_phdr() (+ the
 * overflow-checked elf_is_phdr_sane) and fold the endian-decoded fields.
 * Reuses the kexec_elf build config (base); a second differential angle on the
 * same source, stressing the phdr byteswap + bounds arithmetic natively vs BPF.
 *
 * We parse the ehdr first (to populate elf_info->ehdr, which elf_read_phdr
 * reads for class/endianness and e_phoff), point proghdrs at a local slot,
 * then decode phdr[0]. p_offset/p_filesz/p_memsz are seeded but masked small so
 * the segment stays within the 192-byte image and the sanity check's accept
 * path runs; p_type/p_flags/p_vaddr/p_align/p_paddr are seeded freely. */
static __u64 diff_compute(const __u64 in[4])
{
	unsigned char img[192];
	struct elfhdr ehdr;
	struct elf_phdr ph;
	struct kexec_elf_info info;
	unsigned char *p = img + 64;   /* phdr at e_phoff = 64 */
	int i, ret;

	for (i = 0; i < (int)sizeof(img); i++)
		img[i] = 0;
	/* ehdr */
	img[0] = 0x7f; img[1] = 'E'; img[2] = 'L'; img[3] = 'F';
	img[4] = 2; img[5] = 1; img[6] = 1;
	img[16] = 2; img[18] = 62; img[20] = 1;
	img[32] = 64; img[52] = 64; img[54] = 56; img[56] = 1;

	if (elf_read_ehdr((const char *)img, sizeof(img), &ehdr))
		return 0xdead0ULL;
	/* elf_read_phdr locates the phdr at buf + ehdr->e_phoff; the validated
	 * e_phoff is unbounded once reloaded from the parsed struct, so pin it to
	 * the encoded constant (64). This bounds the pointer math without touching
	 * the phdr-field byteswap under test. Identical on both sides. */
	ehdr.e_phoff = 64;

	/* phdr fields (elf64_phdr): type@0 flags@4 offset@8 vaddr@16 paddr@24
	 * filesz@32 memsz@40 align@48 */
	for (i = 0; i < 4; i++) {
		p[0 + i]  = (unsigned char)(in[0] >> (i * 8));  /* p_type */
		p[4 + i]  = (unsigned char)(in[3] >> (i * 8));  /* p_flags */
	}
	p[8]  = (unsigned char)(in[1] & 0x3f);              /* p_offset (<64) */
	p[32] = (unsigned char)(in[2] & 0x3f);              /* p_filesz (<64) */
	p[40] = (unsigned char)(in[2] >> 8);                /* p_memsz */
	for (i = 0; i < 8; i++) {
		p[16 + i] = (unsigned char)(in[0] >> (i * 8));  /* p_vaddr */
		p[24 + i] = (unsigned char)(in[1] >> (i * 8));  /* p_paddr */
		p[48 + i] = (unsigned char)(in[3] >> (i * 8));  /* p_align */
	}

	info.buffer   = (const char *)img;
	info.ehdr     = (const struct elf64_hdr *)&ehdr;
	info.proghdrs = (const struct elf64_phdr *)&ph;

	ret = elf_read_phdr((const char *)img, sizeof(img), &info, 0);
	if (ret)
		return 0xbad00ULL ^ (__u64)(unsigned)ret;

	return (__u64)ph.p_type ^ ((__u64)ph.p_flags << 4) ^
	       ((__u64)ph.p_offset << 8) ^ ((__u64)ph.p_vaddr << 12) ^
	       ((__u64)ph.p_paddr << 16) ^ ((__u64)ph.p_filesz << 20) ^
	       ((__u64)ph.p_memsz << 24) ^ ((__u64)ph.p_align << 28);
}
