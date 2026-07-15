/* kexec_elf: parse a crafted ELF64 header via elf_read_ehdr (static in the
 * source, callable at file scope) and fold the endian-decoded fields.
 * Byteswap + fixed-layout parse codegen -- native vs BPF. e_entry / e_shoff /
 * e_flags are seeded so the decode stays live; phoff/ehsize/phentsize/phnum
 * are fixed so the header passes the sanity checks and the accept path runs. */
static __u64 diff_compute(const __u64 in[4])
{
	unsigned char img[192];
	struct elfhdr ehdr;
	int i, ret;

	for (i = 0; i < (int)sizeof(img); i++)
		img[i] = 0;
	img[0] = 0x7f; img[1] = 'E'; img[2] = 'L'; img[3] = 'F';
	img[4] = 2; img[5] = 1; img[6] = 1;          /* class64, LSB, EV_CURRENT */
	img[16] = 2; img[18] = 62; img[20] = 1;      /* ET_EXEC, EM_X86_64, v1 */
	for (i = 0; i < 8; i++) {
		img[24 + i] = (unsigned char)(in[0] >> (i * 8));  /* e_entry */
		img[40 + i] = (unsigned char)(in[1] >> (i * 8));  /* e_shoff */
	}
	img[32] = 64;                                /* e_phoff */
	img[48] = (unsigned char)in[2];              /* e_flags */
	img[49] = (unsigned char)(in[2] >> 8);
	img[52] = 64; img[54] = 56; img[56] = 1;     /* ehsize, phentsize, phnum */

	ret = elf_read_ehdr((const char *)img, sizeof(img), &ehdr);
	if (ret)
		return 0xdeadULL ^ (__u64)(unsigned)ret;

	return (__u64)ehdr.e_entry ^ ((__u64)ehdr.e_shoff << 1) ^
	       ((__u64)ehdr.e_flags << 3) ^ ((__u64)ehdr.e_machine << 32) ^
	       ((__u64)ehdr.e_phnum << 40) ^ ((__u64)ehdr.e_phentsize << 48);
}
