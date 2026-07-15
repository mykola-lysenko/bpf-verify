    /* kexec_elf: exercise elf_read_ehdr() -- magic/class/version validation,
     * per-field endian-converting header parse, and elf_is_ehdr_sane's
     * overflow-checked size arithmetic -- on a crafted ELF64 image whose
     * numeric fields are map-seeded (entry point, shoff, flags, phnum), so
     * both the accept and reject paths stay live across fuzzed inputs.
     *
     * Property (BPF_ASSERT): parse consistency -- when the parser accepts,
     * the fields it decoded must equal what the image encodes (machine,
     * phentsize, and the constant-written phnum). execute:true fuzzes this
     * per iteration (0 = pass). */
    __u32 k0 = 0, k1 = 1;
    __u64 *sa = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *sb = bpf_map_lookup_elem(&input_map, &k1);
    __u64 seeda = sa ? *sa : 0x1122334455667788ULL;
    __u64 seedb = sb ? *sb : 0x0123456789abcdefULL;

    unsigned char *p = __bpf_kelf.img;
    int i;
    #pragma clang loop unroll(disable)
    for (i = 0; i < (int)sizeof(__bpf_kelf.img); i++)
        p[i] = 0;

    /* e_ident */
    p[0] = 0x7f; p[1] = 'E'; p[2] = 'L'; p[3] = 'F';
    p[4] = 2;   /* ELFCLASS64 */
    p[5] = 1;   /* ELFDATA2LSB */
    p[6] = 1;   /* EV_CURRENT */
    /* e_type = ET_EXEC, e_machine = EM_X86_64, e_version = 1 */
    p[16] = 2; p[18] = 62; p[20] = 1;
    /* e_entry (u64) and e_shoff (u64): map-seeded */
    #pragma clang loop unroll(disable)
    for (i = 0; i < 8; i++) {
        p[24 + i] = (unsigned char)(seeda >> (i * 8));
        p[40 + i] = (unsigned char)(seedb >> (i * 8));
    }
    /* e_phoff = 64 (right after the ehdr) */
    p[32] = 64;
    /* e_flags seeded (u32) */
    p[48] = (unsigned char)seeda; p[49] = (unsigned char)(seeda >> 8);
    /* e_ehsize = 64, e_phentsize = 56, e_phnum = 1 */
    p[52] = 64; p[54] = 56; p[56] = 1;

    struct elfhdr ehdr;
    int ret = elf_read_ehdr((const char *)p, sizeof(__bpf_kelf.img), &ehdr);

    if (ret == 0) {
        BPF_ASSERT(ehdr.e_machine == 62);
        BPF_ASSERT(ehdr.e_phentsize == 56);
        BPF_ASSERT(ehdr.e_phnum == 1);
    }

    return 0;
