/* The crafted ELF image: 64-byte ehdr + two 56-byte phdr slots. Global area
 * (map-backed) rather than harness stack. */
static struct {
	unsigned char img[192];
} __bpf_kelf;
