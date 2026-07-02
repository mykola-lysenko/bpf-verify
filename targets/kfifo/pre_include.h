
/* kfifo shim only needs minimal stubs */
/* Block scatterlist.h to avoid redefinition of struct scatterlist */
#define _LINUX_SCATTERLIST_H
typedef unsigned int gfp_t;
/* Minimal struct scatterlist for kfifo DMA function declarations */
struct scatterlist {
    unsigned long page_link;
    unsigned int offset;
    unsigned int length;
    unsigned long long dma_address;
    unsigned int dma_length;
    unsigned int dma_flags;
};
/* dma_addr_t is defined in linux/types.h */
/* virt_to_page needed by dma-mapping.h */
#define virt_to_page(addr) ((struct page *)(addr))
#define page_to_virt(page) ((void *)(page))
#define GFP_KERNEL 0
/* Stub out DMA functions that have too many args (> 5, not BPF-compatible) */
#define __kfifo_dma_in_prepare_r(fifo, sgl, nents, len, recsize, dma) (0U)
#define __kfifo_dma_in_finish_r(fifo, len, recsize, dma) do {} while (0)
#define __kfifo_dma_out_prepare_r(fifo, sgl, nents, len, recsize) (0U)
#define __kfifo_dma_out_finish_r(fifo, len, recsize) do {} while (0)
/* Block kfifo.h DMA declarations by renaming the functions */
/* These are renamed via EXTRA_CFLAGS -D flags to avoid macro/declaration conflicts */
/* kfifo uses memcpy as an extern. Provide a static inline definition
 * so it has BTF and no unresolved extern reference. */
#undef noinline
static __attribute__((noinline)) void *bpf_kfifo_memcpy(
        void *dst, const void *src, __kernel_size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}
#undef memcpy
#define memcpy(dst, src, n) bpf_kfifo_memcpy(dst, src, n)
