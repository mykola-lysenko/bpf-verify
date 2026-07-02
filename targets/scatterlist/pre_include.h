
/* scatterlist.c uses page_address, virt_to_page, etc. Block them. */
#define _LINUX_MM_H
#define _LINUX_HIGHMEM_H
#define _LINUX_PAGEMAP_H
#define _LINUX_VMALLOC_H
#define _LINUX_MM_TYPES_H
#define __LINUX_MM_TYPES_H
#define _LINUX_PAGE_FLAGS_H
#define __LINUX_PAGE_FLAGS_H
#define _LINUX_SLAB_H
#define __LINUX_SLAB_H
#define _LINUX_KMEMLEAK_H
#define __LINUX_KMEMLEAK_H
#define __percpu
/* Block scatterlist.h to avoid sg_dma_address/PAGE_SHIFT issues */
#define _LINUX_SCATTERLIST_H
/* Minimal struct scatterlist for sg_init_table/sg_init_one/sg_nents */
struct scatterlist {
    unsigned long page_link;
    unsigned int offset;
    unsigned int length;
    unsigned long long dma_address;
    unsigned int dma_length;
    unsigned int dma_flags;
};
#define sg_is_chain(sg) ((sg)->page_link & 0x01)
#define sg_is_last(sg)  ((sg)->page_link & 0x02)
#define sg_chain_ptr(sg) ((struct scatterlist *)((sg)->page_link & ~0x03UL))
#define sg_dma_address(sg) ((sg)->dma_address)
#define sg_dma_len(sg) ((sg)->dma_length)
/* folio_page is needed by bvec.h */
#define folio_page(folio, n) (&(folio)->page)
/* PAGE_MASK and PAGE_SHIFT needed by bvec.h */
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))
/* kmap_local_page is needed by bvec.h */
#define kmap_local_page(page) ((void *)(page))
#define kunmap_local(addr) do {} while (0)
#define page_address(p) ((void *)(p))
#define virt_to_page(v) ((struct page *)(v))
/* sg_next is in scatterlist.h which we blocked - provide it here */
static inline struct scatterlist *sg_next(struct scatterlist *sg) {
    if (sg_is_last(sg)) return ((struct scatterlist *)0);
    sg++;
    if (sg_is_chain(sg)) sg = sg_chain_ptr(sg);
    return sg;
}
/* sg_init_table and sg_init_one are in scatterlist.c but need sg_mark_end */
#define sg_mark_end(sg) do { (sg)->page_link |= 0x02; } while (0)
#define sg_chain(prv, nr, sgl) do { (prv)[(nr)-1].page_link = ((unsigned long)(sgl)) | 0x01; } while (0)
/* for_each_sg is in scatterlist.h which we blocked */
#define for_each_sg(sglist, sg, nr, __i) for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))
/* sg_nents_for_dma uses DIV_ROUND_UP - provide it */
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif
/* struct sg_table is needed by scatterlist.c */
struct sg_table { struct scatterlist *sgl; unsigned int nents; unsigned int orig_nents; };
/* dma_unmap_sg_attrs stub */
#define dma_unmap_sg_attrs(dev, sg, nents, dir, attrs) do {} while (0)
#define offset_in_page(v) ((unsigned long)(v) & 0xfff)
#define PAGE_SIZE 4096
#define PageHighMem(p) 0
struct page { unsigned long flags; };
struct folio { struct page page; };
