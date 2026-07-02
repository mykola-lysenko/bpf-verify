#define __CXGB4_H__
#define __CUDBG_IF_H__
#define __CUDBG_LIB_COMMON_H__
#ifndef NULL
#define NULL ((void *)0)
#endif

#define CUDBG_STATUS_NO_MEM -19
struct adapter;
struct cudbg_init {
    struct adapter *adap;
    void *outbuf;
    u32 outbuf_size;
    u8 compress_type;
    void *compress_buff;
    u32 compress_buff_size;
    void *workspace;
};

enum cudbg_compression_type {
    CUDBG_COMPRESSION_NONE = 1,
    CUDBG_COMPRESSION_ZLIB,
};

struct cudbg_buffer {
    u32 size;
    u32 offset;
    char *data;
};

#define __HAVE_ARCH_MEMSET
static __always_inline void *memset(void *dst, int c, __kernel_size_t n)
{
    unsigned char *d = dst;
    __kernel_size_t i;

    for (i = 0; i < 256; i++) {
        if (i >= n)
            break;
        d[i] = (unsigned char)c;
    }

    return dst;
}

#define cudbg_get_buff __attribute__((internal_linkage)) cudbg_get_buff
#define cudbg_put_buff __attribute__((internal_linkage)) cudbg_put_buff
#define cudbg_update_buff __attribute__((internal_linkage)) cudbg_update_buff
