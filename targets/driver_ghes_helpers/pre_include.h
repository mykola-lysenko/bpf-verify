#include <linux/errno.h>
#define _AER_H_
#define _LINUX_CXL_EVENT_H
#define FW_WARN ""
#define pr_err_ratelimited(fmt, ...) do { } while (0)
#define pr_warn_ratelimited(fmt, ...) do { } while (0)
#ifndef BIT_ULL
#define BIT_ULL(nr) (1ULL << (nr))
#endif

#define PROT_ERR_VALID_AGENT_ADDRESS BIT_ULL(1)
#define PROT_ERR_VALID_SERIAL_NUMBER BIT_ULL(3)
#define PROT_ERR_VALID_ERROR_LOG BIT_ULL(6)
enum {
    RCD,
    RCH_DP,
    DEVICE,
    LD,
    FMLD,
    RP,
    DSP,
    USP,
};

struct cxl_cper_sec_prot_err {
    u64 valid_bits;
    u8 agent_type;
    u8 reserved[7];
    union {
        u64 rcrb_base_addr;
        struct {
            u8 function;
            u8 device;
            u8 bus;
            u16 segment;
            u8 reserved_1[3];
        };
    } agent_addr;
    struct {
        u16 vendor_id;
        u16 device_id;
        u16 subsystem_vendor_id;
        u16 subsystem_id;
        u8 class_code[2];
        u16 slot;
        u8 reserved_1[4];
    } device_id;
    struct {
        u32 lower_dw;
        u32 upper_dw;
    } dev_serial_num;
    u8 capability[60];
    u16 dvsec_len;
    u16 err_len;
    u8 reserved_2[4];
};

struct cxl_ras_capability_regs {
    u32 uncor_status;
    u32 uncor_mask;
    u32 uncor_severity;
    u32 cor_status;
    u32 cor_mask;
    u32 cap_control;
    u32 header_log[16];
};

struct cxl_cper_prot_err_work_data {
    struct cxl_cper_sec_prot_err prot_err;
    struct cxl_ras_capability_regs ras_cap;
    int severity;
};

struct __bpf_ghes_prot_err_record {
    struct cxl_cper_sec_prot_err err;
    u8 dvsec[8];
    struct cxl_ras_capability_regs ras;
};

struct __bpf_ghes_state {
    struct cxl_cper_prot_err_work_data wd;
};

struct {
    __uint(type, 1 /* BPF_MAP_TYPE_ARRAY */);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct __bpf_ghes_state);
} __bpf_ghes_state_map __attribute__((section(".maps"), used));

static __always_inline int cper_severity_to_aer(int severity)
{
    return severity;
}

#define __HAVE_ARCH_MEMCPY
static __always_inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    __kernel_size_t i;

    for (i = 0; i < 256; i++) {
        if (i >= n)
            break;
        d[i] = s[i];
    }

    return dst;
}

#define cxl_cper_sec_prot_err_valid __attribute__((internal_linkage)) cxl_cper_sec_prot_err_valid
#define cxl_cper_setup_prot_err_work_data __attribute__((internal_linkage)) cxl_cper_setup_prot_err_work_data
