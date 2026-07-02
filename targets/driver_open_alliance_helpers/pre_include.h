#include <linux/errno.h>
#define _LINUX_BITFIELD_H
#define _LINUX_ETHTOOL_NETLINK_H_
#define _UAPI_LINUX_ETHTOOL_NETLINK_H_
#ifndef GENMASK
#define GENMASK(h, l) (((~0U) - ((1U << (l)) - 1)) & (~0U >> (31 - (h))))
#endif
#define FIELD_GET(_mask, _reg) (((u32)(_reg) & (u32)(_mask)) >> __builtin_ctz((unsigned int)(_mask)))
enum {
    ETHTOOL_A_CABLE_RESULT_CODE_UNSPEC,
    ETHTOOL_A_CABLE_RESULT_CODE_OK,
    ETHTOOL_A_CABLE_RESULT_CODE_OPEN,
    ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT,
    ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT,
    ETHTOOL_A_CABLE_RESULT_CODE_IMPEDANCE_MISMATCH,
    ETHTOOL_A_CABLE_RESULT_CODE_NOISE,
    ETHTOOL_A_CABLE_RESULT_CODE_RESOLUTION_NOT_POSSIBLE,
};

#define oa_1000bt1_get_ethtool_cable_result_code __attribute__((__noinline__)) oa_1000bt1_get_ethtool_cable_result_code
#define oa_1000bt1_get_tdr_distance __attribute__((__noinline__)) oa_1000bt1_get_tdr_distance
