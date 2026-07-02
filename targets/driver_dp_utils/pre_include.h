#define _DP_UTILS_H_
struct dp_sdp_header {
    u8 HB0;
    u8 HB1;
    u8 HB2;
    u8 HB3;
} __packed;

#define HEADER_0_MASK 0x000000ffU
#define PARITY_0_MASK 0x0000ff00U
#define HEADER_1_MASK 0x00ff0000U
#define PARITY_1_MASK 0xff000000U
#define HEADER_2_MASK 0x000000ffU
#define PARITY_2_MASK 0x0000ff00U
#define HEADER_3_MASK 0x00ff0000U
#define PARITY_3_MASK 0xff000000U
#ifndef FIELD_PREP
#define FIELD_PREP(_mask, _val) ((((u32)(_val)) << __builtin_ctz((unsigned int)(_mask))) & (_mask))
#endif

