#ifndef _SHIM_LINUX_UNALIGNED_H
#define _SHIM_LINUX_UNALIGNED_H
#include <string.h>
#include "khost.h"
static inline u16 get_unaligned_le16(const void *p){ u16 v; memcpy(&v,p,2); return v; }
static inline u32 get_unaligned_le32(const void *p){ u32 v; memcpy(&v,p,4); return v; }
static inline u64 get_unaligned_le64(const void *p){ u64 v; memcpy(&v,p,8); return v; }
static inline void put_unaligned_le16(u16 v,void *p){ memcpy(p,&v,2); }
static inline void put_unaligned_le32(u32 v,void *p){ memcpy(p,&v,4); }
#define get_unaligned(p) ({ typeof(*(p)) __v; memcpy(&__v,(p),sizeof(__v)); __v; })
#define put_unaligned(v,p) ({ typeof(*(p)) __v=(v); memcpy((p),&__v,sizeof(__v)); })
#endif
