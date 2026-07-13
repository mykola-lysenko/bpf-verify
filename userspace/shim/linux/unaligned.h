#ifndef _SHIM_LINUX_UNALIGNED_H
#define _SHIM_LINUX_UNALIGNED_H
#include <string.h>
#include "khost.h"
static inline u16 get_unaligned_le16(const void *p){ u16 v; memcpy(&v,p,2); return v; }
static inline u32 get_unaligned_le32(const void *p){ u32 v; memcpy(&v,p,4); return v; }
static inline u64 get_unaligned_le64(const void *p){ u64 v; memcpy(&v,p,8); return v; }
static inline void put_unaligned_le16(u16 v,void *p){ memcpy(p,&v,2); }
static inline void put_unaligned_le32(u32 v,void *p){ memcpy(p,&v,4); }
static inline void put_unaligned_le64(u64 v,void *p){ memcpy(p,&v,8); }
static inline u16 get_unaligned_be16(const void *p){ u16 v; memcpy(&v,p,2); return __builtin_bswap16(v); }
static inline u32 get_unaligned_be32(const void *p){ u32 v; memcpy(&v,p,4); return __builtin_bswap32(v); }
static inline u64 get_unaligned_be64(const void *p){ u64 v; memcpy(&v,p,8); return __builtin_bswap64(v); }
static inline void put_unaligned_be16(u16 v,void *p){ v=__builtin_bswap16(v); memcpy(p,&v,2); }
static inline void put_unaligned_be32(u32 v,void *p){ v=__builtin_bswap32(v); memcpy(p,&v,4); }
static inline void put_unaligned_be64(u64 v,void *p){ v=__builtin_bswap64(v); memcpy(p,&v,8); }
#define get_unaligned(p) ({ typeof(*(p)) __v; memcpy(&__v,(p),sizeof(__v)); __v; })
#define put_unaligned(v,p) ({ typeof(*(p)) __v=(v); memcpy((p),&__v,sizeof(__v)); })
#endif
