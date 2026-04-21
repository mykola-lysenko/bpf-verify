/* BPF shim: linux/if_ether.h
 * Provides MAC_ADDR_STR_LEN and ETH_ALEN without pulling in skbuff.h
 */
#ifndef _LINUX_IF_ETHER_H
#define _LINUX_IF_ETHER_H

#include <uapi/linux/if_ether.h>

/* XX:XX:XX:XX:XX:XX */
#define MAC_ADDR_STR_LEN (3 * ETH_ALEN - 1)

/* Stub out skb-dependent functions */
struct sk_buff;
static inline void *skb_mac_header(const struct sk_buff *skb) { return NULL; }

#endif /* _LINUX_IF_ETHER_H */
