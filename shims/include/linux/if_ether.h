/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * BPF shim: linux/if_ether.h
 *
 * Keep the real Ethernet header while blocking linux/skbuff.h's deep network
 * dependency chain. The real if_ether.h only needs a small sk_buff surface for
 * its inline header accessors.
 */
#ifndef __BPF_LINUX_IF_ETHER_SHIM_H
#define __BPF_LINUX_IF_ETHER_SHIM_H

#ifndef SKB_ALLOC_FCLONE
#ifndef _LINUX_SKBUFF_H
#define _LINUX_SKBUFF_H
#endif

struct sk_buff {
	unsigned char *data;
};

static inline void *skb_mac_header(const struct sk_buff *skb)
{
	return skb->data;
}

#define skb_inner_mac_header skb_mac_header
#endif

struct net_device;

#include_next <linux/if_ether.h>

#endif /* __BPF_LINUX_IF_ETHER_SHIM_H */
