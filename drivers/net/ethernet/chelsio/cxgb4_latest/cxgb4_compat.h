/*
 * This file is part of the Chelsio T4 Ethernet driver.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * This file is used to allow the driver to be compiled under multiple
 * versions of Linux with as few obtrusive in-line #ifdef's as possible.
 */

#ifndef __CXGB4_COMPAT_H
#define __CXGB4_COMPAT_H

#include <linux/version.h>
#include <net/inet6_hashtables.h>
#include "common.h"
#include "distro_compat.h"
#include <linux/pci.h>
#if defined(CONFIG_NET_RX_BUSY_POLL)
#include <net/busy_poll.h>
#endif
#ifndef _HAVE_ARCH_IPV6_CSUM
#include <net/ip6_checksum.h>
#endif

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#endif

#ifndef NIPQUAD_FMT
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#ifndef PORT_DA
#define PORT_DA 0x05
#endif
#ifndef PORT_OTHER
#define PORT_OTHER 0xff
#endif

#ifndef VLAN_PRIO_MASK
#define VLAN_PRIO_MASK		0xe000
#endif
#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT		13
#endif

#if defined(ARCH_HAS_IOREMAP_WC)
#define wc_flush() wmb()
#define writel_wc(__v, __a) \
	do { \
		wmb(); /* memory store, WC MMIO store ordering */ \
		__raw_writel((__force u32)cpu_to_le32(__v), __a); \
		wc_flush(); \
	} while (0)
#else
#define wc_flush() do {} while(0)
#define writel_wc(__v, __a) writel(__v, __a)
#endif

#ifndef list_next_entry_circular
#define list_next_entry_circular(pos, head, member) \
	(list_is_last(&(pos)->member, head) ? \
	list_first_entry(head, typeof(*(pos)), member) : list_next_entry(pos, member))
#endif


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0) && \
     LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 8)) || \
     LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 43)
#if IS_ENABLED(CONFIG_VXLAN)
/* Taken from:
 * 94d166c5318c ("vxlan: calculate correct header length for GPE")
 */
static inline int vxlan_headroom(u32 flags)
{
	/* VXLAN:     IP4/6 header + UDP + VXLAN + Ethernet header */
	/* VXLAN-GPE: IP4/6 header + UDP + VXLAN */
	return (flags & VXLAN_F_IPV6 ? sizeof(struct ipv6hdr) :
				       sizeof(struct iphdr)) +
	       sizeof(struct udphdr) + sizeof(struct vxlanhdr) +
	       (flags & VXLAN_F_GPE ? 0 : ETH_HLEN);
}
#endif /* IS_ENABLED(CONFIG_VXLAN) */
#endif

#endif  /* !__CXGB4_COMPAT_H */
