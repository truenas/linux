/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4_L2T_H
#define __CXGB4_L2T_H

#include <linux/spinlock.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <asm/atomic.h>
#include "cxgb4_ctl_defs.h"


enum { L2T_SIZE = 4096 };     /* # of L2T entries */

enum {
	L2T_STATE_VALID,      /* entry is up to date */
	L2T_STATE_STALE,      /* entry may be used but needs revalidation */
	L2T_STATE_RESOLVING,  /* entry needs address resolution */
	L2T_STATE_SYNC_WRITE, /* synchronous write of entry underway */

	/* when state is one of the below the entry is not hashed */
	L2T_STATE_SWITCHING,  /* entry is being used by a switching filter */
	L2T_STATE_UNUSED      /* entry not in use */
};

struct adapter;
struct l2t_data;
struct neighbour;
struct file_operations;
struct cpl_l2t_write_rpl;

/*
 * Each L2T entry plays multiple roles.  First of all, it keeps state for the
 * corresponding entry of the HW L2 table and maintains a queue of offload
 * packets awaiting address resolution.  Second, it is a node of a hash table
 * chain, where the nodes of the chain are linked together through their next
 * pointer.  Finally, each node is a bucket of a hash table, pointing to the
 * first element in its chain through its first pointer.
 */
struct l2t_entry {
	u16 state;                  /* entry state */
	u16 idx;                    /* entry index within in-memory table */
	u32 addr[4];                /* next hop IP or IPv6 address */
	int ifindex;                /* neighbor's net_device's ifindex */
	struct neighbour *neigh;    /* associated neighbour */
	struct l2t_entry *first;    /* start of hash chain */
	struct l2t_entry *next;     /* next l2t_entry on chain */
	struct sk_buff_head arpq;   /* packet queue awaiting resolution */
	spinlock_t lock;
	atomic_t refcnt;            /* entry reference count */
	u16 hash;                   /* hash bucket the entry is on */
	u16 vlan;                   /* VLAN TCI (id: bits 0-11, prio: 13-15 */
	u8 v6;                      /* whether entry is for IPv6 */
	u8 lport;                   /* associated offload logical interface */
	u8 dmac[ETH_ALEN];          /* neighbour's MAC address */
	u8 orig_lport;
};

typedef void (*arp_err_handler_t)(void *handle, struct sk_buff *skb);

/*
 * Callback stored in an skb to handle address resolution failure.
 */
struct l2t_skb_cb {
	void *handle;
	arp_err_handler_t arp_err_handler;
};

#define L2T_SKB_CB(skb) ((struct l2t_skb_cb *)(skb)->cb)

static inline void t4_set_arp_err_handler(struct sk_buff *skb, void *handle,
					  arp_err_handler_t handler)
{
	L2T_SKB_CB(skb)->handle = handle;
	L2T_SKB_CB(skb)->arp_err_handler = handler;
}

#define L2T_LPBK	true
#define L2T_ARPMISS	true
#define L2T_INVALID_IP	0x1000000
#define L2T_INVALID_IP_STR	"0.0.0.1"

void cxgb4_l2t_release(struct l2t_entry *e);
int cxgb4_l2t_send(struct net_device *dev, struct sk_buff *skb,
		   struct l2t_entry *e);
struct l2t_entry *cxgb4_l2t_get(struct l2t_data *d, struct neighbour *neigh,
				const struct net_device *physdev , u32 priority);
struct l2t_entry *cxgb4_l2t_alloc_switching(struct net_device *dev, u16 vlan,
					    u8 port, u8 *dmac);
struct l2t_entry *cxgb4_lookup_l2te(struct net_device *dev, u16 vlan, u8 port,
				    u8 *dmac);
void t4_l2t_update(struct adapter *adap, struct neighbour *neigh);
struct l2t_entry *t4_l2t_alloc_switching(struct adapter *adap, u16 vlan, u8 port,
					 u8 *dmac);
struct l2t_data *t4_init_l2t(unsigned int l2t_start, unsigned int l2t_end);
int t4_reset_l2t(struct l2t_data *d);
void t4_flush_l2t_arpq(struct l2t_data *d);
void do_l2t_write_rpl(struct adapter *p, const struct cpl_l2t_write_rpl *rpl);

int t4_bond_port_disable(struct net_device *dev, bool flag,
					struct bond_ports *bond_ports);
int t4_ports_failover(struct net_device *dev, int event,
                              struct bond_ports *bond_ports, struct l2t_data *d,
			      int loopback);
int t4_l2t_write(struct adapter *adap, struct l2t_entry *e, bool arpmiss);
u64 cxgb4_select_ntuple(struct net_device *dev,
				 const struct l2t_entry *l2t, u16 ipsecidx);
extern const struct file_operations t4_l2t_debugfs_fops;
struct net_device *cxgb4_get_ringbb_egress(struct net_device *dev);
#endif  /* __CXGB4_L2T_H */
