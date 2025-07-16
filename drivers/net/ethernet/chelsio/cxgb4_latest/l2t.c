/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (c) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include <net/neighbour.h>
#include <net/dst.h>
#include "common.h"
#include "l2t.h"
#include "t4_msg.h"
#include "t4fw_interface.h"
#include "cxgb4_ofld.h"
#include "t4_regs.h"
#ifdef BOND_SUPPORT
#include <net/bonding.h>
#include <net/bond_3ad.h>
#endif

/* identifies sync vs async L2T_WRITE_REQs */
#define S_SYNC_WR    12
#define V_SYNC_WR(x) ((x) << S_SYNC_WR)
#define F_SYNC_WR    V_SYNC_WR(1)

struct l2t_data {
	unsigned int l2t_start;     /* start index of our piece of the L2T */
	unsigned int l2t_size;      /* number of entries in l2tab */
	rwlock_t lock;
	atomic_t nfree;             /* number of free entries */
	struct l2t_entry *rover;    /* starting point for next allocation */
	struct l2t_entry l2tab[];  /* MUST BE LAST */
};

/*
 * Module locking notes:  There is a RW lock protecting the L2 table as a
 * whole plus a spinlock per L2T entry.  Entry lookups and allocations happen
 * under the protection of the table lock, individual entry changes happen
 * while holding that entry's spinlock.  The table lock nests outside the
 * entry locks.  Allocations of new entries take the table lock as writers so
 * no other lookups can happen while allocating new entries.  Entry updates
 * take the table lock as readers so multiple entries can be updated in
 * parallel.  An L2T entry can be dropped by decrementing its reference count
 * and therefore can happen in parallel with entry allocation but no entry
 * can change state or increment its ref count during allocation as both of
 * these perform lookups.
 *
 * Note: We do not take refereces to net_devices in this module because both
 * the TOE and the sockets already hold references to the interfaces and the
 * lifetime of an L2T entry is fully contained in the lifetime of the TOE.
 */

static inline unsigned int vlan_prio(const struct l2t_entry *e)
{
	return (e->vlan & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
}

static inline void l2t_hold(struct l2t_data *d, struct l2t_entry *e)
{
	if (atomic_add_return(1, &e->refcnt) == 1)  /* 0 -> 1 transition */
		atomic_dec(&d->nfree);
}

/*
 * To avoid having to check address families we do not allow v4 and v6
 * neighbors to be on the same hash chain.  We keep v4 entries in the first
 * half of available hash buckets and v6 in the second.  We need at least two
 * entries in our L2T for this scheme to work.
 */
enum {
	L2T_MIN_HASH_BUCKETS = 2,
};

static inline unsigned int arp_hash(struct l2t_data *d, const u32 *key,
				    int ifindex)
{
	unsigned int l2t_size_half = d->l2t_size / 2;

	return jhash_2words(*key, ifindex, 0) % l2t_size_half;
}

static inline unsigned int ipv6_hash(struct l2t_data *d,const u32 *key,
				     int ifindex)
{
	unsigned int l2t_size_half = d->l2t_size / 2;
	u32 xor = key[0] ^ key[1] ^ key[2] ^ key[3];

	return (l2t_size_half +
		(jhash_2words(xor, ifindex, 0) % l2t_size_half));
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static unsigned int addr_hash(struct l2t_data *d, const u32 *addr,
			      int addr_len, int ifindex)
{
	return addr_len == 4 ? arp_hash(d, addr, ifindex) :
			       ipv6_hash(d, addr, ifindex);
}
#endif

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
/*
 * Checks if an L2T entry is for the given IP/IPv6 address.  It does not check
 * whether the L2T entry and the address are of the same address family.
 * Callers ensure an address is only checked against L2T entries of the same
 * family, something made trivial by the separation of IP and IPv6 hash chains
 * mentioned above.  Returns 0 if there's a match,
 */
static int addreq(const struct l2t_entry *e, const u32 *addr)
{
	if (e->v6)
		return (e->addr[0] ^ addr[0]) | (e->addr[1] ^ addr[1]) |
		       (e->addr[2] ^ addr[2]) | (e->addr[3] ^ addr[3]);
	return e->addr[0] ^ addr[0];
}

static void neigh_replace(struct l2t_entry *e, struct neighbour *n)
{
	neigh_hold(n);
	if (e->neigh)
		neigh_release(e->neigh);
	e->neigh = n;
}
#endif

/*
 * Write an L2T entry.  Must be called with the entry locked.
 * The write may be synchronous or asynchronous.
 */
static int write_l2e(struct adapter *adap, struct l2t_entry *e, int sync,
		     bool loopback, bool arpmiss)
{
	struct l2t_data *d = adap->l2t;
	unsigned int l2t_idx = e->idx + d->l2t_start;
	struct cpl_l2t_write_req sreq, *req = &sreq;
	int i;

	INIT_TP_WR(req, 0);

	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_L2T_WRITE_REQ,
					l2t_idx | V_SYNC_WR(sync) |
					V_TID_QID(adap->sge.fw_evtq.abs_id)));
	req->params = htons(V_L2T_W_PORT(e->lport) | V_L2T_W_LPBK(loopback) |
			    V_L2T_W_ARPMISS(arpmiss) | V_L2T_W_NOREPLY(!sync));
	req->l2t_idx = htons(l2t_idx);
	req->vlan = htons(e->vlan);
	if (e->neigh && !(e->neigh->dev->flags & IFF_LOOPBACK))
		memcpy(e->dmac, e->neigh->ha, sizeof(e->dmac));
	memcpy(req->dst_mac, e->dmac, sizeof(req->dst_mac));

	if (loopback) {
		for (i = 0; i < ETH_ALEN; i++)
			req->dst_mac[i] = 0;
	}

	if (t4_mgmt_tx_direct(adap, req, sizeof(*req)))
		return -ENOMEM;

	if (sync && e->state != L2T_STATE_SWITCHING)
		e->state = L2T_STATE_SYNC_WRITE;
	return 0;
}

/*
 * Send packets waiting in an L2T entry's ARP queue.  Must be called with the
 * entry locked.
 */
static void send_pending(struct adapter *adap, struct l2t_entry *e)
{
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&e->arpq)) != NULL)
		cxgb4_uld_xmit(adap->port[0], skb);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
}

/*
 * Process a CPL_L2T_WRITE_RPL.  Wake up the ARP queue if it completes a
 * synchronous L2T_WRITE.  Note that the TID in the reply is really the L2T
 * index it refers to.
 */
void do_l2t_write_rpl(struct adapter *adap, const struct cpl_l2t_write_rpl *rpl)
{
	struct l2t_data *d = adap->l2t;
	unsigned int tid = GET_TID(rpl);
	unsigned int l2t_idx = tid % L2T_SIZE;

	if (unlikely(rpl->status != CPL_ERR_NONE)) {
		CH_ERR(adap,
			"Unexpected L2T_WRITE_RPL status %u for entry %u\n",
			rpl->status, l2t_idx);
		return;
	}

	if (tid & F_SYNC_WR) {
		struct l2t_entry *e = &d->l2tab[l2t_idx - d->l2t_start];

		spin_lock(&e->lock);
		if (e->state != L2T_STATE_SWITCHING) {
			send_pending(adap, e);
			e->state = (e->neigh->nud_state & NUD_STALE) ?
					L2T_STATE_STALE : L2T_STATE_VALID;
		}
		spin_unlock(&e->lock);
	}
}
#ifdef CONFIG_CHELSIO_T4_OFFLOAD

/*
 * Add a packet to an L2T entry's queue of packets awaiting resolution.
 * Must be called with the entry's lock held.
 */
static inline void arpq_enqueue(struct l2t_entry *e, struct sk_buff *skb)
{
	__skb_queue_tail(&e->arpq, skb);
}

static void handle_failed_resolution(struct adapter *adap, struct l2t_entry *e);

/*
 * Write the sync l2e entry.  If it fails then drop all the queued
 * skbs in the l2t entry.
 */
static void write_sync_l2e(struct adapter *adap, struct l2t_entry *e)
{
	if (write_l2e(adap, e, 1, !L2T_LPBK, !L2T_ARPMISS))
		handle_failed_resolution(adap, e);
}

int cxgb4_l2t_send(struct net_device *dev, struct sk_buff *skb,
		   struct l2t_entry *e)
{
	struct adapter *adap = netdev2adap(dev);

again:
	switch (e->state) {
	case L2T_STATE_STALE:     /* entry is stale, kick off revalidation */
		neigh_event_send(e->neigh, NULL);
		spin_lock_bh(&e->lock);
		if (e->state == L2T_STATE_STALE)
			e->state = L2T_STATE_VALID;
		spin_unlock_bh(&e->lock);
		fallthrough; /* fallthrough */
	case L2T_STATE_VALID:     /* fast-path, send the packet on */
		return cxgb4_uld_xmit(dev, skb);
	case L2T_STATE_RESOLVING:
	case L2T_STATE_SYNC_WRITE:
		spin_lock_bh(&e->lock);
		if (e->state != L2T_STATE_SYNC_WRITE &&
		    e->state != L2T_STATE_RESOLVING) {
			/* ARP already completed */
			spin_unlock_bh(&e->lock);
			goto again;
		}
		arpq_enqueue(e, skb);
		spin_unlock_bh(&e->lock);

		/*
		 * Only the first packet added to the arpq should kick off
		 * resolution.  However, because skb allocation can fail,
		 * we allow each packet added to the arpq to retry resolution
		 * as a way of recovering from transient memory exhaustion.
		 * A better way would be to use a work request to retry L2T
		 * entries when there's no memory.
		 */
		if (e->state == L2T_STATE_RESOLVING) {
			if (!neigh_event_send(e->neigh, NULL)) {
				spin_lock_bh(&e->lock);
				if (e->state == L2T_STATE_RESOLVING &&
				    !skb_queue_empty(&e->arpq))
					write_sync_l2e(adap, e);
				spin_unlock_bh(&e->lock);
			}
		}
	}
	return 0;
}
EXPORT_SYMBOL(cxgb4_l2t_send);

/*
 * Allocate a free L2T entry.  Must be called with l2t_data.lock held.
 */
static struct l2t_entry *alloc_l2e(struct l2t_data *d)
{
	struct l2t_entry *end, *e, **p;

	if (!atomic_read(&d->nfree))
		return NULL;

	/* there's definitely a free entry */
	for (e = d->rover, end = &d->l2tab[d->l2t_size]; e != end; ++e)
		if (atomic_read(&e->refcnt) == 0)
			goto found;

	for (e = d->l2tab; atomic_read(&e->refcnt); ++e)
		;
found:
	d->rover = e + 1;
	atomic_dec(&d->nfree);

	/*
	 * The entry we found may be an inactive entry that is
	 * presently in the hash table.  We need to remove it.
	 */
	if (e->state < L2T_STATE_SWITCHING)
		for (p = &d->l2tab[e->hash].first; *p; p = &(*p)->next)
			if (*p == e) {
				*p = e->next;
				e->next = NULL;
				break;
			}

	e->state = L2T_STATE_UNUSED;
	return e;
}
#endif

static struct l2t_entry *find_or_alloc_l2e(struct l2t_data *d, u16 vlan,
					   u8 port, u8 *dmac)
{
	struct l2t_entry *end, *e, **p;
	struct l2t_entry *first_free = NULL;

	for (e = &d->l2tab[0], end = &d->l2tab[d->l2t_size]; e != end; ++e)
	{
		if (atomic_read(&e->refcnt) == 0) {
			if (!first_free)
				first_free = e;
		} else {
			if (e->state == L2T_STATE_SWITCHING) {
				if ((memcmp(e->dmac, dmac, ETH_ALEN) == 0) &&
				    (e->vlan == vlan) && (e->lport == port))
					goto exists;
			}
		}
	}

	if (first_free) {
		e = first_free;
		goto found;
	}

	return NULL;

found:
	/*
	 * The entry we found may be an inactive entry that is
	 * presently in the hash table.  We need to remove it.
	 */
	if (e->state < L2T_STATE_SWITCHING)
		for (p = &d->l2tab[e->hash].first; *p; p = &(*p)->next)
			if (*p == e) {
				*p = e->next;
				e->next = NULL;
				break;
			}
	e->state = L2T_STATE_UNUSED;

exists:
	return e;
}

struct l2t_entry *cxgb4_lookup_l2te(struct net_device *dev, u16 vlan, u8 port,
				    u8 *dmac)
{
	struct adapter *adap = netdev2adap(dev);
	struct l2t_data *d = adap->l2t;
	struct l2t_entry *e, *end;

	for (e = &d->l2tab[0], end = &d->l2tab[d->l2t_size]; e != end; ++e) {
		if ((memcmp(e->dmac, dmac, ETH_ALEN) == 0) &&
		    (e->vlan == vlan) && (e->lport == port))
			goto found;
	}

	return NULL;

found:
	return e;
}
EXPORT_SYMBOL(cxgb4_lookup_l2te);

/*
 * Called when an L2T entry has no more users.  The entry is left in the hash
 * table since it is likely to be reused but we also bump nfree to indicate
 * that the entry can be reallocated for a different neighbor.  We also drop
 * the existing neighbor reference in case the neighbor is going away and is
 * waiting on our reference.
 *
 * Because entries can be reallocated to other neighbors once their ref count
 * drops to 0 we need to take the entry's lock to avoid races with a new
 * incarnation.
 */
static void _t4_l2e_free(struct l2t_entry *e)
{
	struct l2t_data *d;

	if (atomic_read(&e->refcnt) == 0) {  /* hasn't been recycled */
		if (e->neigh) {
			neigh_release(e->neigh);
			e->neigh = NULL;
		}
		/*
		 * Don't need to worry about the arpq, an L2T entry can't be
		 * released if any packets are waiting for resolution as we
		 * need to be able to communicate with the device to close a
		 * connection.
		 */
	}

	d = container_of(e, struct l2t_data, l2tab[e->idx]);
	atomic_inc(&d->nfree);
}

/* Locked version of _t4_l2t_free */
static void t4_l2e_free(struct l2t_entry *e)
{
	struct l2t_data *d;

	spin_lock_bh(&e->lock);
	if (atomic_read(&e->refcnt) == 0) {  /* hasn't been recycled */
		if (e->neigh) {
			neigh_release(e->neigh);
			e->neigh = NULL;
		}
		/*
		 * Don't need to worry about the arpq, an L2T entry can't be
		 * released if any packets are waiting for resolution as we
		 * need to be able to communicate with the device to close a
		 * connection.
		 */
	}
	spin_unlock_bh(&e->lock);

	d = container_of(e, struct l2t_data, l2tab[e->idx]);
	atomic_inc(&d->nfree);
}

void cxgb4_l2t_release(struct l2t_entry *e)
{
	if (atomic_dec_and_test(&e->refcnt))
		t4_l2e_free(e);
}
EXPORT_SYMBOL(cxgb4_l2t_release);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
/*
 * Update an L2T entry that was previously used for the same next hop as neigh.
 * Must be called with softirqs disabled.
 */
static void reuse_entry(struct l2t_entry *e, struct neighbour *neigh)
{
	unsigned int nud_state;

	spin_lock(&e->lock);                /* avoid race with t4_l2t_free */
	if (neigh != e->neigh)
		neigh_replace(e, neigh);
	nud_state = neigh->nud_state;
	if (memcmp(e->dmac, neigh->ha, sizeof(e->dmac)) ||
	    !(nud_state & NUD_VALID))
		e->state = L2T_STATE_RESOLVING;
	else if (nud_state & NUD_CONNECTED)
		e->state = L2T_STATE_VALID;
	else
		e->state = L2T_STATE_STALE;
	spin_unlock(&e->lock);
}

static inline int in_bond(int port, struct bond_ports *bond_ports)
{
	int i;

	for (i = 0; i < bond_ports->nports; i++)
		if (port ==  bond_ports->ports[i])
			break;

	return (i < bond_ports->nports);
}

int t4_bond_port_disable(struct net_device *dev, bool flag,
				struct bond_ports *bond_ports)
{
	struct adapter *adapter = netdev2adap(dev);
	struct port_info *pi = adap2pinfo(adapter, bond_ports->port);
	int ret;

	/*
	 * Enabling a Virtual Interface can result in an interrupt during the
	 * processing of the VI Enable command and, in some paths, result in
	 * an attempt to issue another command in the interrupt context.
	 * Thus, we disable interrupts during the course of the VI Enable
	 * command ...
	 */

	if (flag)
		local_bh_disable();
	ret = t4_enable_pi_params(adapter, adapter->mbox, pi,
				  flag, flag, false);
	if (flag)
		local_bh_enable();
	return ret;
}
EXPORT_SYMBOL(t4_bond_port_disable);
#endif

int t4_l2t_write(struct adapter *adap, struct l2t_entry *e, bool arpmiss)
{
       write_l2e(adap, e, 0, !L2T_LPBK, arpmiss);
       return 0;

}
EXPORT_SYMBOL(t4_l2t_write);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
int t4_ports_failover(struct net_device *dev, int event,
		      struct bond_ports *bond_ports, struct l2t_data *d,
		      int loopback)
{
	int port = bond_ports->port, i;
	struct adapter *adap = netdev2adap(dev);
	struct net_device *bond_dev = netdev_master_upper_dev_get_rcu(bond_ports->slave_dev);
	struct l2t_entry *e;
	int nports = 0, port_idx;

	/* Reassign L2T entries */
	switch (event) {
		case FAILOVER_PORT_RELEASE:
		case FAILOVER_PORT_DOWN:
			read_lock_bh(&d->lock);
			port_idx = 0;
			nports = bond_ports->nports;
			for ( i = 0 ; i < d->l2t_size;  ++i) {
				for (e = d->l2tab[i].first; e; e = e->next) {
					int newport;

					if (e->lport == port && nports) {
						newport = bond_ports->ports
								[port_idx];
						spin_lock(&e->lock);
						e->lport = newport;
						write_l2e(adap, e, 0,
							  !L2T_LPBK,
							  !L2T_ARPMISS);
						spin_unlock(&e->lock);
						port_idx = port_idx < nports - 1?
						port_idx + 1 : 0;
					}
					/*
					 * If the port is released, update
					 * orig_smt_idx to failed over port.
					 * There are 2 situations:
					 * 1. Port X is the original port and
					 * is released. {orig_smt_idx, smt_idx}
					 * follows these steps.
					 * {X, X} -> {X, Y} -> {Y, Y}
					 * 2. Port Z is released, a failover
					 * from port X had happened previously.
					 * {orig_smt_idx, smt_idx} follows these
					 * steps:
					 * {X, Z} -> {Z, Z}
					 */
					if (event == FAILOVER_PORT_RELEASE &&
						e->orig_lport == port) {
						spin_lock(&e->lock);
						e->orig_lport = e->lport;
						spin_unlock(&e->lock);
					}
				}
			}
			read_unlock_bh(&d->lock);
			break;
		case FAILOVER_PORT_UP:
			read_lock_bh(&d->lock);
			for ( i = 0 ; i < d->l2t_size;  ++i) {
				for (e = d->l2tab[i].first; e; e = e->next) {
					if (e->orig_lport == port &&
						in_bond(e->lport, bond_ports)) {
						spin_lock(&e->lock);
						e->lport = port;
						write_l2e(adap, e, 0,
							  !L2T_LPBK,
							  !L2T_ARPMISS);
						spin_unlock(&e->lock);
					}
				}
			}
			read_unlock_bh(&d->lock);
			break;
		case FAILOVER_ACTIVE_SLAVE:
			read_lock_bh(&d->lock);
			for ( i = 0 ; i < d->l2t_size;  ++i) {
				for (e = d->l2tab[i].first; e; e = e->next) {
					if (loopback && in_bond(e->lport, bond_ports)) {
						char ip[60];
						if (!e->v6)
							sprintf(ip, NIPQUAD_FMT, NIPQUAD(e->addr[0]));

						if (strcmp(ip, L2T_INVALID_IP_STR) != 0) {
							spin_lock(&e->lock);
							e->lport += 4;
							write_l2e(adap, e, 0,
								  L2T_LPBK,
								  !L2T_ARPMISS);
							spin_unlock(&e->lock);
						}
					} else if (e->lport != port) {
						if (e->neigh) {
							struct net_device *ndev = e->neigh->dev;

							if (e->neigh->dev->priv_flags & IFF_802_1Q_VLAN)
								ndev = vlan_dev_real_dev(e->neigh->dev);

							if (ndev && (ndev->flags & IFF_MASTER)) {
								if (strcmp(ndev->name, bond_dev->name) == 0) {
									spin_lock(&e->lock);
									e->lport = port;
									write_l2e(adap, e, 0,
										  !L2T_LPBK,
										  !L2T_ARPMISS);
									spin_unlock(&e->lock);
								}
							}
						}
					}
				}
			}
			read_unlock_bh(&d->lock);
			break;
	}
	return 0;
}
EXPORT_SYMBOL(t4_ports_failover);

struct l2t_entry *cxgb4_l2t_get(struct l2t_data *d, struct neighbour *neigh,
				const struct net_device *physdev,
				u32 priority)
{
	u8 lport;
	u16 vlan;
	struct l2t_entry *e;
	int addr_len = neigh->tbl->key_len;
	u32 *addr = (u32 *)neigh->primary_key;
	int ifidx = neigh->dev->ifindex;
	int hash = addr_hash(d, addr, addr_len, ifidx);
#ifdef BOND_SUPPORT
	struct bonding *bond;
	struct slave *slave;
#endif

	if (test_bit(ADAPTER_ERROR, &netdev2adap(physdev)->adap_err_state))
		return NULL;

	lport = cxgb4_modparam_enable_ringbb() ? 1 : cxgb4_port_chan(physdev);
	if (neigh->dev->flags & IFF_LOOPBACK)
		lport += 4;

	if (is_vlan_dev(neigh->dev)) {
		vlan = vlan_dev_vlan_id(neigh->dev);
		vlan |= vlan_dev_get_egress_qos_mask(neigh->dev , priority);
#ifdef BOND_SUPPORT
	} else if (neigh->dev->flags & IFF_MASTER) {
		bond = (struct bonding *)netdev_priv(neigh->dev);
		rcu_read_lock();
		slave = bond_first_slave_rcu(bond);
		if (slave && is_vlan_dev(slave->dev)) {
			vlan = vlan_dev_vlan_id(slave->dev);
			vlan |= vlan_dev_get_egress_qos_mask(slave->dev,
							     priority);
		} else
			vlan = CPL_L2T_VLAN_NONE;
		rcu_read_unlock();
#endif
	} else
		vlan = CPL_L2T_VLAN_NONE;

	write_lock_bh(&d->lock);
	for (e = d->l2tab[hash].first; e; e = e->next)
		if (!addreq(e, addr) && e->ifindex == ifidx &&
		    e->lport == lport && e->vlan == vlan) {
			l2t_hold(d, e);
			/*
			 * We now have an entry that has previously been used
			 * for this next hop.  If we are the sole owner it
			 * may have been some time since this entry has been
			 * maintained so we need to bring it up to date.
			 * Otherwise the existing users have been updating it.
			 */
			if (atomic_read(&e->refcnt) == 1)
				reuse_entry(e, neigh);
			goto done;
		}

	/* Need to allocate a new entry */
	e = alloc_l2e(d);
	if (e) {
		spin_lock(&e->lock);          /* avoid race with t4_l2t_free */
		e->state = L2T_STATE_RESOLVING;
		if (neigh->dev->flags & IFF_LOOPBACK)
			memcpy(e->dmac, physdev->dev_addr, ETH_ALEN); 
		memcpy(e->addr, addr, addr_len);
		e->ifindex = ifidx;
		e->hash = hash;
		e->lport = lport;
		e->orig_lport = lport;
		e->v6 = addr_len == 16;
		atomic_set(&e->refcnt, 1);
		neigh_replace(e, neigh);
		e->vlan = vlan;
		e->next = d->l2tab[hash].first;
		d->l2tab[hash].first = e;
		spin_unlock(&e->lock);
	}
done:
	write_unlock_bh(&d->lock);
	return e;
}
EXPORT_SYMBOL(cxgb4_l2t_get);
#endif

u64 cxgb4_select_ntuple(struct net_device *dev,
			const struct l2t_entry *l2t, u16 ipsecidx)
{
	struct adapter *adap = netdev2adap(dev);
	struct tp_params *tp = &adap->params.tp;
	u64 ntuple = 0;

	/* Initialize each of the fields which we care about which are present
	 * in the Compressed Filter Tuple.
	 */
	if (tp->vlan_shift >= 0 && l2t->vlan != CPL_L2T_VLAN_NONE)
		ntuple |= (u64)(F_FT_VLAN_VLD | l2t->vlan) << tp->vlan_shift;

	if (tp->port_shift >= 0)
		ntuple |= (u64)l2t->lport << tp->port_shift;

	if (tp->protocol_shift >= 0)
		ntuple |= (u64)IPPROTO_TCP << tp->protocol_shift;

	if (tp->vnic_shift >= 0 && (tp->ingress_config & F_VNIC)) {
		struct port_info *pi = (struct port_info *)netdev_priv(dev);

		ntuple |= (u64)(V_FT_VNID_ID_VF(pi->vin) |
				V_FT_VNID_ID_PF(adap->pf) |
				V_FT_VNID_ID_VLD(pi->vivld)) << tp->vnic_shift;
	}

	if (tp->ipsecidx_shift >= 0)
		ntuple |= (u64)ipsecidx << tp->ipsecidx_shift;

	return ntuple;
}
EXPORT_SYMBOL(cxgb4_select_ntuple);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
/*
 * Called when address resolution fails for an L2T entry to handle packets
 * on the arpq head.  If a packet specifies a failure handler it is invoked,
 * otherwise the packet is sent to the device.
 *
 * XXX: maybe we should abandon the latter behavior and just require a failure
 * handler.
 */
static void handle_failed_resolution(struct adapter *adap, struct l2t_entry *e)
{
	struct sk_buff *skb;

	if (skb_queue_empty(&e->arpq))
		return;

	skb = skb_peek(&e->arpq);
	__skb_queue_head_init(&e->arpq);
	spin_unlock(&e->lock);

	do {
		struct sk_buff *next = skb->next;
		const struct l2t_skb_cb *cb = L2T_SKB_CB(skb);

		skb->next = skb->prev = NULL;
		if (cb->arp_err_handler)
			cb->arp_err_handler(cb->handle, skb);
		else
			cxgb4_uld_xmit(adap->port[e->lport], skb);
		skb = next;
	} while (skb != (struct sk_buff *)&e->arpq);

	spin_lock(&e->lock);
}

static void t4_l2t_update_entry(struct adapter *adap, struct l2t_entry *e,
				struct neighbour *neigh)
{
	if (neigh != e->neigh)
		neigh_replace(e, neigh);

	if (e->state == L2T_STATE_RESOLVING) {
		if (neigh->nud_state & NUD_FAILED) {
			handle_failed_resolution(adap, e);
		} else if ((neigh->nud_state & (NUD_CONNECTED | NUD_STALE)) &&
			   !skb_queue_empty(&e->arpq)) {
			write_sync_l2e(adap, e);
		}
	} else {
		e->state = neigh->nud_state & NUD_CONNECTED ?
			   L2T_STATE_VALID : L2T_STATE_STALE;
		if (memcmp(e->dmac, neigh->ha, sizeof(e->dmac)))
			write_l2e(adap, e, 0, !L2T_LPBK, !L2T_ARPMISS);
	}
}

/*
 * Called when the host's neighbor layer makes a change to some entry that is
 * loaded into the HW L2 table.
 */
void t4_l2t_update(struct adapter *adap, struct neighbour *neigh)
{
	u32 *addr = (u32 *)neigh->primary_key;
	int hash, ifidx = neigh->dev->ifindex;
	int addr_len = neigh->tbl->key_len;
	struct l2t_data *d = adap->l2t;
	struct l2t_entry *e, *e_next;

	hash = addr_hash(d, addr, addr_len, ifidx);
	read_lock(&d->lock);
	e = d->l2tab[hash].first;
	while (e) {
		e_next = e->next;
		if (!addreq(e, addr) && e->ifindex == ifidx) {
			spin_lock(&e->lock);
			if (atomic_read(&e->refcnt)) {
				read_unlock(&d->lock);
				t4_l2t_update_entry(adap, e, neigh);
				read_lock(&d->lock);
			}
			spin_unlock(&e->lock);
		}
		e = e_next;
	}
	read_unlock(&d->lock);
}
#endif

/* Allocate an L2T entry for use by a switching rule.  Such need to be
 * explicitly freed and while busy they are not on any hash chain, so normal
 * address resolution updates do not see them.
 */
struct l2t_entry *t4_l2t_alloc_switching(struct adapter *adap, u16 vlan,
					 u8 port, u8 *eth_addr)
{
	struct l2t_data *d = adap->l2t;
	struct l2t_entry *e;
	int ret;

	write_lock_bh(&d->lock);
	e = find_or_alloc_l2e(d, vlan, port, eth_addr);
	if (e) {
		spin_lock(&e->lock);          /* avoid race with t4_l2t_free */
		if (!atomic_read(&e->refcnt)) {
			e->state = L2T_STATE_SWITCHING;
			e->vlan = vlan;
			e->lport = port;
			memcpy(e->dmac, eth_addr, ETH_ALEN);
			atomic_set(&e->refcnt, 1);
			if ((ret = write_l2e(adap, e, 0,
					     !L2T_LPBK, !L2T_ARPMISS)) < 0) {
				_t4_l2e_free(e);
				spin_unlock(&e->lock);
				write_unlock_bh(&d->lock);
				return NULL;
			}
		} else
                       atomic_inc(&e->refcnt);

		spin_unlock(&e->lock);
	}
	write_unlock_bh(&d->lock);
	return e;
}

/**
 * @dev: net_device pointer
 * @vlan: VLAN Id
 * @port: Associated port
 * @dmac: Destination MAC address to add to L2T
 * Returns pointer to the allocated l2t entry
 *
 * Allocates an L2T entry for use by switching rule of a filter
 */
struct l2t_entry *cxgb4_l2t_alloc_switching(struct net_device *dev, u16 vlan,
					    u8 port, u8 *dmac)
{
	struct adapter *adap = netdev2adap(dev);

	return t4_l2t_alloc_switching(adap, vlan, port, dmac);
}
EXPORT_SYMBOL(cxgb4_l2t_alloc_switching);

int t4_reset_l2t(struct l2t_data *d)
{
	int i;

	if (d->l2t_size != atomic_read(&d->nfree)) {
		return -EBUSY;
	}

	d->rover = d->l2tab;
	for (i = 0; i < d->l2t_size; ++i) {
		memset(&d->l2tab[i], 0, sizeof d->l2tab[i]);
		d->l2tab[i].idx = i;
		d->l2tab[i].state = L2T_STATE_UNUSED;
		spin_lock_init(&d->l2tab[i].lock);
		atomic_set(&d->l2tab[i].refcnt, 0);
		skb_queue_head_init(&d->l2tab[i].arpq);
	}
	return 0;
}

struct l2t_data *t4_init_l2t(unsigned int l2t_start, unsigned int l2t_end)
{
	unsigned int l2t_size;
	int i;
	struct l2t_data *d;

	if (l2t_start >= l2t_end || l2t_end >= L2T_SIZE)
		return NULL;
	l2t_size = l2t_end - l2t_start + 1;
	if (l2t_size < L2T_MIN_HASH_BUCKETS)
		return NULL;

	d = t4_alloc_mem(sizeof(*d) + l2t_size*sizeof(struct l2t_entry));
	if (!d)
		return NULL;

	d->l2t_start = l2t_start;
	d->l2t_size = l2t_size;

	d->rover = d->l2tab;
	atomic_set(&d->nfree, l2t_size);
	rwlock_init(&d->lock);

	for (i = 0; i < d->l2t_size; ++i) {
		d->l2tab[i].idx = i;
		d->l2tab[i].state = L2T_STATE_UNUSED;
		spin_lock_init(&d->l2tab[i].lock);
		atomic_set(&d->l2tab[i].refcnt, 0);
		skb_queue_head_init(&d->l2tab[i].arpq);
	}
	return d;
}

static void flush_arpq(struct l2t_entry *e)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&e->arpq)) != NULL)
		kfree_skb(skb);
}

/*
 * Drop pending skbs on all l2t entries.
 * This is needed to ensure no failure handlers are called
 * after calling the ULD to do failure recovery.
 */
void t4_flush_l2t_arpq(struct l2t_data *d)
{
	int i;

	read_lock_bh(&d->lock);
	for (i = 0; i < d->l2t_size; ++i) {
		struct l2t_entry *e;

		e = &d->l2tab[i];
		spin_lock(&e->lock);
		if (!skb_queue_empty(&e->arpq))
			flush_arpq(e);
		spin_unlock(&e->lock);
	}
	read_unlock_bh(&d->lock);
	return;
}

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "t4_linux_fs.h"

static inline void *l2t_get_idx(struct seq_file *seq, loff_t pos)
{
	struct l2t_data *d = seq->private;

	return pos >= d->l2t_size ? NULL : &d->l2tab[pos];
}

static void *l2t_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? l2t_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *l2t_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	v = l2t_get_idx(seq, *pos);
	++*pos;
	return v;
}

static void l2t_seq_stop(struct seq_file *seq, void *v)
{
}

static char l2e_state(const struct l2t_entry *e)
{
	switch (e->state) {
	case L2T_STATE_VALID: return 'V';  /* valid, fast-path entry */
	case L2T_STATE_STALE: return 'S';  /* needs revalidation, but usable */
	case L2T_STATE_SYNC_WRITE: return 'W';
	case L2T_STATE_RESOLVING:
		return skb_queue_empty(&e->arpq) ? 'R' : 'A';
	case L2T_STATE_SWITCHING: return 'X';
	default:
		return 'U';
	}
}

static int l2t_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, " Idx IP address      "
			 "Ethernet address  VLAN/P LP State Users Port\n");
	else {
		char ip[60];
		struct l2t_data *d = seq->private;
		struct l2t_entry *e = v;

		spin_lock_bh(&e->lock);
		if (e->state == L2T_STATE_SWITCHING)
			ip[0] = '\0';
		else if (!e->v6)
			sprintf(ip, NIPQUAD_FMT, NIPQUAD(e->addr[0]));
		else
			ip[0] = '\0';  // XXX IPv6 is too long, hmm
		seq_printf(seq, "%4u %-15s %02x:%02x:%02x:%02x:%02x:%02x %4d"
			   " %u %2u   %c   %5u %s\n",
			   e->idx + d->l2t_start, ip,
			   e->dmac[0], e->dmac[1], e->dmac[2],
			   e->dmac[3], e->dmac[4], e->dmac[5],
			   e->vlan & VLAN_VID_MASK, vlan_prio(e), e->lport,
			   l2e_state(e), atomic_read(&e->refcnt),
			   e->neigh ? e->neigh->dev->name : "");
		spin_unlock_bh(&e->lock);
	}
	return 0;
}

static const struct seq_operations l2t_seq_ops = {
	.start = l2t_seq_start,
	.next = l2t_seq_next,
	.stop = l2t_seq_stop,
	.show = l2t_seq_show
};

static int l2t_seq_open(struct inode *inode, struct file *file)
{
	int rc = seq_open(file, &l2t_seq_ops);

	if (!rc) {
		struct t4_linux_debugfs_data *d = inode->i_private;
		struct seq_file *seq = file->private_data;
		struct adapter *adap = d->adap;

		seq->private = adap->l2t;
	}
	return rc;
}

const struct file_operations t4_l2t_debugfs_fops = {
	.owner = THIS_MODULE,
	.open = l2t_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
