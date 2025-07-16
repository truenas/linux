/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2008-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Kumar Sanghvi (kumaras@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/* Heavily derived from l2t.c */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/jhash.h>
#include <net/neighbour.h>
#include <net/addrconf.h>
#include "common.h"
#include "smt.h"
#include "t4_msg.h"
#include "t4fw_interface.h"
#include "cxgb4_ofld.h"
#include "t4_regs.h"

struct smt_data *t4_init_smt(u32 smt_start_idx, u32 smt_size)
{
	int i;
	struct smt_data *s;

	s = t4_alloc_mem(sizeof(*s) + smt_size*sizeof(struct smt_entry));
	if (!s)
		return NULL;

	s->smt_start = smt_start_idx;
	s->smt_size = smt_size;
	rwlock_init(&s->lock);

	for(i = 0; i < s->smt_size; ++i) {
		s->smtab[i].idx = i;
		s->smtab[i].hw_idx = smt_start_idx + i;
		s->smtab[i].state = SMT_STATE_UNUSED;
		memset(&s->smtab[i].src_mac, 0, ETH_ALEN);
		spin_lock_init(&s->smtab[i].lock);
		atomic_set(&s->smtab[i].refcnt, 0);
	}
	return s;
}

static struct smt_entry *find_or_alloc_smte(struct smt_data *s, u8 *smac)
{
	struct smt_entry *e, *end;
	struct smt_entry *first_free = NULL;

	for (e = &s->smtab[0], end = &s->smtab[s->smt_size]; e != end; ++e) {
		if (atomic_read(&e->refcnt) == 0) {
			if (!first_free)
				first_free = e;
		} else {
			if (e->state == SMT_STATE_SWITCHING) {
				/*
				 * This entry is actually in use. See if we can
				 * re-use it ?
				 */
				if (memcmp(e->src_mac, smac, ETH_ALEN) == 0)
					goto found_reuse;
			}
		}
	}

	if (first_free) {
		e = first_free;
		goto found;
	}

	return NULL;

found:
	e->state = SMT_STATE_UNUSED;

found_reuse:
	return e;
}

struct smt_entry *cxgb4_lookup_smte(struct net_device *dev, u8 *smac)
{
	struct adapter *adap = netdev2adap(dev);
	struct smt_data *s = adap->smt;
	struct smt_entry *e, *end;

	for (e = &s->smtab[0], end = &s->smtab[s->smt_size]; e != end; ++e) {
		if (memcmp(e->src_mac, smac, ETH_ALEN) == 0)
			goto found;
	}

	return NULL;

found:
	return e;
}
EXPORT_SYMBOL(cxgb4_lookup_smte);

static void t4_smte_free(struct smt_entry *e)
{
	struct smt_data *s;

	spin_lock_bh(&e->lock);
	if (atomic_read(&e->refcnt) == 0) {  /* hasn't been recycled */
		e->state = SMT_STATE_UNUSED;
	}
	spin_unlock_bh(&e->lock);

	s = container_of(e, struct smt_data, smtab[e->idx]);
}

/**
 * @e: smt entry to release
 *
 * Releases ref count and frees up an smt entry from SMT table
 */
void cxgb4_smt_release(struct smt_entry *e)
{
	if (atomic_dec_and_test(&e->refcnt))
		t4_smte_free(e);
}
EXPORT_SYMBOL(cxgb4_smt_release);

void do_smt_write_rpl(struct adapter *adap, const struct cpl_smt_write_rpl *rpl)
{
	struct smt_data *s = adap->smt;
	unsigned int smtidx = G_TID_TID(GET_TID(rpl));

	if (unlikely(rpl->status != CPL_ERR_NONE)) {
		struct smt_entry *e = &s->smtab[smtidx];
		CH_ERR(adap,
			"Unexpected SMT_WRITE_RPL status %u for entry %u\n",
			rpl->status, smtidx);
		spin_lock(&e->lock);
		e->state = SMT_STATE_ERROR;
		spin_unlock(&e->lock);

		return;
	}
}

int write_ofld_smt(struct net_device *dev, unsigned int tid, u8 vi_vld)
{
	struct adapter *adap = netdev2adap(dev);
	struct cpl_smt_write_req *req;
	struct cpl_t6_smt_write_req *t6req;
	struct sk_buff *skb;
	int size;
	u8 row;
	struct port_info *pi = (struct port_info *)netdev_priv(dev);
	u32 vivld_pf_vf = V_SMTW_VF_VLD(vi_vld) | V_SMTW_PF(adap->pf) |
			  V_SMTW_VF(pi->vin);

	if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T5) {
		size = sizeof(*req);
		skb = alloc_skb(size, GFP_ATOMIC);
		if (!skb)
			return -ENOMEM;
		/* Source MAC Table (SMT) contains 256 SMAC entries
		 * organized in 128 rows of 2 entries each.
		 */
		req = (struct cpl_smt_write_req *)__skb_put(skb, size);
		INIT_TP_WR(req, 0);
		req->pfvf1 = htons(vivld_pf_vf);
		memset(req->src_mac1, 0x0, ETH_ALEN);
		/* MTU is specified in units of 4 bytes */
		req->pfvf0 = htons((dev->mtu +
				    sizeof(struct vlan_ethhdr)) >> 2);
		req->params = 0;
		/* Each row contains an SMAC pair.
		 * LSB selects the SMAC entry within a row.
		 */
		row = (pi->smt_idx >> 1);
	} else {
		size = sizeof(*t6req);
		skb = alloc_skb(size, GFP_ATOMIC);
		if (!skb)
			return -ENOMEM;
		/* Source MAC Table (SMT) contains 256 SMAC entries */
		t6req = (struct cpl_t6_smt_write_req *)__skb_put(skb, size);
		INIT_TP_WR(t6req, 0);
		t6req->params = htonl(dev->mtu + sizeof(struct vlan_ethhdr));
		req = (struct cpl_smt_write_req *)t6req;
		req->pfvf0 = htons(vivld_pf_vf);
		row = pi->smt_idx;
	}

	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SMT_WRITE_REQ, tid |
				V_TID_QID(adap->sge.fw_evtq.abs_id)));
	req->params |= htonl(V_SMTW_NORPL(1) |
			    V_SMTW_IDX(row) |
			    V_SMTW_OVLAN_IDX(0));
	memcpy(req->src_mac0, dev->dev_addr, ETH_ALEN);
	t4_mgmt_tx(adap, skb);
	return 0;
}
EXPORT_SYMBOL(write_ofld_smt);

static int write_smt_entry(struct adapter *adapter, struct smt_entry *e)
{
	struct smt_data *s = adapter->smt;
	struct cpl_smt_write_req *req;
	struct cpl_t6_smt_write_req *t6req;
	struct sk_buff *skb;
	int size;
	u8 row;

	if (CHELSIO_CHIP_VERSION(adapter->params.chip) <= CHELSIO_T5) {
		size = sizeof(*req);
		skb = alloc_skb(size, GFP_ATOMIC);
		if (!skb)
			return -ENOMEM;
		/* Source MAC Table (SMT) contains 256 SMAC entries
		 * organized in 128 rows of 2 entries each.
		 */
		req = (struct cpl_smt_write_req *)__skb_put(skb, size);
		INIT_TP_WR(req, 0);

		/* Each row contains an SMAC pair.
		 * LSB selects the SMAC entry within a row
		 */
		row = (e->hw_idx >> 1);
		if (e->idx & 1) {
			req->pfvf1 = 0x0;
			memcpy(req->src_mac1, e->src_mac, ETH_ALEN);

			/* fill pfvf0/src_mac0 with entry
			 * at prev index from smt-tab.
			 */
			req->pfvf0 = 0x0;
			memcpy(req->src_mac0, s->smtab[e->idx - 1].src_mac,
			       ETH_ALEN);
		} else {
			req->pfvf0 = 0x0;
			memcpy(req->src_mac0, e->src_mac, ETH_ALEN);

			/* fill pfvf1/src_mac1 with entry
			 * at next index from smt-tab
			 */
			req->pfvf1 = 0x0;
			memcpy(req->src_mac1, s->smtab[e->idx + 1].src_mac,
			       ETH_ALEN);
		}
	} else {
		size = sizeof(*t6req);
		skb = alloc_skb(size, GFP_ATOMIC);
		if (!skb)
			return -ENOMEM;
		/* Source MAC Table (SMT) contains 256 SMAC entries */
		t6req = (struct cpl_t6_smt_write_req *)__skb_put(skb, size);
		INIT_TP_WR(t6req, 0);
		req = (struct cpl_smt_write_req *)t6req;

		/* fill pfvf0/src_mac0 from smt-tab */
		req->pfvf0 = 0x0;
		memcpy(req->src_mac0, s->smtab[e->idx].src_mac, ETH_ALEN);
		row = e->hw_idx;
	}

	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SMT_WRITE_REQ, e->hw_idx |
				V_TID_QID(adapter->sge.fw_evtq.abs_id)));
	req->params = htonl(V_SMTW_NORPL(0) |
			    V_SMTW_IDX(row) |
			    V_SMTW_OVLAN_IDX(0));
	t4_mgmt_tx(adapter, skb);

	return 0;
}

static struct smt_entry *t4_smt_alloc_switching(struct adapter *adap, u16 pfvf,
					 u8 *smac)
{
	struct smt_data *s = adap->smt;
	struct smt_entry *e;

	write_lock_bh(&s->lock);
	e = find_or_alloc_smte(s, smac);
	if (e) {
		spin_lock(&e->lock);
		if (!atomic_read(&e->refcnt)) {
			atomic_set(&e->refcnt, 1);
			e->state = SMT_STATE_SWITCHING;
			e->pfvf = pfvf;
			memcpy(e->src_mac, smac, ETH_ALEN);
			write_smt_entry(adap, e);
		} else
			atomic_inc(&e->refcnt);
		spin_unlock(&e->lock);
	}
	write_unlock_bh(&s->lock);
	return e;
}

/**
 * @dev: net_device pointer
 * @smac: MAC address to add to SMT
 * Returns pointer to the SMT entry created
 *
 * Allocates an SMT entry to be used by switching rule of a filter.
 */
struct smt_entry *cxgb4_smt_alloc_switching(struct net_device *dev, u8 *smac)
{
	struct adapter *adap = netdev2adap(dev);

	return t4_smt_alloc_switching(adap, 0x0, smac);
}
EXPORT_SYMBOL(cxgb4_smt_alloc_switching);

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "t4_linux_fs.h"

static inline void *smt_get_idx(struct seq_file *seq, loff_t pos)
{
	struct smt_data *s = seq->private;

	return pos >= s->smt_size ? NULL : &s->smtab[pos];
}

static void *smt_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? smt_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *smt_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	v = smt_get_idx(seq, *pos);
	++*pos;
	return v;
}

static void smt_seq_stop(struct seq_file *seq, void *v)
{
}

static char smte_state(const struct smt_entry *e)
{
	switch (e->state) {
	case SMT_STATE_ERROR: return 'E';
	case SMT_STATE_SWITCHING: return 'S';
	case SMT_STATE_UNUSED: return 'U';
	default:
		return 'U';
	}
}

static int smt_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, " Idx  PFVF  Ethernet Address     State  Users\n");
	else {
		struct smt_entry *e = v;

		spin_lock_bh(&e->lock);
		seq_printf(seq, "%4u  %04x  %02x:%02x:%02x:%02x:%02x:%02x  %4c  %5u\n",
			   e->hw_idx, e->pfvf,
			   e->src_mac[0], e->src_mac[1], e->src_mac[2],
			   e->src_mac[3], e->src_mac[4], e->src_mac[5],
			   smte_state(e), atomic_read(&e->refcnt));
		spin_unlock_bh(&e->lock);
	}
	return 0;
}

static const struct seq_operations smt_seq_ops = {
	.start = smt_seq_start,
	.next = smt_seq_next,
	.stop = smt_seq_stop,
	.show = smt_seq_show
};

static int smt_seq_open(struct inode *inode, struct file *file)
{
	int rc = seq_open(file, &smt_seq_ops);

	if (!rc) {
		struct t4_linux_debugfs_data *d = inode->i_private;
		struct seq_file *seq = file->private_data;
		struct adapter *adap = d->adap;

		seq->private = adap->smt;
	}
	return rc;
}

const struct file_operations t4_smt_debugfs_fops = {
	.owner = THIS_MODULE,
	.open = smt_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
