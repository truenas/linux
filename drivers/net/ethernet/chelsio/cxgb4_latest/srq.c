/*
 * This file is part of the Chelsio T4 Ethernet driver for Linux.
 *
 * Copyright (C) 2015-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Santosh Rastapur (santosh@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/* Heavily derived from smt.c */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/jhash.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/neighbour.h>
#include <net/addrconf.h>
#include "common.h"
#include "t4_msg.h"
#include "t4fw_interface.h"
#include "cxgb4_ofld.h"
#include "t4_regs.h"
#include "t4_linux_fs.h"
#include "srq.h"

int cxgb4_srq_init(struct adapter *adap, u32 srq_size)
{
	struct srq_data *s;
	int i;

	/*
	 * t4_alloc_mem() returns the memory set to all zeros.
	 */
	s = t4_alloc_mem(sizeof(*s) + srq_size*sizeof(struct srq_entry));
	if (!s)
		return -ENOMEM;

	s->srq_size = srq_size;
	s->rpl_count = 0;
	init_completion(&s->comp);

	for (i = 0; i < s->srq_size; ++i)
		s->srqtab[i].idx = i;

	adap->uld.srq = s;
	return 0;
}

void cxgb4_srq_cleanup(struct adapter *adap)
{
	kfree(adap->uld.srq);
	adap->uld.srq = NULL;
}

/**
 * do_srq_read_entries: read the SRQ table
 * @adap: Pointer to the adapter
 *
 * Send CPL_SRQ_TABLE_REQ messages for each entry.
 * Contents will be returned in CPL_SRQ_TABLE_RPL messages.
 *
 */
static int do_srq_read_enteries(struct adapter *adap)
{
	struct cpl_srq_table_req *req;
	struct sk_buff *skb;
	int i;

	/* Read the srq */
	for (i = 0; i < adap->uld.srq->srq_size; i++) {
		skb = alloc_skb(sizeof(*req), GFP_KERNEL);
		if (!skb)
			return -ENOMEM;
		req = (struct cpl_srq_table_req *)
				__skb_put(skb, sizeof(*req));
		memset(req, 0, sizeof(*req));
		INIT_TP_WR(req, 0);
		OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SRQ_TABLE_REQ,
					V_TID_TID(i) |
					V_TID_QID(adap->sge.fw_evtq.abs_id)));
		req->idx = i;

		/* do_srq_table_rpl() will make it valid */
		adap->uld.srq->srqtab[i].valid = 0;
		t4_mgmt_tx(adap, skb);
	}
	return 0;
}

void do_srq_table_rpl(struct adapter *adap, const struct cpl_srq_table_rpl *rpl)
{
	struct srq_data *s = adap->uld.srq;
	unsigned int idx = G_TID_TID(GET_TID(rpl));
	struct srq_entry *e;

	if (unlikely(rpl->status != CPL_CONTAINS_READ_RPL)) {
		CH_ERR(adap,
			"Unexpected SRQ_TABLE_RPL status %u for entry %u\n",
			rpl->status, idx);
		goto out;
	}

	/* Store the read entry */
	e = &s->srqtab[idx];
	e->valid = 1;
	WARN_ON_ONCE(e->idx != idx);
	e->pdid = G_SRQT_PDID(be64_to_cpu(rpl->rsvd_pdid));
	e->qlen = G_SRQT_QLEN(be32_to_cpu(rpl->qlen_qbase));
	e->qbase = G_SRQT_QBASE(be32_to_cpu(rpl->qlen_qbase));
	e->cur_msn = be16_to_cpu(rpl->cur_msn);
	e->max_msn = be16_to_cpu(rpl->max_msn);
out:
	if (++s->rpl_count == s->srq_size)
		complete(&s->comp);
}

static inline void *srq_get_idx(struct seq_file *seq, loff_t pos)
{
	struct adapter *adap = seq->private;
	struct srq_data *s = adap->uld.srq;

	return pos >= s->srq_size ? NULL : &s->srqtab[pos];
}

static void *srq_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? srq_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *srq_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	v = srq_get_idx(seq, *pos);
	++*pos;
	return v;
}

static void srq_seq_stop(struct seq_file *seq, void *v)
{
}

static int srq_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, " Idx  PDID      QBASE    QLEN    Cur MSN    Max MSN\n");
	else {
		struct srq_entry *e = v;

		if (e->valid)
			seq_printf(seq, "%4u  %4u   %8u    %4u       %4u       %4u\n",
				   e->idx, e->pdid,
				   e->qbase, e->qlen,
				   e->cur_msn, e->max_msn);
		else
			seq_printf(seq, "-\n");
	}
	return 0;
}

static const struct seq_operations srq_seq_ops = {
	.start = srq_seq_start,
	.next = srq_seq_next,
	.stop = srq_seq_stop,
	.show = srq_seq_show
};

static int srq_seq_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	struct srq_data *s;
	struct seq_file *seq;
	int rc = -ENODEV;

	s = adap->uld.srq;

	if (!(adap->flags & FULL_INIT_DONE) || !s)
		goto out;

	rc = seq_open(file, &srq_seq_ops);
	if (rc)
		goto out;

	seq = file->private_data;

	/*
	 * XXX do we need a global mutex to single thread
	 * this or are debugfs file operations single
	 * threaded?
	 */
	init_completion(&s->comp);
	s->rpl_count = 0;
	rc = do_srq_read_enteries(adap);
	if (rc)
		goto out;
	rc = wait_for_completion_timeout(&s->comp, SRQ_WAIT_TO);

	/* !rc means we timed out */
	if (rc) {
		seq->private = adap;
		rc = 0;
	} else
		rc = -ETIMEDOUT;
out:
	return rc;
}

const struct file_operations t4_srq_debugfs_fops = {
	.owner = THIS_MODULE,
	.open = srq_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
