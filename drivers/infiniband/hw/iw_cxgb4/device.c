/*
 * Copyright (c) 2009-2021 Chelsio, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/debugfs.h>
#include <linux/math64.h>
#include <linux/vmalloc.h>

#include <rdma/ib_verbs.h>

#include "iw_cxgb4.h"

#define DRV_VERSION "4.1.0.3"

MODULE_AUTHOR("Steve Wise");
MODULE_DESCRIPTION("Chelsio T4/T5/T6/T7 RDMA Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

int db_fc_resume_size = 64;
module_param(db_fc_resume_size, int, 0644);
MODULE_PARM_DESC(db_fc_resume_size, "qps are resumed from db flow control in "
		 "this size chunks (default = 64)");

static int db_fc_resume_delay = 1;
module_param(db_fc_resume_delay, int, 0644);
MODULE_PARM_DESC(db_fc_resume_delay, "how long to delay between removing qps "
		 "from the fc list (default is 1 jiffy)");

static int db_fc_drain_thresh = 0;
module_param(db_fc_drain_thresh, int, 0644);
MODULE_PARM_DESC(db_fc_drain_thresh,
		 "relative threshold at which a chunk will be resumed "
                 "from the fc list (default is 0 (int_thresh << "
		 "db_fc_drain_thresh))");

int wd_disable_inaddr_any = 0;
module_param(wd_disable_inaddr_any, int, 0644);
MODULE_PARM_DESC(wd_disable_inaddr_any,
		 "Disables reserving 1/2 of the WD filter space for INADDR_ANY "
		 "mappings (default 0).");

int roce_mode = 0;
module_param(roce_mode, int, 0644);
MODULE_PARM_DESC(roce_mode, "Enables RoCE mode, 1 = roce mode, 0 = iWARP mode "
			    "(default 0)");

static LIST_HEAD(uld_ctx_list);
static DEFINE_MUTEX(dev_mutex);
static struct workqueue_struct *reg_workq;

static struct dentry *chrd_debugfs_root;

struct chrd_debugfs_data {
	struct chrd_dev *devp;
	char *buf;
	int bufsize;
	int pos;
};

static ssize_t debugfs_read(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	struct chrd_debugfs_data *d = file->private_data;
	loff_t pos = *ppos;
	loff_t avail = d->pos;

	if (pos < 0)
		return -EINVAL;
	if (pos >= avail)
		return 0;
	if (count > avail - pos)
		count = avail - pos;

	while (count) {
		size_t len = 0;

		len = min((int)count, (int)d->pos - (int)pos);
		if (copy_to_user(buf, d->buf + pos, len))
			return -EFAULT;
		if (len == 0)
			return -EINVAL;

		buf += len;
		pos += len;
		count -= len;
	}
	count = pos - *ppos;
	*ppos = pos;
	return count;
}

int chrd_wr_log = 0;
module_param(chrd_wr_log, int, 0444);
MODULE_PARM_DESC(chrd_wr_log, "Enables logging of work request timing data.");

static int chrd_wr_log_size_order = 12;
module_param(chrd_wr_log_size_order, int, 0444);
MODULE_PARM_DESC(chrd_wr_log_size_order,
		 "Number of entries (log2) in the work request timing log.");

void chrd_log_wr_stats(struct t4_wq *wq, struct t4_cqe *cqe)
{
	struct wr_log_entry le;
	int idx;

	if (!wq->rdev->wr_log)
		return;

	idx = (atomic_inc_return(&wq->rdev->wr_log_idx) - 1) &
		  (wq->rdev->wr_log_size - 1);
	le.poll_sge_ts = cxgb4_read_sge_timestamp(wq->rdev->lldi.ports[0]);
	le.poll_host_time = ktime_get();
	le.valid = 1;
	le.cqe_sge_ts = CQE_TS(cqe);
	if (SQ_TYPE(cqe)) {
		le.qid = wq->sq.qid;
		le.opcode = CQE_OPCODE(cqe);
		le.post_host_time = wq->sq.sw_sq[wq->sq.cidx].host_time;
		le.post_sge_ts = wq->sq.sw_sq[wq->sq.cidx].sge_ts;
		le.wr_id = CQE_WRID_SQ_IDX(cqe);
	} else {
		le.qid = wq->rq.qid;
		le.opcode = FW_RI_RECEIVE;
		le.post_host_time = wq->rq.sw_rq[wq->rq.cidx].host_time;
		le.post_sge_ts = wq->rq.sw_rq[wq->rq.cidx].sge_ts;
		le.wr_id = CQE_WRID_MSN(cqe);
	}
	wq->rdev->wr_log[idx] = le;
}

static int wr_log_show(struct seq_file *seq, void *v)
{
	struct chrd_dev *dev = seq->private;
	ktime_t prev_time;
	struct wr_log_entry *lep;
	int prev_time_set = 0;
	int idx, end;

#define ts2ns(ts) div64_u64((ts) * dev->rdev.lldi.cclk_ps, 1000)

	idx = atomic_read(&dev->rdev.wr_log_idx) &
	      (dev->rdev.wr_log_size - 1);
	end = idx - 1;
	if (end < 0)
		end = dev->rdev.wr_log_size - 1;
	lep = &dev->rdev.wr_log[idx];
	while (idx != end) {
		if (lep->valid) {
			if (!prev_time_set) {
				prev_time_set = 1;
				prev_time = lep->poll_host_time;
			}
			seq_printf(seq, "%04u: nsec %llu qid %u opcode "
				"%u %s 0x%x host_wr_delta nsec %llu "
				"post_sge_ts 0x%llx cqe_sge_ts 0x%llx "
				"poll_sge_ts 0x%llx post_poll_delta_ns %llu "
				"cqe_poll_delta_ns %llu\n",
				idx,
				ktime_to_ns(ktime_sub(lep->poll_host_time,
						      prev_time)),
			        lep->qid, lep->opcode,
				lep->opcode == FW_RI_RECEIVE ? "msn" : "wrid",
				lep->wr_id,
				ktime_to_ns(ktime_sub(lep->poll_host_time,
						      lep->post_host_time)),
				lep->post_sge_ts, lep->cqe_sge_ts,
				lep->poll_sge_ts,
				ts2ns(lep->poll_sge_ts - lep->post_sge_ts),
				ts2ns(lep->poll_sge_ts - lep->cqe_sge_ts));
			prev_time = lep->poll_host_time;
		}
		idx++;
		if (idx > (dev->rdev.wr_log_size - 1))
			idx = 0;
		lep = &dev->rdev.wr_log[idx];
	}
#undef ts2ns
	return 0;
}

static int wr_log_open(struct inode *inode, struct file *file)
{
	return single_open(file, wr_log_show, inode->i_private);
}

static ssize_t wr_log_clear(struct file *file, const char __user *buf,
			      size_t count, loff_t *pos)
{
	struct chrd_dev *dev = ((struct seq_file *)file->private_data)->private;
	int i;

	if (dev->rdev.wr_log)
		for (i = 0; i < dev->rdev.wr_log_size; i++)
			dev->rdev.wr_log[i].valid = 0;
	return count;
}

static const struct file_operations wr_log_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = wr_log_open,
	.release = single_release,
	.read 	 = seq_read,
	.llseek  = seq_lseek,
	.write   = wr_log_clear,
};

static struct sockaddr_in zero_sin = {
	.sin_family = AF_INET,
};

static struct sockaddr_in6 zero_sin6 = {
	.sin6_family = AF_INET6,
};

static void set_ep_sin_addrs(struct chrd_ep *ep,
			     struct sockaddr_in **lsin,
			     struct sockaddr_in **rsin,
			     struct sockaddr_in **m_lsin,
			     struct sockaddr_in **m_rsin)
{
	struct iw_cm_id *id = ep->com.cm_id;

	*m_lsin = (struct sockaddr_in *)&ep->com.local_addr;
	*m_rsin = (struct sockaddr_in *)&ep->com.remote_addr;
	if (id) {
		*lsin = (struct sockaddr_in *)&id->local_addr;
		*rsin = (struct sockaddr_in *)&id->remote_addr;
	} else {
		*lsin = &zero_sin;
		*rsin = &zero_sin;
	}
}

static void set_ep_sin6_addrs(struct chrd_ep *ep,
			     struct sockaddr_in6 **lsin6,
			     struct sockaddr_in6 **rsin6,
			     struct sockaddr_in6 **m_lsin6,
			     struct sockaddr_in6 **m_rsin6)
{
	struct iw_cm_id *id = ep->com.cm_id;

	*m_lsin6 = (struct sockaddr_in6 *)&ep->com.local_addr;
	*m_rsin6 = (struct sockaddr_in6 *)&ep->com.remote_addr;
	if (id) {
		*lsin6 = (struct sockaddr_in6 *)&id->local_addr;
		*rsin6 = (struct sockaddr_in6 *)&id->remote_addr;
	} else {
		*lsin6 = &zero_sin6;
		*rsin6 = &zero_sin6;
	}
}

static int dump_qp(unsigned long id, struct chrd_qp *qp,
		   struct chrd_debugfs_data *qpd)
{
	int space;
	int cc;

	if (id != qp->wq.sq.qid)
		return 0;

	space = qpd->bufsize - qpd->pos - 1;
	if (space == 0)
		return 1;
	if (rdma_protocol_roce(qp->ibqp.device, 1)) {
		struct chrd_ah *ahp = &qp->roce_attr.roce_ah;

		if (ahp->net_type == RDMA_NETWORK_IPV6)
			cc = snprintf(qpd->buf + qpd->pos, space,
				      "roce qp_type %s qp %p  sq id %u %s id %u state %u history 0x%lx %s %u %pI6:%u->%pI6:%u\n",
				      qp->qp_type == IB_QPT_GSI ? "GSI" : "RC", qp,
				      qp->wq.sq.qid, qp->srq ? "srq" : "rq",
				      qp->srq ? qp->srq->idx : qp->wq.rq.qid, (int)qp->attr.state,
				      qp->history, qp->qp_type == IB_QPT_GSI ? "ftid" : "hw tid",
				      qp->qp_type == IB_QPT_GSI ? qp->roce_attr.gsi_ftid : qp->roce_attr.hwtid,
				      &ahp->local_ip_addr[0], ahp->src_port,
				      &ahp->dest_ip_addr[0],
				      ahp->dst_port);
		else
			cc = snprintf(qpd->buf + qpd->pos, space,
				      "roce qp_type  %s qp %p  sq id %u %s id %u state %u history 0x%lx %s %u %pI4:%u->%pI4:%u\n",
				      qp->qp_type == IB_QPT_GSI ? "GSI" : "RC", qp,
				      qp->wq.sq.qid, qp->srq ? "srq" : "rq",
				      qp->srq ? qp->srq->idx : qp->wq.rq.qid, (int)qp->attr.state,
				      qp->history, qp->qp_type == IB_QPT_GSI ? "ftid" : "hw tid",
				      qp->qp_type == IB_QPT_GSI ? qp->roce_attr.gsi_ftid : qp->roce_attr.hwtid,
				      &ahp->local_ip_addr[3], ahp->src_port, &ahp->dest_ip_addr[3],
				      ahp->dst_port);

	} else {
		if (qp->ep) {
			struct chrd_ep *ep = qp->ep;

			if (ep->com.local_addr.ss_family == AF_INET) {
				struct sockaddr_in *lsin;
				struct sockaddr_in *rsin;
				struct sockaddr_in *m_lsin;
				struct sockaddr_in *m_rsin;

				set_ep_sin_addrs(ep, &lsin, &rsin, &m_lsin, &m_rsin);
				cc = snprintf(qpd->buf + qpd->pos, space,
					      "iwarp rc qp sq id %u %s id %u state %u "
					      "onchip %u ep tid %u state %u "
					      "%pI4:%u/%u->%pI4:%u/%u\n",
					      qp->wq.sq.qid, qp->srq ? "srq" : "rq",
					      qp->srq ? qp->srq->idx : qp->wq.rq.qid,
					      (int)qp->attr.state,
					      qp->wq.sq.flags & T4_SQ_ONCHIP,
					      ep->hwtid, (int)ep->com.state,
					      &lsin->sin_addr, ntohs(lsin->sin_port),
					      ntohs(m_lsin->sin_port),
					      &rsin->sin_addr, ntohs(rsin->sin_port),
					      ntohs(m_rsin->sin_port));
			} else {
				struct sockaddr_in6 *lsin6;
				struct sockaddr_in6 *rsin6;
				struct sockaddr_in6 *m_lsin6;
				struct sockaddr_in6 *m_rsin6;

				set_ep_sin6_addrs(ep, &lsin6, &rsin6, &m_lsin6,
						  &m_rsin6);
				cc = snprintf(qpd->buf + qpd->pos, space,
					      "iwarp rc qp sq id %u rq id %u state %u "
					      "onchip %u ep tid %u state %u "
					      "%pI6:%u/%u->%pI6:%u/%u\n",
					      qp->wq.sq.qid, qp->wq.rq.qid,
					      (int)qp->attr.state,
					      qp->wq.sq.flags & T4_SQ_ONCHIP,
					      ep->hwtid, (int)ep->com.state,
					      &lsin6->sin6_addr,
					      ntohs(lsin6->sin6_port),
					      ntohs(m_lsin6->sin6_port),
					      &rsin6->sin6_addr,
					      ntohs(rsin6->sin6_port),
					      ntohs(m_rsin6->sin6_port));
			}
	} else
		cc = snprintf(qpd->buf + qpd->pos, space,
			      "iwarp rc qp sq id %u rq id %u state %u onchip %u\n",
			      qp->wq.sq.qid, qp->wq.rq.qid, (int)qp->attr.state,
			      qp->wq.sq.flags & T4_SQ_ONCHIP);
	}
	if (cc < space)
		qpd->pos += cc;
	return 0;
}

static
int dump_raw_qp(int id, struct chrd_raw_qp *rqp, struct chrd_debugfs_data *qpd)
{
	int space;
	int cc;
	struct chrd_raw_srq *srq = to_chrd_raw_srq(rqp->ibqp.srq);

	space = qpd->bufsize - qpd->pos - 1;
	if (space == 0)
		return 1;

	cc = snprintf(qpd->buf + qpd->pos, space, "raw qp%s iqid %u flid %u "
		      "txqid %u state %u onchip %u dev %s fids %u..%u/%u..%u\n",
		      srq ? "/srq" : "",
		      srq ? srq->iq.cntxt_id : rqp->iq.cntxt_id, 
		      srq ? srq->fl.cntxt_id : rqp->fl.cntxt_id,
		      rqp->txq.cntxt_id, rqp->state,
		      rqp->txq.flags & T4_SQ_ONCHIP, rqp->netdev->name,
		      rqp->fid, rqp->fid + rqp->nfids - 1,
		      rqp->fid + rqp->rhp->rdev.nfids,
		      rqp->fid + rqp->rhp->rdev.nfids + rqp->nfids - 1);
	if (cc < space)
		qpd->pos += cc;
	return 0;
}

static int qp_release(struct inode *inode, struct file *file)
{
	struct chrd_debugfs_data *qpd = file->private_data;
	if (!qpd) {
		pr_info("%s null qpd?\n", __func__);
		return 0;
	}
	vfree(qpd->buf);
	kfree(qpd);
	return 0;
}

static int qp_open(struct inode *inode, struct file *file)
{
	struct chrd_qp *qp;
	struct chrd_raw_qp *rqp;
	struct chrd_debugfs_data *qpd;
	unsigned long index;
	int ret = 0;
	int count = 1;

	qpd = kmalloc(sizeof *qpd, GFP_KERNEL);
	if (!qpd) {
		ret = -ENOMEM;
		goto out;
	}
	qpd->devp = inode->i_private;
	qpd->pos = 0;

	xa_for_each(&qpd->devp->qps, index, qp)
		count++;
	xa_for_each(&qpd->devp->rawqps, index, rqp)
		count++;

	qpd->bufsize = count * 180;
	qpd->buf = vmalloc(qpd->bufsize);
	if (!qpd->buf) {
		ret = -ENOMEM;
		goto err_free_qpd;
	}

	xa_lock_irq(&qpd->devp->qps);
	xa_for_each(&qpd->devp->qps, index, qp)
		dump_qp(index, qp, qpd);
	xa_unlock_irq(&qpd->devp->qps);
	xa_lock_irq(&qpd->devp->rawqps);
	xa_for_each(&qpd->devp->rawqps, index, rqp)
		dump_raw_qp(index, rqp, qpd);
	xa_unlock_irq(&qpd->devp->rawqps);

	file->private_data = qpd;
	goto out;
err_free_qpd:
	kfree(qpd);
out:
	return ret;
}

static const struct file_operations qp_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = qp_open,
	.release = qp_release,
	.read    = debugfs_read,
};

static int dump_stag(unsigned long id, struct chrd_debugfs_data *stagd)
{
	int space;
	int cc;
	struct fw_ri_tpte tpte;
	int ret;

	space = stagd->bufsize - stagd->pos - 1;
	if (space == 0)
		return 1;

	ret = cxgb4_read_tpte(stagd->devp->rdev.lldi.ports[0], (u32)id<<8,
			      (__be32 *)&tpte);
	if (ret) {
		pr_err("%s cxgb4_read_tpte err %d\n", __func__,
		       ret);
		return ret;
	}
	cc = snprintf(stagd->buf + stagd->pos, space,
		      "stag: idx 0x%x valid %d key 0x%x state %d pdid %d "
		      "perm 0x%x ps %d len 0x%llx va 0x%llx\n",
		      (u32)id<<8,
		      G_FW_RI_TPTE_VALID(ntohl(tpte.valid_to_pdid)),
		      G_FW_RI_TPTE_STAGKEY(ntohl(tpte.valid_to_pdid)),
		      G_FW_RI_TPTE_STAGSTATE(ntohl(tpte.valid_to_pdid)),
		      G_FW_RI_TPTE_PDID(ntohl(tpte.valid_to_pdid)),
		      G_FW_RI_TPTE_PERM(ntohl(tpte.locread_to_qpid)),
		      G_FW_RI_TPTE_PS(ntohl(tpte.locread_to_qpid)),
		      ((u64)ntohl(tpte.len_hi) << 32) | ntohl(tpte.len_lo),
		      ((u64)ntohl(tpte.va_hi) << 32) | ntohl(tpte.va_lo_fbo));
	if (cc < space)
		stagd->pos += cc;
	return 0;
}

static int stag_release(struct inode *inode, struct file *file)
{
	struct chrd_debugfs_data *stagd = file->private_data;
	if (!stagd) {
		pr_info("%s null stagd?\n", __func__);
		return 0;
	}
	vfree(stagd->buf);
	kfree(stagd);
	return 0;
}

static int stag_open(struct inode *inode, struct file *file)
{
	struct chrd_debugfs_data *stagd;
	void *p;
	unsigned long index;
	int ret = 0;
	int count = 1;

	stagd = kmalloc(sizeof *stagd, GFP_KERNEL);
	if (!stagd) {
		ret = -ENOMEM;
		goto out;
	}
	stagd->devp = inode->i_private;
	stagd->pos = 0;

	xa_for_each(&stagd->devp->mrs, index, p)
		count++;

	stagd->bufsize = count * 256;
	stagd->buf = vmalloc(stagd->bufsize);
	if (!stagd->buf) {
		ret = -ENOMEM;
		goto err1;
	}

	xa_lock_irq(&stagd->devp->mrs);
	xa_for_each(&stagd->devp->mrs, index, p)
		dump_stag(index, stagd);
	xa_unlock_irq(&stagd->devp->mrs);

	file->private_data = stagd;
	goto out;
err1:
	kfree(stagd);
out:
	return ret;
}

static const struct file_operations stag_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = stag_open,
	.release = stag_release,
	.read    = debugfs_read,
};

static char *db_state_str[] = {"NORMAL", "STOPPED", "FLOW_CONTROL", "RECOVERY"};

static int stats_show(struct seq_file *seq, void *v)
{
	struct chrd_dev *dev = seq->private;

	seq_printf(seq, "   Object: %10s %10s %10s %10s\n", "Total", "Current", "Max", "Fail");
	seq_printf(seq, "     PDID: %10llu %10llu %10llu %10llu\n",
		   dev->rdev.rdma_res->stats.pd.total,
		   dev->rdev.rdma_res->stats.pd.cur,
		   dev->rdev.rdma_res->stats.pd.max,
		   dev->rdev.rdma_res->stats.pd.fail);
	seq_printf(seq, "      QID: %10llu %10llu %10llu %10llu\n",
		   dev->rdev.rdma_res->stats.qid.total,
		   dev->rdev.rdma_res->stats.qid.cur,
		   dev->rdev.rdma_res->stats.qid.max,
		   dev->rdev.rdma_res->stats.qid.fail);
	seq_printf(seq, "     SRQS: %10llu %10llu %10llu %10llu\n",
		   dev->rdev.rdma_res->stats.srqt.total,
		   dev->rdev.rdma_res->stats.srqt.cur,
		   dev->rdev.rdma_res->stats.srqt.max,
		   dev->rdev.rdma_res->stats.srqt.fail);
	seq_printf(seq, "   TPTMEM: %10llu %10llu %10llu %10llu\n",
		   dev->rdev.stats.stag.total, dev->rdev.stats.stag.cur,
		   dev->rdev.stats.stag.max, dev->rdev.stats.stag.fail);
	seq_printf(seq, "   PBLMEM: %10llu %10llu %10llu %10llu\n",
		   dev->rdev.stats.pbl.total, dev->rdev.stats.pbl.cur,
		   dev->rdev.stats.pbl.max, dev->rdev.stats.pbl.fail);
	seq_printf(seq, "  RRQTMEM: %10llu %10llu %10llu %10llu\n",
		   dev->rdev.stats.rrqt.total, dev->rdev.stats.rrqt.cur,
		   dev->rdev.stats.rrqt.max, dev->rdev.stats.rrqt.fail);
	seq_printf(seq, "   RQTMEM: %10llu %10llu %10llu %10llu\n",
		   dev->rdev.rdma_res->stats.rqt.total,
		   dev->rdev.rdma_res->stats.rqt.cur,
		   dev->rdev.rdma_res->stats.rqt.max,
		   dev->rdev.rdma_res->stats.rqt.fail);
	seq_printf(seq, "  OCQPMEM: %10llu %10llu %10llu %10llu\n",
		   dev->rdev.stats.ocqp.total, dev->rdev.stats.ocqp.cur,
		   dev->rdev.stats.ocqp.max, dev->rdev.stats.ocqp.fail);
	seq_printf(seq, "  DB FULL: %10llu\n", dev->rdev.stats.db_full);
	seq_printf(seq, " DB EMPTY: %10llu\n", dev->rdev.stats.db_empty);
	seq_printf(seq, "  DB DROP: %10llu\n", dev->rdev.stats.db_drop);
	seq_printf(seq, " DB State: %s Transitions %llu FC Interruptions %llu\n",
		   db_state_str[dev->db_state],
		   dev->rdev.stats.db_state_transitions,
		   dev->rdev.stats.db_fc_interruptions);
	seq_printf(seq, "TCAM_FULL: %10llu\n", dev->rdev.stats.tcam_full);
	seq_printf(seq, "ACT_OFLD_CONN_FAILS: %10llu\n", dev->rdev.stats.act_ofld_conn_fails);
	seq_printf(seq, "PAS_OFLD_CONN_FAILS: %10llu\n", dev->rdev.stats.pas_ofld_conn_fails);
	seq_printf(seq, "NEG_ADV_RCVD: %10llu\n", dev->rdev.stats.neg_adv);
	seq_printf(seq, "AVAILABLE IRD: %10u\n", dev->avail_ird);
	return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_show, inode->i_private);
}

static ssize_t stats_clear(struct file *file, const char __user *buf,
			      size_t count, loff_t *pos)
{
	struct chrd_dev *dev = ((struct seq_file *)file->private_data)->private;

	mutex_lock(&dev->rdev.stats.lock);
	dev->rdev.stats.stag.max = 0;
	dev->rdev.stats.stag.fail = 0;
	dev->rdev.stats.pbl.max = 0;
	dev->rdev.stats.pbl.fail = 0;
	dev->rdev.stats.rrqt.max = 0;
	dev->rdev.stats.rrqt.fail = 0;
	dev->rdev.stats.ocqp.max = 0;
	dev->rdev.stats.ocqp.fail = 0;
	dev->rdev.stats.db_full = 0;
	dev->rdev.stats.db_empty = 0;
	dev->rdev.stats.db_drop = 0;
	dev->rdev.stats.db_state_transitions = 0;
	dev->rdev.stats.tcam_full = 0;
	dev->rdev.stats.act_ofld_conn_fails = 0;
	dev->rdev.stats.pas_ofld_conn_fails = 0;
	mutex_unlock(&dev->rdev.stats.lock);

	mutex_lock(&dev->rdev.rdma_res->stats.lock);
	dev->rdev.rdma_res->stats.pd.max = 0;
	dev->rdev.rdma_res->stats.pd.fail = 0;
	dev->rdev.rdma_res->stats.qid.max = 0;
	dev->rdev.rdma_res->stats.qid.fail = 0;
	dev->rdev.rdma_res->stats.srqt.max = 0;
	dev->rdev.rdma_res->stats.srqt.fail = 0;
	dev->rdev.rdma_res->stats.rqt.max = 0;
	dev->rdev.rdma_res->stats.rqt.fail = 0;
	mutex_unlock(&dev->rdev.rdma_res->stats.lock);
	return count;
}

static const struct file_operations stats_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = stats_open,
	.release = single_release,
	.read 	 = seq_read,
	.llseek  = seq_lseek,
	.write   = stats_clear,
};

static int dump_ep(struct chrd_ep *ep, struct chrd_debugfs_data *epd)
{
	int space;
	int cc;

	space = epd->bufsize - epd->pos - 1;
	if (space == 0)
		return 1;

	if (ep->com.local_addr.ss_family == AF_INET) {
		struct sockaddr_in *lsin;
		struct sockaddr_in *rsin;
		struct sockaddr_in *m_lsin;
		struct sockaddr_in *m_rsin;

		set_ep_sin_addrs(ep, &lsin, &rsin, &m_lsin, &m_rsin);
		cc = snprintf(epd->buf + epd->pos, space,
			      "ep %p cm_id %p qp %p state %d flags 0x%lx "
			      "history 0x%lx hwtid %d atid %d "
			      "%pI4:%d/%d <-> %pI4:%d/%d\n",
			      ep, ep->com.cm_id, ep->com.qp,
			      (int)ep->com.state, ep->com.flags,
			      ep->com.history, ep->hwtid, ep->atid,
			      &lsin->sin_addr, ntohs(lsin->sin_port),
			      ntohs(m_lsin->sin_port),
			      &rsin->sin_addr, ntohs(rsin->sin_port),
			      ntohs(m_rsin->sin_port));
	} else {
		struct sockaddr_in6 *lsin6;
		struct sockaddr_in6 *rsin6;
		struct sockaddr_in6 *m_lsin6;
		struct sockaddr_in6 *m_rsin6;

		set_ep_sin6_addrs(ep, &lsin6, &rsin6, &m_lsin6, &m_rsin6);
		cc = snprintf(epd->buf + epd->pos, space,
			      "ep %p cm_id %p qp %p state %d flags 0x%lx "
			      "history 0x%lx hwtid %d atid %d "
			      "%pI6:%d/%d <-> %pI6:%d/%d\n",
			      ep, ep->com.cm_id, ep->com.qp,
			      (int)ep->com.state, ep->com.flags,
			      ep->com.history, ep->hwtid, ep->atid,
			      &lsin6->sin6_addr, ntohs(lsin6->sin6_port),
			      ntohs(m_lsin6->sin6_port),
			      &rsin6->sin6_addr, ntohs(rsin6->sin6_port),
			      ntohs(m_rsin6->sin6_port));
	}

	if (cc < space)
		epd->pos += cc;
	return 0;
}

static
int dump_listen_ep(struct chrd_listen_ep *ep, struct chrd_debugfs_data *epd)
{
	int space;
	int cc;

	space = epd->bufsize - epd->pos - 1;
	if (space == 0)
		return 1;

	if (ep->com.local_addr.ss_family == AF_INET) {
		struct sockaddr_in *lsin = (struct sockaddr_in *)
			&ep->com.cm_id->local_addr;
		struct sockaddr_in *m_lsin = (struct sockaddr_in *)
			&ep->com.cm_id->m_local_addr;

		cc = snprintf(epd->buf + epd->pos, space,
			      "ep %p cm_id %p state %d flags 0x%lx stid %d "
			      "backlog %d %pI4:%d/%d\n",
			      ep, ep->com.cm_id, (int)ep->com.state,
			      ep->com.flags, ep->stid, ep->backlog,
			      &lsin->sin_addr, ntohs(lsin->sin_port),
			      ntohs(m_lsin->sin_port));
	} else {
		struct sockaddr_in6 *lsin6 = (struct sockaddr_in6 *)
			&ep->com.cm_id->local_addr;
		struct sockaddr_in6 *m_lsin6 = (struct sockaddr_in6 *)
			&ep->com.cm_id->m_local_addr;

		cc = snprintf(epd->buf + epd->pos, space,
			      "ep %p cm_id %p state %d flags 0x%lx stid %d "
			      "backlog %d %pI6:%d/%d\n",
			      ep, ep->com.cm_id, (int)ep->com.state,
			      ep->com.flags, ep->stid, ep->backlog,
			      &lsin6->sin6_addr, ntohs(lsin6->sin6_port),
			      ntohs(m_lsin6->sin6_port));
	}

	if (cc < space)
		epd->pos += cc;
	return 0;
}


static int ep_release(struct inode *inode, struct file *file)
{
	struct chrd_debugfs_data *epd = file->private_data;
	if (!epd) {
		pr_info("%s null qpd?\n", __func__);
		return 0;
	}
	vfree(epd->buf);
	kfree(epd);
	return 0;
}

static int ep_open(struct inode *inode, struct file *file)
{
	struct chrd_ep *ep;
	struct chrd_listen_ep *lep;
	unsigned long index;
	struct chrd_debugfs_data *epd;
	int ret = 0;
	int count = 1;

	epd = kmalloc(sizeof *epd, GFP_KERNEL);
	if (!epd) {
		ret = -ENOMEM;
		goto out;
	}
	epd->devp = inode->i_private;
	epd->pos = 0;

	xa_for_each(&epd->devp->hwtids, index, ep)
		count++;
	xa_for_each(&epd->devp->atids, index, ep)
		count++;
	xa_for_each(&epd->devp->stids, index, lep)
		count++;

	epd->bufsize = count * 240;
	epd->buf = vmalloc(epd->bufsize);
	if (!epd->buf) {
		ret = -ENOMEM;
		goto err1;
	}

	xa_lock_irq(&epd->devp->hwtids);
	xa_for_each(&epd->devp->hwtids, index, ep)
		dump_ep(ep, epd);
	xa_unlock_irq(&epd->devp->hwtids);
	xa_lock_irq(&epd->devp->atids);
	xa_for_each(&epd->devp->atids, index, ep)
		dump_ep(ep, epd);
	xa_unlock_irq(&epd->devp->atids);
	xa_lock_irq(&epd->devp->stids);
	xa_for_each(&epd->devp->stids, index, lep)
		dump_listen_ep(lep, epd);
	xa_unlock_irq(&epd->devp->stids);

	file->private_data = epd;
	goto out;
err1:
	kfree(epd);
out:
	return ret;
}

static const struct file_operations ep_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = ep_open,
	.release = ep_release,
	.read    = debugfs_read,
};

static int fids_show(struct seq_file *seq, void *v)
{
	struct chrd_dev *dev = seq->private;
	int i;

	for (i = BITS_TO_LONGS(dev->rdev.nfids) - 1; i >=0 ; i--) {
		seq_printf(seq, "%016lx ", dev->rdev.fids[i]);
	}
	seq_printf(seq, "\n");
	return 0;
}

static int fids_open(struct inode *inode, struct file *file)
{
	return single_open(file, fids_show, inode->i_private);
}

static const struct file_operations fids_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = fids_open,
	.release = single_release,
	.read 	 = seq_read,
	.llseek  = seq_lseek,
};

static void setup_debugfs(struct chrd_dev *devp)
{
	struct dentry *de;

	de = debugfs_create_file("qps", S_IWUSR, devp->debugfs_root,
				 (void *)devp, &qp_debugfs_fops);
	if (de && de->d_inode)
		de->d_inode->i_size = 4096;

	de = debugfs_create_file("stags", S_IWUSR, devp->debugfs_root,
				 (void *)devp, &stag_debugfs_fops);
	if (de && de->d_inode)
		de->d_inode->i_size = 4096;

	de = debugfs_create_file("stats", S_IWUSR, devp->debugfs_root,
				 (void *)devp, &stats_debugfs_fops);
	if (de && de->d_inode)
		de->d_inode->i_size = 4096;

	de = debugfs_create_file("eps", S_IWUSR, devp->debugfs_root,
				 (void *)devp, &ep_debugfs_fops);
	if (de && de->d_inode)
		de->d_inode->i_size = 4096;

	de = debugfs_create_file("fids", S_IWUSR, devp->debugfs_root,
				 (void *)devp, &fids_debugfs_fops);
	if (de && de->d_inode)
		de->d_inode->i_size = 4096;

	if (chrd_wr_log) {
		de = debugfs_create_file("wr_log", S_IWUSR, devp->debugfs_root,
					 (void *)devp, &wr_log_debugfs_fops);
		if (de && de->d_inode)
			de->d_inode->i_size = 4096;
	}
}

/* Caller takes care of locking if needed */
static int chrd_rdev_open(struct chrd_rdev *rdev)
{
	struct resource *res;
	int nfids;
	int err;

	res = cxgb4_bar_resource(rdev->lldi.ports[0], 2);
	if (!res)
		return -EOPNOTSUPP;

	cxgb4_uld_init_dev_ucontext(&rdev->uctx);

	/*
	 * fids tracks which filter ids are in use.  The lower half
	 * are used for WD endpoints with a non-wildcard local ipaddr.
	 * endpoints with a wildcard local ipaddr get the upper half.
	 * This ensures that the non-wildcard filter has precedence.
	 */
	if (wd_disable_inaddr_any)
		nfids = rdev->lldi.uld_tids.ftids.size & ~3U;
	else
		nfids = (rdev->lldi.uld_tids.ftids.size >> 1) & ~3U;

	rdev->fids = kmalloc(BITS_TO_LONGS(nfids) * sizeof(unsigned long),
			     GFP_KERNEL);
	if (!rdev->fids) {
		err = -ENOMEM;
		goto err;
	}
	bitmap_zero(rdev->fids, nfids);
	rdev->nfids = nfids;

	/*
	 * This implementation assumes udb_density == ucq_density!  Eventually
	 * we might need to support this but for now fail the open. Also the
	 * cqid and qpid range must match for now.
	 */
	if (rdev->lldi.udb_density != rdev->lldi.ucq_density) {
		pr_err("%s: unsupported udb/ucq densities %u/%u\n",
		       rdev->lldi.name, rdev->lldi.udb_density,
		       rdev->lldi.ucq_density);
		err = -EINVAL;
		goto err_free_fids;
	}
	if (rdev->lldi.vr->qp.start != rdev->lldi.vr->cq.start ||
	    rdev->lldi.vr->qp.size != rdev->lldi.vr->cq.size) {
		pr_err("%s: unsupported qp and cq id ranges "
		       "qp start %u size %u cq start %u size %u\n",
		       rdev->lldi.name, rdev->lldi.vr->qp.start,
		       rdev->lldi.vr->qp.size, rdev->lldi.vr->cq.size,
		       rdev->lldi.vr->cq.size);
		err = -EINVAL;
		goto err_free_fids;
	}

	/* This implementation requires a sge_host_page_size <= PAGE_SIZE. */
        if (rdev->lldi.sge_host_page_size > PAGE_SIZE) {
                pr_err("%s: unsupported sge host page size %u\n",
                       rdev->lldi.name, rdev->lldi.sge_host_page_size);
                err = -EINVAL;
                goto err_free_fids;
        }


	pr_debug("dev %s stag start 0x%0x size 0x%0x num stags %d "
		 "pbl start 0x%0x size 0x%0x rq start 0x%0x size 0x%0x "
		 "qp qid start %u size %u cq qid start %u size %u\n",
		 rdev->lldi.name, rdev->lldi.vr->stag.start,
		 rdev->lldi.vr->stag.size, chrd_num_stags(rdev),
		 rdev->lldi.vr->pbl.start, rdev->lldi.vr->pbl.size,
		 rdev->lldi.vr->rq.start, rdev->lldi.vr->rq.size,
		 rdev->lldi.vr->qp.start, rdev->lldi.vr->qp.size,
		 rdev->lldi.vr->cq.start, rdev->lldi.vr->cq.size);

	if (chrd_num_stags(rdev) == 0) {
		err = -EINVAL;
		goto err_free_fids;
	}

	rdev->stats.stag.total = rdev->lldi.vr->stag.size;
	rdev->stats.pbl.total = rdev->lldi.vr->pbl.size;
	rdev->stats.rrqt.total = rdev->lldi.vr->rrq.size;
	rdev->stats.ocqp.total = rdev->lldi.vr->ocq.size;

	err = chrd_init_resource(rdev, chrd_num_stags(rdev));
	if (err) {
		pr_err("error %d initializing resources\n", err);
		goto err_free_fids;
	}

	pr_debug("udb len 0x%llx udb base 0x%llx db_reg %p gts_reg %p "
		 "qpmask 0x%x cqmask 0x%x\n", resource_size(res),
		 res->start, rdev->lldi.db_reg, rdev->lldi.gts_reg,
		 rdev->rdma_res->qpmask, rdev->rdma_res->cqmask);

	err = chrd_pblpool_create(rdev);
	if (err) {
		pr_err("error %d initializing pbl pool\n", err);
		goto err_destroy_resource;
	}
	err = chrd_rrqtpool_create(rdev);
	if (err) {
		pr_err("error %d initializing rrqt pool\n", err);
		goto err_destroy_pblpool;
	}

	rdev->status_page = dma_alloc_coherent(rdev->lldi.dev, PAGE_SIZE,
					       &rdev->daddr, GFP_KERNEL);
	if (!rdev->status_page) {
		pr_err("error allocating status page\n");
		goto err_destroy_rrqtpool;
	}
	rdev->status_page->qp_start = rdev->lldi.vr->qp.start;
	rdev->status_page->qp_size = rdev->lldi.vr->qp.size;
	rdev->status_page->cq_start = rdev->lldi.vr->cq.start;
	rdev->status_page->cq_size = rdev->lldi.vr->cq.size;
	rdev->status_page->fid_base = rdev->lldi.uld_tids.ftids.start;
	rdev->status_page->wc_supported = t5_en_wc;
	rdev->status_page->write_cmpl_supported = rdev->lldi.write_cmpl_support;

	if (chrd_wr_log) {
		rdev->wr_log = kzalloc( (1 << chrd_wr_log_size_order) *
					sizeof *rdev->wr_log, GFP_KERNEL);
		if (rdev->wr_log) {
			rdev->wr_log_size = 1 << chrd_wr_log_size_order;
			atomic_set(&rdev->wr_log_idx, 0);
		} else {
			pr_err("error allocating wr_log. "
			       "Logging disabled\n");
		}
	}

	rdev->status_page->db_off = 0;

	init_completion(&rdev->rqt_compl);
	init_completion(&rdev->rrqt_compl);
	init_completion(&rdev->pbl_compl);
	kref_init(&rdev->rqt_kref);
	kref_init(&rdev->rrqt_kref);
	kref_init(&rdev->pbl_kref);

	rdev->free_workq = create_singlethread_workqueue("iw_cxgb4_free");
	if (!rdev->free_workq) {
		err = -ENOMEM;
		goto err_free_status_page;
	}

	return 0;
err_free_status_page:
	dma_free_coherent(rdev->lldi.dev, PAGE_SIZE, rdev->status_page,
			  rdev->daddr);
err_destroy_rrqtpool:
	chrd_rrqtpool_destroy(rdev);
err_destroy_pblpool:
	chrd_pblpool_destroy(rdev);
err_destroy_resource:
	chrd_destroy_resource(rdev);
err_free_fids:
	kfree(rdev->fids);
err:
	return err;
}

static void chrd_rdev_close(struct chrd_rdev *rdev)
{
	if (rdev->wr_log)
		kfree(rdev->wr_log);
	dma_free_coherent(rdev->lldi.dev, PAGE_SIZE, rdev->status_page,
			  rdev->daddr);
	kfree(rdev->fids);
	chrd_pblpool_destroy(rdev);
	chrd_rqtpool_destroy(rdev);
	chrd_rrqtpool_destroy(rdev);
	wait_for_completion(&rdev->pbl_compl);
	wait_for_completion(&rdev->rqt_compl);
	wait_for_completion(&rdev->rrqt_compl);
	destroy_workqueue(rdev->free_workq);
	chrd_destroy_resource(rdev);
}

void chrd_dealloc(struct uld_ctx *ctx)
{
	chrd_rdev_close(&ctx->dev->rdev);
	WARN_ON(!xa_empty(&ctx->dev->cqs));
	WARN_ON(!xa_empty(&ctx->dev->qps));
	WARN_ON(!xa_empty(&ctx->dev->mrs));
	wait_event(ctx->dev->wait, xa_empty(&ctx->dev->hwtids));
	WARN_ON(!xa_empty(&ctx->dev->stids));
	WARN_ON(!xa_empty(&ctx->dev->atids));
	WARN_ON(!xa_empty(&ctx->dev->rawqps));
	WARN_ON(!xa_empty(&ctx->dev->rawiqs));
	WARN_ON(!xa_empty(&ctx->dev->fids));
	if (ctx->dev->rdev.bar2_kva)
		iounmap(ctx->dev->rdev.bar2_kva);
	if (ctx->dev->rdev.oc_mw_kva)
		iounmap(ctx->dev->rdev.oc_mw_kva);
	ib_dealloc_device(&ctx->dev->ibdev);
	ctx->dev = NULL;
}

static void chrd_remove(struct uld_ctx *ctx)
{
	pr_debug("chrd_dev %p\n",  ctx->dev);
	if (ctx->dev->debugfs_root)
		debugfs_remove_recursive(ctx->dev->debugfs_root);
	chrd_unregister_device(ctx->dev);
	chrd_dealloc(ctx);
}

static int rdma_supported(const struct cxgb4_lld_info *infop)
{
	return infop->vr->stag.size > 0 && infop->vr->pbl.size > 0 &&
	       infop->vr->rq.size > 0 && infop->vr->qp.size > 0 &&
	       infop->vr->cq.size > 0;
}

static struct chrd_dev *chrd_alloc(const struct cxgb4_lld_info *infop)
{
	struct chrd_dev *devp;
	struct resource *res;
	int ret;

	res = cxgb4_bar_resource(infop->ports[0], 2);
	if (!res)
		return ERR_PTR(-EOPNOTSUPP);

	if (!rdma_supported(infop)) {
		pr_info("%s: RDMA not supported on this device\n",
			infop->name);
		return ERR_PTR(-ENOSYS);
	}

	if (!ocqp_supported(infop)) {
		pr_info("%s: On-Chip Queues not supported on this device\n",
			infop->name);
	}

	devp = ib_alloc_device(chrd_dev, ibdev);
	if (!devp) {
		pr_err("Cannot allocate ib device\n");
		return ERR_PTR(-ENOMEM);
	}
	devp->rdev.lldi = *infop;

	/* init various hw-queue params based on lld info */
	pr_info("%s: ing. padding boundary is %d, "
		"egrsstatuspagesize = %d\n", __func__,
		devp->rdev.lldi.sge_ingpadboundary,
		devp->rdev.lldi.sge_egrstatuspagesize);

	devp->rdev.hw_queue.t4_eq_status_entries =
		devp->rdev.lldi.sge_egrstatuspagesize / 64;
	pr_info("t4_eq_status_entries %d\n", devp->rdev.hw_queue.t4_eq_status_entries);
	devp->rdev.hw_queue.t4_max_eq_size = 65520;
	devp->rdev.hw_queue.t4_max_iq_size = 65520;
	devp->rdev.hw_queue.t4_max_rq_size = 8192 -
		devp->rdev.hw_queue.t4_eq_status_entries - 1;
	devp->rdev.hw_queue.t4_max_sq_size =
		devp->rdev.hw_queue.t4_max_eq_size -
		devp->rdev.hw_queue.t4_eq_status_entries - 1;
	devp->rdev.hw_queue.t4_max_qp_depth =
		devp->rdev.hw_queue.t4_max_rq_size;
	devp->rdev.hw_queue.t4_max_cq_depth =
		devp->rdev.hw_queue.t4_max_iq_size - 2;
	devp->rdev.hw_queue.t4_stat_len =
		devp->rdev.lldi.sge_egrstatuspagesize;

	/*
	 * For T5/T6/T7 devices, we map all of BAR2 with WC.
	 * For T4 devices with onchip qp mem, we map only that part
	 * of BAR2 with WC.
	 */
	devp->rdev.bar2_pa = res->start;
	if (!is_t4(devp->rdev.lldi.adapter_type)) {
		devp->rdev.bar2_kva = ioremap_wc(devp->rdev.bar2_pa,
						 resource_size(res));
		if (!devp->rdev.bar2_kva) {
			pr_err("Unable to ioremap BAR2\n");
			ib_dealloc_device(&devp->ibdev);
			return ERR_PTR(-EINVAL);
		}
	} else if (ocqp_supported(infop)) {
		devp->rdev.oc_mw_pa = res->start + resource_size(res) -
			roundup_pow_of_two(devp->rdev.lldi.vr->ocq.size);
		devp->rdev.oc_mw_kva = ioremap_wc(devp->rdev.oc_mw_pa,
			devp->rdev.lldi.vr->ocq.size);
		if (!devp->rdev.oc_mw_kva) {
			pr_err("Unable to ioremap onchip mem\n");
			ib_dealloc_device(&devp->ibdev);
			return ERR_PTR(-EINVAL);
		}
	}

	pr_debug("ocq memory: hw_start 0x%x size %u mw_pa 0x%lx mw_kva %p\n",
		 devp->rdev.lldi.vr->ocq.start, devp->rdev.lldi.vr->ocq.size,
		 devp->rdev.oc_mw_pa, devp->rdev.oc_mw_kva);

	ret = chrd_rdev_open(&devp->rdev);
	if (ret) {
		pr_err("Unable to open CXIO rdev err %d\n", ret);
		ib_dealloc_device(&devp->ibdev);
		return ERR_PTR(ret);
	}

	xa_init_flags(&devp->cqs, XA_FLAGS_LOCK_IRQ);
	xa_init_flags(&devp->qps, XA_FLAGS_LOCK_IRQ);
	xa_init_flags(&devp->rawqps, XA_FLAGS_LOCK_IRQ);
	xa_init_flags(&devp->rawiqs, XA_FLAGS_LOCK_IRQ);
	xa_init_flags(&devp->mrs, XA_FLAGS_LOCK_IRQ);
	xa_init_flags(&devp->hwtids, XA_FLAGS_LOCK_IRQ);
	xa_init_flags(&devp->stids, XA_FLAGS_LOCK_IRQ);
	xa_init_flags(&devp->atids, XA_FLAGS_LOCK_IRQ);
	xa_init_flags(&devp->fids, XA_FLAGS_LOCK_IRQ);
	/* remove this */
	spin_lock_init(&devp->lock);
	mutex_init(&devp->rdev.stats.lock);
	mutex_init(&devp->db_mutex);
	INIT_LIST_HEAD(&devp->db_fc_list);
	INIT_LIST_HEAD(&devp->rdev.blocker_list);
	INIT_LIST_HEAD(&devp->rdev.ep_glist);
	mutex_init(&devp->rdev.ep_glist_lock);
	mutex_init(&devp->rdev.blocker_lock);
	init_waitqueue_head(&devp->wait);
	devp->avail_ird = devp->rdev.lldi.max_ird_adapter;

	if (chrd_debugfs_root) {
		devp->debugfs_root =
			debugfs_create_dir(devp->rdev.lldi.name,
					   chrd_debugfs_root);
		setup_debugfs(devp);
	}

	return devp;
}

static void *chrd_uld_add(const struct cxgb4_lld_info *infop)
{
	struct uld_ctx *ctx;
	static int vers_printed;
	int i;

	if (!vers_printed++)
		pr_info("Chelsio T4/T5/T6/T7 RDMA Driver - version %s\n",
			DRV_VERSION);

	ctx = kzalloc(sizeof *ctx, GFP_KERNEL);
	if (!ctx) {
		ctx = ERR_PTR(-ENOMEM);
		goto out;
	}
	ctx->lldi = *infop;

	pr_debug("found device %s nchan %u nrxq %u ntxq %u nports %u\n",
		 ctx->lldi.name, ctx->lldi.nchan, ctx->lldi.nrxq,
		 ctx->lldi.ntxq, ctx->lldi.nports);

	mutex_lock(&dev_mutex);
	list_add_tail(&ctx->entry, &uld_ctx_list);
	mutex_unlock(&dev_mutex);

	for (i = 0; i < ctx->lldi.nrxq; i++)
		pr_debug("rxqid[%u] %u\n", i, ctx->lldi.rxq_ids[i]);

out:
	return ctx;
}

static struct sk_buff *t4_pktgl_to_skb(const struct pkt_gl *gl,
				       unsigned int skb_len,
				       unsigned int pull_len)
{
	struct sk_buff *skb;
	struct skb_shared_info *ssi;

	if (gl->tot_len <= 512) {
		skb = alloc_skb(gl->tot_len, GFP_ATOMIC);
		if (unlikely(!skb))
			goto out;
		__skb_put(skb, gl->tot_len);
		skb_copy_to_linear_data(skb, gl->va, gl->tot_len);
	} else {
		skb = alloc_skb(skb_len, GFP_ATOMIC);
		if (unlikely(!skb))
			goto out;
		__skb_put(skb, pull_len);
		skb_copy_to_linear_data(skb, gl->va, pull_len);

		ssi = skb_shinfo(skb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
		skb_frag_fill_page_desc(&ssi->frags[0], gl->frags[0].page,
					gl->frags[0].offset + pull_len,
					gl->frags[0].size - pull_len);
#else
		skb_frag_set_page(skb, 0, gl->frags[0].page);
		skb_frag_off_set(&ssi->frags[0], gl->frags[0].offset + pull_len);
		skb_frag_size_set(&ssi->frags[0], gl->frags[0].size - pull_len);
#endif
		if (gl->nfrags > 1)
			memcpy(&ssi->frags[1], &gl->frags[1],
			       (gl->nfrags - 1) * sizeof(skb_frag_t));
		ssi->nr_frags = gl->nfrags;

		skb->len = gl->tot_len;
		skb->data_len = skb->len - pull_len;
		skb->truesize += skb->data_len;

		/* Get a reference for the last page, we don't own it */
		get_page(gl->frags[gl->nfrags - 1].page);
	}
out:
	return skb;
}

static inline struct sk_buff *copy_gl_to_skb_pkt(const struct pkt_gl *gl,
						 const __be64 *rsp,
						 u32 pktshift)
{
        struct sk_buff *skb;

	/* 
	 * Allocate space for cpl_pass_accept_req which will be synthesized by
	 * driver. Once the driver synthesizes the request the skb will go
	 * through the regular cpl_pass_accept_req processing.
	 * The math here assumes sizeof cpl_pass_accept_req >= sizeof cpl_rx_pkt.
	 */
	skb = alloc_skb(gl->tot_len + sizeof(struct cpl_pass_accept_req) +
			sizeof(struct rss_header) - pktshift, GFP_ATOMIC);
	if (unlikely(!skb))
		return NULL;

	 __skb_put(skb, gl->tot_len + sizeof(struct cpl_pass_accept_req) +
		   sizeof(struct rss_header) - pktshift);

	/*
	 * This skb will contain: 
	 *   rss_header from the rspq descriptor (1 flit)
	 *   cpl_rx_pkt struct from the rspq descriptor (2 flits)
	 *   space for the difference between the size of an
	 *      rx_pkt and pass_accept_req cpl (1 flit)
	 *   the packet data from the gl
	 */
	skb_copy_to_linear_data(skb, rsp, sizeof(struct cpl_pass_accept_req) +
				sizeof(struct rss_header));
	skb_copy_to_linear_data_offset(skb, sizeof(struct rss_header) +
				       sizeof(struct cpl_pass_accept_req),
				       gl->va + pktshift,
				       gl->tot_len - pktshift);
	return skb;
}

static inline int recv_rx_pkt(struct chrd_dev *dev, const struct pkt_gl *gl,
			   const __be64 *rsp)
{
	unsigned int opcode = *(u8 *)rsp;
	struct sk_buff *skb;

	if (opcode != CPL_RX_PKT)
		goto out;

	skb = copy_gl_to_skb_pkt(gl , rsp, dev->rdev.lldi.sge_pktshift);
	if (skb == NULL)
		goto out;

	if (chrd_handlers[opcode] == NULL) {
		pr_info("%s no handler opcode 0x%x...\n", __func__, opcode);
		kfree_skb(skb);
		goto out;
	}
	chrd_handlers[opcode](dev, skb);
        return 1;
out:
	return 0;
}

static int chrd_uld_rx_handler(void *handle, const __be64 *rsp,
			const struct pkt_gl *gl)
{
	struct uld_ctx *ctx = handle;
	struct chrd_dev *dev = ctx->dev;
	struct sk_buff *skb;
	u8 opcode;

	if (chrd_fatal_error(&dev->rdev))
		return 0;

	if (gl == NULL) {
		/* omit RSS and rsp_ctrl at end of descriptor */
		unsigned int len = 64 - sizeof(struct rsp_ctrl) - 8;

		skb = alloc_skb(256, GFP_ATOMIC);
		if (!skb)
			goto nomem;
		__skb_put(skb, len);
		skb_copy_to_linear_data(skb, &rsp[1], len);
	} else if (gl == CXGB4_MSG_AN) {
		const struct rsp_ctrl *rc = (void *)rsp;
		u32 qid = be32_to_cpu(rc->pldbuflen_qid);
		u32 pidx = G_RSPD_LEN(be32_to_cpu(rc->hdrbuflen_pidx));
		
		chrd_ev_handler(dev, qid, pidx);
		return 0;
	} else if (unlikely(*(u8 *)rsp != *(u8 *)gl->va)) {
		if (recv_rx_pkt(dev, gl, rsp))
			return 0;

		pr_info("%s: unexpected FL contents at %p, "
			"RSS %#llx, FL %#llx, len %u\n",
			ctx->lldi.name, gl->va,
			(unsigned long long)be64_to_cpu(*rsp),
			(unsigned long long)be64_to_cpu(*(u64 *)gl->va),
			gl->tot_len);

		return 0;
	} else {
		skb = t4_pktgl_to_skb(gl, 128, 128);
		if (unlikely(!skb))
			goto nomem;
	}

	opcode = *(u8 *)rsp;
	if (chrd_handlers[opcode])
		chrd_handlers[opcode](dev, skb);
	else {
		pr_info("%s no handler opcode 0x%x...\n", __func__, opcode);
		kfree_skb(skb);
	}

	return 0;
nomem:
	return -1;
}

static int chrd_uld_state_change(void *handle, enum cxgb4_state new_state)
{
	struct uld_ctx *ctx = handle;

	pr_debug("new_state %u\n", new_state);
	switch (new_state) {
	case CXGB4_STATE_UP:
		pr_info("%s: Up\n", ctx->lldi.name);
		if (!ctx->dev) {
			ctx->dev = chrd_alloc(&ctx->lldi);
			if (IS_ERR(ctx->dev)) {
				pr_err("%s: initialization failed: %ld\n",
				       ctx->lldi.name, PTR_ERR(ctx->dev));
				ctx->dev = NULL;
				break;
			}

			INIT_WORK(&ctx->reg_work, chrd_register_device);
			queue_work(reg_workq, &ctx->reg_work);
		}
		break;
	case CXGB4_STATE_DOWN:
		pr_info("%s: Down\n", ctx->lldi.name);
		if (ctx->dev)
			chrd_remove(ctx);
		break;
	case CXGB4_STATE_START_RECOVERY:
		pr_info("%s: Fatal Error\n", ctx->lldi.name);
		if (ctx->dev) {
			chrd_disable_device(&ctx->dev->rdev, 1);
		}
		break;
	case CXGB4_STATE_DETACH:
		pr_info("%s: Detach\n", ctx->lldi.name);
		if (ctx->dev)
			chrd_remove(ctx);
		break;
	case CXGB4_STATE_SHUTDOWN:
		pr_info("%s: Shutdown\n", ctx->lldi.name);
		if (ctx->dev) {
			struct chrd_rdev *rdev = &ctx->dev->rdev;
			rdev->flags |= T4_FATAL_ERROR;
		}
		break;
	}
	return 0;
}

static void stop_queues(struct uld_ctx *ctx)
{
	unsigned long index, flags;
	struct chrd_raw_qp *rqp;
	struct chrd_qp *qp;

	xa_lock_irqsave(&ctx->dev->qps, flags);
	xa_lock_irqsave(&ctx->dev->rawqps, flags);
	ctx->dev->rdev.stats.db_state_transitions++;
	ctx->dev->db_state = STOPPED;
	if (ctx->dev->rdev.flags & T4_STATUS_PAGE_DISABLED) {
		xa_for_each(&ctx->dev->qps, index, qp)
			t4_disable_wq_db(&qp->wq);
		xa_for_each(&ctx->dev->rawqps, index, rqp)
			t4_disable_fl_db(&rqp->fl);
	} else {
		ctx->dev->rdev.status_page->db_off = 1;
	}
	xa_unlock_irqrestore(&ctx->dev->rawqps, flags);
	xa_unlock_irqrestore(&ctx->dev->qps, flags);
}

static void resume_rc_qp(struct chrd_qp *qp)
{
	spin_lock(&qp->lock);
	t4_ring_sq_db(&qp->wq, qp->wq.sq.wq_pidx_inc, NULL);
	qp->wq.sq.wq_pidx_inc = 0;
	t4_ring_rq_db(&qp->wq, qp->wq.rq.wq_pidx_inc, NULL);
	qp->wq.rq.wq_pidx_inc = 0;
	spin_unlock(&qp->lock);
}

static void resume_raw_qp(struct chrd_raw_qp *qp)
{
	u32 val = 0;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(qp->rhp->rdev.lldi.adapter_type);
	writel(V_QID(qp->txq.cntxt_id) | V_PIDX(qp->txq.pidx_inc),
	       qp->rhp->rdev.lldi.db_reg);
	qp->txq.pidx_inc = 0;

	switch (chip_ver) {
	case CHELSIO_T4:
		val = V_PIDX(qp->fl.pidx_inc) | F_DBPRIO;
		break;
	case CHELSIO_T5:
		val = F_DBPRIO;
		fallthrough; /* fallthrough */
	case CHELSIO_T6:
	case CHELSIO_T7:
	default:
		val |= V_PIDX_T5(qp->fl.pidx_inc);
		break;
	}

	writel(V_QID(qp->fl.cntxt_id) | val,
	       qp->rhp->rdev.lldi.db_reg);
	qp->fl.pidx_inc = 0;
}

static void resume_raw_srq(struct chrd_raw_srq *srq)
{
	u32 val = 0;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(srq->dev->rdev.lldi.adapter_type);

	switch (chip_ver) {
	case CHELSIO_T4:
		val = V_PIDX(srq->fl.pidx_inc) | F_DBPRIO;
		break;
	case CHELSIO_T5:
		val = F_DBPRIO;
		fallthrough; /* fallthrough */
	case CHELSIO_T6:
	case CHELSIO_T7:
	default:
		val |= V_PIDX_T5(srq->fl.pidx_inc);
		break;
	}

	writel(V_QID(srq->fl.cntxt_id) | val,
	       srq->dev->rdev.lldi.db_reg);
	srq->fl.pidx_inc = 0;
}

static void resume_a_chunk(struct uld_ctx *ctx)
{
	int i;
	struct db_fcl *fcl;

	for (i = 0; i < db_fc_resume_size; i++) {
		fcl = list_first_entry(&ctx->dev->db_fc_list, struct db_fcl,
				       db_fc_entry);
		list_del_init(&fcl->db_fc_entry);

		switch (fcl->type) {
		case RC_QP:
			resume_rc_qp(fcl_to_chrd_qp(fcl));
			break;
		case RAW_QP:
			resume_raw_qp(fcl_to_chrd_raw_qp(fcl));
			break;
		case RAW_SRQ:
			resume_raw_srq(fcl_to_chrd_raw_srq(fcl));
			break;
		default:
			WARN_ONCE(1, "Unknown fcl type %u\n", fcl->type);
		}
		if (list_empty(&ctx->dev->db_fc_list))
			break;
	}
}

static void resume_queues(struct uld_ctx *ctx)
{
	xa_lock_irq(&ctx->dev->qps);
	if (ctx->dev->db_state != STOPPED)
		goto out;
	ctx->dev->db_state = FLOW_CONTROL;
	while (1) {
		if (list_empty(&ctx->dev->db_fc_list)) {
			struct chrd_qp *qp;
			unsigned long index;

			WARN_ON(ctx->dev->db_state != FLOW_CONTROL);
			ctx->dev->db_state = NORMAL;
			ctx->dev->rdev.stats.db_state_transitions++;
			if (ctx->dev->rdev.flags & T4_STATUS_PAGE_DISABLED) {
				xa_for_each(&ctx->dev->rawqps, index, qp)
					t4_enable_wq_db(&qp->wq);
			} else
				ctx->dev->rdev.status_page->db_off = 0;
			break;
		} else {
			if (cxgb4_dbfifo_count(ctx->dev->rdev.lldi.ports[0],1) <
			    (ctx->dev->rdev.lldi.dbfifo_int_thresh <<
			     db_fc_drain_thresh)) {
				resume_a_chunk(ctx);
			}
			if (!list_empty(&ctx->dev->db_fc_list)) {
				xa_unlock_irq(&ctx->dev->qps);
				if (db_fc_resume_delay) {
					set_current_state(TASK_UNINTERRUPTIBLE);
					schedule_timeout(db_fc_resume_delay);
				}
				xa_lock_irq(&ctx->dev->qps);
				if (ctx->dev->db_state != FLOW_CONTROL)
					break;
			}
		}
	}
out:
	if (ctx->dev->db_state != NORMAL)
		ctx->dev->rdev.stats.db_fc_interruptions++;
	xa_unlock_irq(&ctx->dev->qps);
}

struct qp_list {
	unsigned idx;
	struct chrd_qp **qps;
	unsigned ridx;
	struct chrd_raw_qp **rqps;
};

static void deref_qps(struct qp_list *qp_list)
{
	int idx;

	for (idx = 0; idx < qp_list->idx; idx ++) {
		chrd_iw_qp_rem_ref(&qp_list->qps[idx]->ibqp);
	}
	for (idx = 0; idx < qp_list->ridx; idx ++) {
		chrd_iw_qp_rem_ref(&qp_list->rqps[idx]->ibqp);
	}
}

static void recover_lost_dbs(struct uld_ctx *ctx, struct qp_list *qp_list)
{
	int idx;
	int ret;

	for (idx = 0; idx < qp_list->idx; idx++) {
		struct chrd_qp *qp = qp_list->qps[idx];

		xa_lock_irq(&qp->rhp->qps);
		spin_lock(&qp->lock);
		ret = cxgb4_uld_txq_sync_pidx(qp->rhp->rdev.lldi.ports[0],
					      qp->wq.sq.qid,
					      t4_sq_host_wq_pidx(&qp->wq),
					      t4_sq_wq_size(&qp->wq));
		if (ret) {
			pr_err("%s: Fatal error - "
			       "DB overflow recovery failed - "
			       "error syncing SQ qid %u\n",
			       ctx->lldi.name, qp->wq.sq.qid);
			return;
		}
		qp->wq.sq.wq_pidx_inc = 0;

		ret = cxgb4_uld_txq_sync_pidx(qp->rhp->rdev.lldi.ports[0],
					      qp->wq.rq.qid,
					      t4_rq_host_wq_pidx(&qp->wq),
					      t4_rq_wq_size(&qp->wq));

		if (ret) {
			pr_err("%s: Fatal error - "
			       "DB overflow recovery failed - "
			       "error syncing RQ qid %u\n",
			       ctx->lldi.name, qp->wq.rq.qid);
			return;
		}
		qp->wq.rq.wq_pidx_inc = 0;
		spin_unlock(&qp->lock);
		xa_unlock_irq(&qp->rhp->qps);

		/* Wait for the dbfifo to drain */
		while (cxgb4_dbfifo_count(qp->rhp->rdev.lldi.ports[0], 1) > 0) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(usecs_to_jiffies(10));
		}
	}
	for (idx = 0; idx < qp_list->ridx; idx++) {
		struct chrd_raw_qp *rqp = qp_list->rqps[idx];

		spin_lock_irq(&rqp->rhp->lock);
		ret = cxgb4_uld_txq_sync_pidx(rqp->rhp->rdev.lldi.ports[0],
					      rqp->txq.cntxt_id,
					      t4_txq_host_wq_pidx(&rqp->txq),
					      t4_txq_wq_size(&rqp->txq));
		if (ret) {
			pr_err("%s: Fatal error - "
			       "DB overflow recovery failed - "
			       "error syncing Raw TXQ qid %u\n",
			       ctx->lldi.name, rqp->txq.cntxt_id);
			return;
		}
		rqp->txq.pidx_inc = 0;

		ret = cxgb4_uld_txq_sync_pidx(rqp->rhp->rdev.lldi.ports[0],
					      rqp->fl.cntxt_id,
					      t4_fl_host_wq_pidx(&rqp->fl),
					      t4_fl_wq_size(&rqp->fl));

		if (ret) {
			pr_err("%s: Fatal error - "
			       "DB overflow recovery failed - "
			       "error syncing Raw FL qid %u\n",
			       ctx->lldi.name, rqp->fl.cntxt_id);
			return;
		}
		rqp->fl.pidx_inc = 0;
		spin_unlock_irq(&rqp->rhp->lock);

		/* Wait for the dbfifo to drain */
		while (cxgb4_dbfifo_count(rqp->rhp->rdev.lldi.ports[0], 1)
		       > 0) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(usecs_to_jiffies(10));
		}
	}
}

static void recover_queues(struct uld_ctx *ctx)
{
	struct chrd_qp *qp;
	struct chrd_raw_qp *rqp;
	unsigned long index;
	int count = 0;
	struct qp_list qp_list;
	int ret;

	/* slow everybody down */
	set_current_state(TASK_UNINTERRUPTIBLE);
	schedule_timeout(usecs_to_jiffies(1000));

	/* flush the SGE contexts */
	ret = cxgb4_flush_eq_cache(ctx->dev->rdev.lldi.ports[0]);
	if (ret) {
		pr_err("%s: Fatal error - DB overflow recovery failed\n",
		       ctx->lldi.name);
		return;
	}

	/* Count active queues so we can build a list of queues to recover */
	xa_lock_irq(&ctx->dev->qps);
	xa_lock_irq(&ctx->dev->rawqps);
	WARN_ON(ctx->dev->db_state != STOPPED);
	ctx->dev->db_state = RECOVERY;
	xa_for_each(&ctx->dev->qps, index, qp)
		count++;

	qp_list.qps = kzalloc(count * sizeof *qp_list.qps, GFP_ATOMIC);
	if (!qp_list.qps) {
		pr_err("%s: Fatal error - DB overflow recovery failed\n",
		       ctx->lldi.name);
		xa_unlock_irq(&ctx->dev->rawqps);
		xa_unlock_irq(&ctx->dev->qps);
		return;
	}
	qp_list.idx = 0;

	/* add and ref each qp so it doesn't get freed */
	xa_for_each(&ctx->dev->qps, index, qp) {
		chrd_iw_qp_add_ref(&qp->ibqp);
		qp_list.qps[qp_list.idx++] = qp;
	}

	count = 0;
	xa_for_each(&ctx->dev->rawqps, index, rqp)
		count++;

	qp_list.rqps = kzalloc(count * sizeof *qp_list.rqps, GFP_ATOMIC);
	if (!qp_list.rqps) {
		pr_err("%s: Fatal error - DB overflow recovery failed\n",
		       ctx->lldi.name);
		xa_unlock_irq(&ctx->dev->rawqps);
		xa_unlock_irq(&ctx->dev->qps);
		kfree(qp_list.qps);
		return;
	}
	qp_list.ridx = 0;
	
	/* add and ref each qp so it doesn't get freed */
	xa_for_each(&ctx->dev->rawqps, index, rqp) {
		chrd_iw_qp_add_ref(&rqp->ibqp);
		qp_list.rqps[qp_list.ridx++] = rqp;
	}

	xa_unlock_irq(&ctx->dev->rawqps);
	xa_unlock_irq(&ctx->dev->qps);
	
        /* now traverse the list in a safe context to recover the db state*/
	recover_lost_dbs(ctx, &qp_list);

	/* we're almost done!  deref the qps and clean up */
	deref_qps(&qp_list);
	kfree(qp_list.qps);
	kfree(qp_list.rqps);

	xa_lock_irq(&ctx->dev->qps);
	WARN_ON(ctx->dev->db_state != RECOVERY);
	ctx->dev->db_state = STOPPED;
	xa_unlock_irq(&ctx->dev->qps);
}

void chrd_dispatch_event(struct ib_device* ibdev,
                         u8 port_num,
                         enum ib_event_type type)
{
	struct ib_event event;

	memset(&event, 0, sizeof event);
	event.device 		= ibdev;
	event.element.port_num  = port_num;
	event.event             = type;

	ib_dispatch_event(&event);
}

static int chrd_uld_control(void *handle, enum cxgb4_control control, ...)
{
	struct uld_ctx *ctx = handle;
	va_list vargs;
	int port_num;

	va_start(vargs, control);

	switch (control) {
	case CXGB4_CONTROL_DB_FULL:
		stop_queues(ctx);
		ctx->dev->rdev.stats.db_full++;
		break;
	case CXGB4_CONTROL_DB_EMPTY:
		resume_queues(ctx);
		mutex_lock(&ctx->dev->rdev.stats.lock);
		ctx->dev->rdev.stats.db_empty++;
		mutex_unlock(&ctx->dev->rdev.stats.lock);
		break;
	case CXGB4_CONTROL_DB_DROP:
		recover_queues(ctx);
		mutex_lock(&ctx->dev->rdev.stats.lock);
		ctx->dev->rdev.stats.db_drop++;
		mutex_unlock(&ctx->dev->rdev.stats.lock);
		break;
	case CXGB4_CONTROL_MAC_ADDR_CHANGE:
		/* rdma port numbers starts from 1 */
		port_num = va_arg(vargs, int) + 1;

		if (ctx->dev)
			chrd_dispatch_event(&ctx->dev->ibdev,
					    (u8)port_num,
					    IB_EVENT_GID_CHANGE);
		break;
	default:
		pr_warn("%s: unknown control cmd %u\n",
			ctx->lldi.name, control);
		break;
	}

	va_end(vargs);
	return 0;
}

static struct cxgb4_uld_info chrd_uld_info = {
	.name = DRV_NAME,
	.add = chrd_uld_add,
	.rx_handler = chrd_uld_rx_handler,
	.state_change = chrd_uld_state_change,
	.control = chrd_uld_control,
};

void _chrd_free_wr_wait(struct kref *kref)
{
	struct chrd_wr_wait *wr_waitp;

	wr_waitp = container_of(kref, struct chrd_wr_wait, kref);
	pr_debug("Free wr_wait %p\n", wr_waitp);
	kfree(wr_waitp);
}

struct chrd_wr_wait *chrd_alloc_wr_wait(gfp_t gfp)
{
	struct chrd_wr_wait *wr_waitp;

	wr_waitp = kzalloc(sizeof(*wr_waitp), gfp);
	if (wr_waitp) {
		kref_init(&wr_waitp->kref);
		pr_debug("wr_wait %p\n", wr_waitp);
	}
	return wr_waitp;
}

static int __init chrd_init_module(void)
{
	int err;

	err = chrd_cm_init();
	if (err)
		return err;

	chrd_debugfs_root = debugfs_create_dir(DRV_NAME, NULL);

	reg_workq = create_singlethread_workqueue("Register_iWARP_device");
	if (!reg_workq) {
		pr_err("Failed creating workqueue to register iwarp device\n");
		return -ENOMEM;
	}

	cxgb4_register_uld_type(CXGB4_ULD_TYPE_RDMA, &chrd_uld_info);

	return 0;
}

static void __exit chrd_exit_module(void)
{
	struct uld_ctx *ctx, *tmp;

	mutex_lock(&dev_mutex);
	list_for_each_entry_safe(ctx, tmp, &uld_ctx_list, entry) {
		if (ctx->dev)
			chrd_remove(ctx);
		kfree(ctx);
	}
	mutex_unlock(&dev_mutex);
	flush_workqueue(reg_workq);
	destroy_workqueue(reg_workq);
	cxgb4_unregister_uld_type(CXGB4_ULD_TYPE_RDMA);
	chrd_cm_term();
	debugfs_remove_recursive(chrd_debugfs_root);
}

module_init(chrd_init_module);
module_exit(chrd_exit_module);
