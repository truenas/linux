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
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
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
#include "iw_cxgb4.h"
#include <clip_tbl.h>

#include <linux/module.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pci.h>

#include <rdma/ib_user_verbs.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_cache.h>

#include <net/xfrm.h>

#include <cxgbtool.h>

static int db_delay_usecs = 1;
module_param(db_delay_usecs, int, 0644);
MODULE_PARM_DESC(db_delay_usecs, "Usecs to delay awaiting db fifo to drain");

static int ocqp_support = 1;
module_param(ocqp_support, int, 0644);
MODULE_PARM_DESC(ocqp_support, "Support on-chip QPs (default=1)");

int allow_nonroot_rawqps = 0;
module_param(allow_nonroot_rawqps, int, 0644);
MODULE_PARM_DESC(allow_nonroot_rawqps,
		 "Allow nonroot access to raw qps (default = 0)");

static int max_fr_immd = T4_MAX_FR_IMMD;
module_param(max_fr_immd, int, 0644);
MODULE_PARM_DESC(max_fr_immd, "fastreg threshold for using DSGL instead of immediate");

#ifdef ARCH_HAS_IOREMAP_WC
int t5_en_wc = 1;
#else
int t5_en_wc = 0;
#endif

module_param(t5_en_wc, int, 0644);
MODULE_PARM_DESC(t5_en_wc, "Use BAR2/WC path for kernel users (default 1)");

static int alloc_ird(struct chrd_dev *dev, u32 ird)
{
	int ret;

	xa_lock_irq(&dev->qps);
	if (ird <= dev->avail_ird) {
		dev->avail_ird -= ird;
		ret = 0;
	} else {
		ret = -ENOMEM;
		pr_warn("%s: device IRD resources exhausted\n",
			dev->rdev.lldi.name);
	}
	xa_unlock_irq(&dev->qps);
	return ret;
}

static void free_ird(struct chrd_dev *dev, int ird)
{
	xa_lock_irq(&dev->qps);
	dev->avail_ird += ird;
	xa_unlock_irq(&dev->qps);
}

static void set_state(struct chrd_qp *qhp, enum chrd_qp_state state)
{
	unsigned long flag;
	spin_lock_irqsave(&qhp->lock, flag);
	qhp->attr.state = state;
	spin_unlock_irqrestore(&qhp->lock, flag);
}

//Todo: optimise this further by removing the conversions
static void set_v2_state(struct chrd_qp *qhp, enum chrd_v2_qp_state state)
{
	unsigned long flag;
	spin_lock_irqsave(&qhp->lock, flag);
	qhp->attr.state = state;
	spin_unlock_irqrestore(&qhp->lock, flag);
}

static void dealloc_oc_sq(struct chrd_rdev *rdev, struct t4_sq *sq)
{
	cxgb4_uld_ocqp_pool_free(rdev->lldi.ports[0], sq->dma_addr,
				 sq->memsize);
}

static void dealloc_host_sq(struct chrd_rdev *rdev, struct t4_sq *sq)
{
	dma_free_coherent(rdev->lldi.dev, sq->memsize, sq->queue,
			  dma_unmap_addr(sq, mapping));
}

static void dealloc_sq(struct chrd_rdev *rdev, struct t4_sq *sq)
{
	if (t4_sq_onchip(sq))
		dealloc_oc_sq(rdev, sq);
	else
		dealloc_host_sq(rdev, sq);
}

static int alloc_oc_sq(struct chrd_rdev *rdev, struct t4_sq *sq)
{
	if (!ocqp_support || !ocqp_supported(&rdev->lldi))
		return -ENOSYS;
	sq->dma_addr = cxgb4_uld_ocqp_pool_alloc(rdev->lldi.ports[0],
						 sq->memsize);
	if (!sq->dma_addr)
		return -ENOMEM;
	sq->phys_addr = rdev->oc_mw_pa + sq->dma_addr -
			rdev->lldi.vr->ocq.start;
	sq->queue = (__force union t4_wr *)(rdev->oc_mw_kva + sq->dma_addr -
					    rdev->lldi.vr->ocq.start);
	sq->flags |= T4_SQ_ONCHIP;
	return 0;
}

static int alloc_host_sq(struct chrd_rdev *rdev, struct t4_sq *sq)
{
	sq->queue = dma_alloc_coherent(rdev->lldi.dev, sq->memsize,
				       &(sq->dma_addr), GFP_KERNEL);
	if (!sq->queue)
		return -ENOMEM;
	sq->phys_addr = virt_to_phys(sq->queue);
	dma_unmap_addr_set(sq, mapping, sq->dma_addr);
	return 0;
}

static void *alloc_ring(struct chrd_dev *dev, size_t len, dma_addr_t *dma_addr,
			unsigned long *phys_addr, int onchip)
{
	void *p;

	if (onchip && ocqp_support && ocqp_supported(&dev->rdev.lldi)) {
		*dma_addr = cxgb4_uld_ocqp_pool_alloc(dev->rdev.lldi.ports[0],
						      len);
		if (!*dma_addr)
			goto offchip;
		*phys_addr = dev->rdev.oc_mw_pa + *dma_addr -
			     dev->rdev.lldi.vr->ocq.start;
		p = (void *)(dev->rdev.oc_mw_kva + *dma_addr -
			     dev->rdev.lldi.vr->ocq.start);
	} else {
offchip:
		p = dma_alloc_coherent(dev->rdev.lldi.dev, len, dma_addr,
				       GFP_KERNEL);
		if (!p)
			return NULL;
		*phys_addr = virt_to_phys(p);
	}
	memset(p, 0, len);
	return p;
}

static int get_fid(struct chrd_dev *dev, int count)
{
	int f;

	spin_lock_irq(&dev->lock);

	if (count == 1) {
		f = find_first_zero_bit(dev->rdev.fids, dev->rdev.nfids);
	} else {
		f = bitmap_find_next_zero_area(dev->rdev.fids, dev->rdev.nfids, 0, count, 3);
	}

	if (f >= dev->rdev.nfids)
		f = -1;
	else
		bitmap_set(dev->rdev.fids, f, count);
	spin_unlock_irq(&dev->lock);
	if (f >= 0)
		f += dev->rdev.lldi.uld_tids.hpftids.size;
	return f;
}

static int del_filter(struct chrd_raw_qp *rqp, int filter_id)
{
	struct filter_ctx ctx;
	int ret;

	init_completion(&ctx.completion);

	if (rqp->ibqp.qp_type ==  IB_QPT_RAW_ETH)
		filter_id += rqp->rhp->rdev.lldi.uld_tids.ftids.start -
			     rqp->rhp->rdev.lldi.uld_tids.hpftids.size;
	rtnl_lock();
	ret = cxgb4_uld_filter_delete(rqp->netdev, filter_id, NULL, &ctx,
				      GFP_KERNEL);
	rtnl_unlock();
	if (ret == -ENOENT) {
		ret = 0;
	} else if (!ret) {
		ret = chrd_wait(&rqp->rhp->rdev, &ctx.completion);
		if (!ret)
			ret = ctx.result;
	}
	return ret;
}

static void put_fid(struct chrd_raw_qp *rqp)
{
	int ret = 0;
	int i;

	for (i = 0; i < rqp->nfids; i++) {
		do {
			int filter_id;

			filter_id = rqp->fid + i;
			ret = del_filter(rqp, filter_id);
			if (!ret) {
				filter_id += rqp->rhp->rdev.nfids;
				ret = del_filter(rqp, filter_id);
			}
			if (!ret || ret != -EBUSY)
				break;
			if (chrd_fatal_error(&rqp->rhp->rdev)) {
				ret = -EIO;
				break;
			}
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(usecs_to_jiffies(500));
		} while (1);
	}

	if (ret && ret != -E2BIG)
		pr_warn("del filter %u failed ret %d\n",
		       rqp->fid, ret);
	else {
		u32 f;

		f = rqp->fid - rqp->rhp->rdev.lldi.uld_tids.hpftids.size;
		spin_lock_irq(&rqp->rhp->lock);
		bitmap_clear(rqp->rhp->rdev.fids, f, rqp->nfids);
		spin_unlock_irq(&rqp->rhp->lock);
	}
}

static void free_srq_queue(struct chrd_srq *srq,
			   struct cxgb4_dev_ucontext *uctx,
			   struct chrd_wr_wait *wr_waitp)
{
	struct chrd_rdev *rdev = &srq->rhp->rdev;
	struct sk_buff *skb = srq->destroy_skb;
	struct t4_srq *wq = &srq->wq;
	struct fw_ri_res_wr *res_wr;
	struct fw_ri_res *res;
	int wr_len;

	wr_len = sizeof *res_wr + sizeof *res;
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, NCHAN);

	res_wr = (struct fw_ri_res_wr *)__skb_put(skb, wr_len);
	memset(res_wr, 0, wr_len);
	res_wr->op_nres = cpu_to_be32(
			V_FW_WR_OP(FW_RI_RES_WR) |
			V_FW_RI_RES_WR_NRES(1) |
			F_FW_WR_COMPL);
	res_wr->len16_pkd = cpu_to_be32(DIV_ROUND_UP(wr_len, 16));
	res_wr->cookie = (uintptr_t)wr_waitp;
	res = res_wr->res;
	res->u.srq.restype = FW_RI_RES_TYPE_SRQ;
	res->u.srq.op = FW_RI_RES_OP_RESET;
	res->u.srq.srqid = cpu_to_be32(srq->idx);
	res->u.srq.eqid = cpu_to_be32(wq->qid);

	chrd_init_wr_wait(wr_waitp);
	chrd_ref_send_wait(rdev, skb, wr_waitp, 0, 0, __func__);

	dma_free_coherent(rdev->lldi.dev,
			  wq->memsize, wq->queue,
			  dma_unmap_addr(wq, mapping));
	chrd_rqtpool_free(rdev, wq->rqt_hwaddr, wq->rqt_size);
	kfree(wq->sw_rq);
	cxgb4_uld_put_qpid(uctx, wq->qid);
	return;
}

static int alloc_srq_queue(struct chrd_srq *srq,
			   struct cxgb4_dev_ucontext *uctx,
			   struct chrd_wr_wait *wr_waitp)
{
	struct chrd_rdev *rdev = &srq->rhp->rdev;
	int user = (uctx != &rdev->uctx);
	struct t4_srq *wq = &srq->wq;
	struct fw_ri_res_wr *res_wr;
	struct fw_ri_res *res;
	struct sk_buff *skb;
	int wr_len;
	int eqsize;
	int ret = -ENOMEM;

	wq->qid = cxgb4_uld_get_qpid(rdev->rdma_res, uctx);
	if (!wq->qid)
		goto err;

	if (!user) {
		wq->sw_rq = kzalloc(wq->size * sizeof *wq->sw_rq,
				 GFP_KERNEL);
		if (!wq->sw_rq)
			goto err_put_qpid;
		wq->pending_wrs = kzalloc(srq->wq.size * 
			sizeof *srq->wq.pending_wrs, GFP_KERNEL);
		if (!wq->pending_wrs)
			goto err_free_sw_rq;
	}

	wq->rqt_size = wq->size;
	wq->rqt_hwaddr = chrd_rqtpool_alloc(rdev, wq->rqt_size);
	if (!wq->rqt_hwaddr)
		goto err_free_pending_wrs;
	wq->rqt_abs_idx = (wq->rqt_hwaddr - rdev->lldi.vr->rq.start) >>
			     T4_RQT_ENTRY_SHIFT;

	wq->queue = dma_alloc_coherent(rdev->lldi.dev,
				       wq->memsize, &(wq->dma_addr),
				       GFP_KERNEL);
	if (!wq->queue)
		goto err_free_rqtpool;

	dma_unmap_addr_set(wq, mapping, wq->dma_addr);

	wq->bar2_va = chrd_bar2_addrs(rdev, wq->qid,
				      CXGB4_BAR2_QTYPE_EGRESS,
				      &wq->bar2_qid,
				      user ? &wq->bar2_pa : NULL);

	/*
	 * User mode must have bar2 access.
	 */
	if (user && !wq->bar2_va) {
		pr_warn(MOD "%s: srqid %u not in BAR2 range.\n",
			rdev->lldi.name, wq->qid);
		ret = -EINVAL;
		goto err_free_queue;
	}

	/* build fw_ri_res_wr */
	wr_len = sizeof *res_wr + sizeof *res;

	skb = alloc_skb(wr_len, GFP_KERNEL);
	if (!skb)
		goto err_free_queue;
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, NCHAN);

	res_wr = (struct fw_ri_res_wr *)__skb_put(skb, wr_len);
	memset(res_wr, 0, wr_len);
	res_wr->op_nres = cpu_to_be32(
			V_FW_WR_OP(FW_RI_RES_WR) |
			V_FW_RI_RES_WR_NRES(1) |
			F_FW_WR_COMPL);
	res_wr->len16_pkd = cpu_to_be32(DIV_ROUND_UP(wr_len, 16));
	res_wr->cookie = (uintptr_t)wr_waitp;
	res = res_wr->res;
	res->u.srq.restype = FW_RI_RES_TYPE_SRQ;
	res->u.srq.op = FW_RI_RES_OP_WRITE;

	/*
	 * eqsize is the number of 64B entries plus the status page size.
	 */
	eqsize = wq->size * T4_RQ_NUM_SLOTS +
		rdev->hw_queue.t4_eq_status_entries;
	res->u.srq.eqid = cpu_to_be32(wq->qid);
	res->u.srq.fetchszm_to_iqid = cpu_to_be32(
		V_FW_RI_RES_WR_HOSTFCMODE(0) |	/* no host cidx updates */
		V_FW_RI_RES_WR_CPRIO(0) |	/* don't keep in chip cache */
		V_FW_RI_RES_WR_PCIECHN(0) |	/* set by uP at ri_init time */
		V_FW_RI_RES_WR_FETCHRO(rdev->lldi.relaxed_ordering));
	res->u.srq.dcaen_to_eqsize = cpu_to_be32(
		V_FW_RI_RES_WR_DCAEN(0) |
		V_FW_RI_RES_WR_DCACPU(0) |
		V_FW_RI_RES_WR_FBMIN(2) |
		V_FW_RI_RES_WR_FBMAX(3) |
		V_FW_RI_RES_WR_CIDXFTHRESHO(0) |
		V_FW_RI_RES_WR_CIDXFTHRESH(0) |
		V_FW_RI_RES_WR_EQSIZE(eqsize));
	res->u.srq.eqaddr = cpu_to_be64(wq->dma_addr);
	res->u.srq.srqid = cpu_to_be32(srq->idx);
	res->u.srq.pdid = cpu_to_be32(srq->pdid);
	res->u.srq.hwsrqsize = cpu_to_be32(wq->rqt_size);
	res->u.srq.hwsrqaddr = cpu_to_be32(wq->rqt_hwaddr -
					   rdev->lldi.vr->rq.start);

	chrd_init_wr_wait(wr_waitp);

	ret = chrd_ref_send_wait(rdev, skb, wr_waitp, 0, wq->qid, __func__);
	if (ret)
		goto err_free_queue;

	pr_debug("srq %u eqid %u pdid %u queue va %p pa 0x%llx\n"
		 " bar2_addr %p rqt addr 0x%x size %d\n",
		 srq->idx, wq->qid, srq->pdid, wq->queue,
		 (u64)virt_to_phys(wq->queue), wq->bar2_va,
		 wq->rqt_hwaddr, wq->rqt_size);

	return 0;
err_free_queue:
	dma_free_coherent(rdev->lldi.dev,
			  wq->memsize, wq->queue,
			  dma_unmap_addr(wq, mapping));
err_free_rqtpool:
	chrd_rqtpool_free(rdev, wq->rqt_hwaddr, wq->rqt_size);
err_free_pending_wrs:
	if (!user)
		kfree(wq->pending_wrs);
err_free_sw_rq:
	if (!user)
		kfree(wq->sw_rq);
err_put_qpid:
	cxgb4_uld_put_qpid(uctx, wq->qid);
err:
	return ret;
}

static void free_raw_txq(struct chrd_dev *dev, struct chrd_raw_qp *rqp)
{
	struct fw_eq_eth_cmd c;
	int ret;

	pr_debug("cntxt_id %d\n", rqp->txq.cntxt_id);
	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_EQ_ETH_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_EQ_ETH_CMD_FREE | FW_LEN16(c));
	c.eqid_pkd = htonl(V_FW_EQ_ETH_CMD_EQID(rqp->txq.cntxt_id));
	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c, sizeof(c), &c);
	rtnl_unlock();

	if (ret) {
		pr_err("%s: %s mbox command failed with %d\n",
		       dev->rdev.lldi.name, __func__, ret);
		return;
	}
	if (rqp->txq.flags & T4_SQ_ONCHIP)
		cxgb4_uld_ocqp_pool_free(dev->rdev.lldi.ports[0],
					 rqp->txq.dma_addr, rqp->txq.memsize);
	else
		dma_free_coherent(dev->rdev.lldi.dev, rqp->txq.memsize, rqp->txq.desc,
				  rqp->txq.dma_addr);
}

static int alloc_raw_txq(struct chrd_dev *dev, struct chrd_raw_qp *rqp)
{
	int ret, nentries;
	struct fw_eq_eth_cmd c;
	struct t4_eth_txq *txq = &rqp->txq;
	struct fw_params_cmd c2;
	__be32 *p = &c2.param[0].mnem;
	u16 rid = dev->rdev.lldi.rxq_ids[cxgb4_port_idx(rqp->netdev)];

	/* Add status entries */
	nentries = txq->size * T4_TXQ_NUM_SLOTS +
		dev->rdev.hw_queue.t4_eq_status_entries;

	txq->desc = alloc_ring(dev, txq->memsize, &txq->dma_addr,
			       &txq->phys_addr, 1);
	if (!txq->desc)
		return -ENOMEM;

	if (chrd_onchip_pa(&dev->rdev, txq->phys_addr))
		txq->flags = T4_SQ_ONCHIP;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_EQ_ETH_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_EQ_ETH_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_EQ_ETH_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_EQ_ETH_CMD_ALLOC |
				 F_FW_EQ_ETH_CMD_EQSTART | (sizeof(c) / 16));
	c.autoequiqe_to_viid =
		htonl(V_FW_EQ_ETH_CMD_VIID(cxgb4_port_viid(rqp->netdev)));
	c.fetchszm_to_iqid =
		htonl(V_FW_EQ_ETH_CMD_HOSTFCMODE(X_HOSTFCMODE_NONE) |
		      (txq->flags & T4_SQ_ONCHIP ? F_FW_EQ_ETH_CMD_ONCHIP : 0) |
		      V_FW_EQ_ETH_CMD_PCIECHN(cxgb4_port_chan(rqp->netdev)) |
		      V_FW_EQ_ETH_CMD_FETCHRO(dev->rdev.lldi.relaxed_ordering) |
		      V_FW_EQ_ETH_CMD_IQID(rid));
	c.dcaen_to_eqsize =
		htonl(V_FW_EQ_ETH_CMD_FBMIN(X_FETCHBURSTMIN_64B) |
		      (txq->flags & T4_SQ_ONCHIP ?
			V_FW_EQ_ETH_CMD_FBMAX(X_FETCHBURSTMAX_256B) :
			V_FW_EQ_ETH_CMD_FBMAX(X_FETCHBURSTMAX_512B)) |
		      V_FW_EQ_ETH_CMD_CIDXFTHRESH(X_CIDXFLUSHTHRESH_32) |
		      V_FW_EQ_ETH_CMD_EQSIZE(nentries));
	c.eqaddr = cpu_to_be64(txq->dma_addr);

	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s mbox error %d\n", __func__, ret);
		if (rqp->txq.flags & T4_SQ_ONCHIP)
			cxgb4_uld_ocqp_pool_free(dev->rdev.lldi.ports[0],
						 rqp->txq.dma_addr,
						 rqp->txq.memsize);
		else
			dma_free_coherent(dev->rdev.lldi.dev, rqp->txq.memsize,
					  rqp->txq.desc, rqp->txq.dma_addr);
		return ret;
	}

	txq->cntxt_id = G_FW_EQ_ETH_CMD_EQID(ntohl(c.eqid_pkd));

	/*
	 * Tell uP to route SGE_EGR_UPDATE CPLs to the send cq.
	 */
	memset(&c2, 0, sizeof(c));
	c2.op_to_vfn = htonl(V_FW_CMD_OP(FW_PARAMS_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | 
			    V_FW_PARAMS_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_EQ_ETH_CMD_VFN(0));
	c2.retval_len16 = htonl(FW_LEN16(c));
	*p++ = htonl(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) | 
		V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_EQ_CMPLIQID_CTRL) |
		V_FW_PARAMS_PARAM_YZ(txq->cntxt_id));
	*p++ = htonl(rqp->scq->cq.cqid);

	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c2, sizeof(c2), &c2);
	rtnl_unlock();
	if (ret) {
		pr_err("%s mbox error (FW_PARAMS/DMAQ_EQ_CMPLIQID_CTRL) %d\n",
		       __func__, ret);
		free_raw_txq(dev, rqp);
		return ret;
	}
	pr_debug("cntxt_id %d size %d memsize %d dma_addr "
		 "%lx phys_addr %lx\n", txq->cntxt_id, txq->size,
		 txq->memsize, (unsigned long)txq->dma_addr, txq->phys_addr);
	return 0;
}

static void stop_raw_rxq(struct chrd_dev *dev, struct chrd_raw_qp *rqp)
{
	struct fw_iq_cmd c;
	int ret;

	pr_debug("iq cntxt_id %d\n", rqp->iq.cntxt_id);
	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = cpu_to_be32(F_FW_IQ_CMD_IQSTOP | FW_LEN16(c));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP));
	c.iqid = htons(rqp->iq.cntxt_id);
	c.fl0id = htons(rqp->fl.cntxt_id);
	c.fl1id = htons(0xffff);
	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret)
		pr_err(MOD "%s: %s mbox command failed with %d\n",
		       dev->rdev.lldi.name, __func__, ret);
}

static void free_raw_rxq(struct chrd_dev *dev, struct chrd_raw_qp *rqp)
{
	struct fw_iq_cmd c;
	int ret;

	pr_debug("iq cntxt_id %d\n", rqp->iq.cntxt_id);
	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_IQ_CMD_FREE | FW_LEN16(c));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP));
	c.iqid = htons(rqp->iq.cntxt_id);
	c.fl0id = htons(rqp->fl.cntxt_id);
	c.fl1id = htons(0xffff);
	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s: %s mbox command failed with %d\n",
		       dev->rdev.lldi.name, __func__, ret);
		return;
	}
	dma_free_coherent(dev->rdev.lldi.dev, rqp->iq.memsize, rqp->iq.desc,
			  rqp->iq.dma_addr);
	dma_free_coherent(dev->rdev.lldi.dev, rqp->fl.memsize, rqp->fl.desc,
			  rqp->fl.dma_addr);
}

static int alloc_raw_rxq(struct chrd_dev *dev, struct chrd_raw_qp *rqp)
{
	int ret, flsz = 0;
	struct fw_iq_cmd c;
	u16 rid = dev->rdev.lldi.ciq_ids[cxgb4_port_idx(rqp->netdev)];
	struct t4_iq *iq = &rqp->iq;
	struct t4_fl *fl = &rqp->fl;
	unsigned int chip_ver;

	chip_ver = CHELSIO_CHIP_VERSION(dev->rdev.lldi.adapter_type);
	iq->desc = alloc_ring(dev, iq->memsize, &iq->dma_addr, &iq->phys_addr,
			      0);
	if (!iq->desc)
		return -ENOMEM;

	fl->size = roundup(fl->size, 8);
	fl->desc = alloc_ring(dev, fl->memsize, &fl->dma_addr, &fl->phys_addr,
			      0);
	if (!fl->desc) {
		ret = -ENOMEM;
		goto err;
	}
	flsz = fl->size / 8 + dev->rdev.hw_queue.t4_eq_status_entries;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_IQ_CMD_ALLOC | F_FW_IQ_CMD_IQSTART |
				 (sizeof(c) / 16));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP) |
		V_FW_IQ_CMD_IQASYNCH(0) |
		V_FW_IQ_CMD_VIID(cxgb4_port_viid(rqp->netdev)) |
		V_FW_IQ_CMD_IQANUS(X_UPDATESCHEDULING_TIMER) |
		V_FW_IQ_CMD_IQANUD(X_UPDATEDELIVERY_INTERRUPT) |
		V_FW_IQ_CMD_IQANDST(X_INTERRUPTDESTINATION_IQ) |
		V_FW_IQ_CMD_IQANDSTINDEX(rid));
	c.iqdroprss_to_iqesize = htons(
		V_FW_IQ_CMD_IQPCIECH(cxgb4_port_chan(rqp->netdev)) |
		F_FW_IQ_CMD_IQO |
		V_FW_IQ_CMD_IQINTCNTTHRESH(0) |
		V_FW_IQ_CMD_IQESIZE(ilog2(T4_IQE_LEN) - 4));
	c.iqsize = htons(iq->size);
	c.iqaddr = cpu_to_be64(iq->dma_addr);

	c.iqns_to_fl0congen =
		htonl(V_FW_IQ_CMD_FL0HOSTFCMODE(X_HOSTFCMODE_NONE) |
		      F_FW_IQ_CMD_FL0CONGEN |
		      V_FW_IQ_CMD_IQTYPE(FW_IQ_IQTYPE_NIC) |
		      F_FW_IQ_CMD_FL0CONGCIF |
		      (fl->cong_drop ? F_FW_IQ_CMD_FL0CONGDROP : 0) |
		      V_FW_IQ_CMD_FL0FETCHRO(dev->rdev.lldi.relaxed_ordering) |
		      V_FW_IQ_CMD_FL0DATARO(dev->rdev.lldi.relaxed_ordering) |
		      (fl->packed ? F_FW_IQ_CMD_FL0PACKEN : 0)|
		      F_FW_IQ_CMD_FL0PADEN);
	c.fl0dcaen_to_fl0cidxfthresh =
		htons(V_FW_IQ_CMD_FL0FBMIN(X_FETCHBURSTMIN_64B) |
		      V_FW_IQ_CMD_FL0FBMAX(chip_ver <= CHELSIO_T5 ?
		      X_FETCHBURSTMAX_512B : X_FETCHBURSTMAX_256B));
	c.fl0size = htons(flsz);
	c.fl0addr = cpu_to_be64(fl->dma_addr);

	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s mbox error %d\n", __func__, ret);
		goto err;
	}

	iq->cntxt_id = ntohs(c.iqid);
	iq->size--;			/* subtract status entry */

	fl->cntxt_id = ntohs(c.fl0id);
	fl->avail = fl->pend_cred = 0;
	fl->pidx = fl->cidx = 0;
	fl->db = dev->rdev.lldi.db_reg;

	/* 
	 * Set the congestion management context to enable congestion control
	 * signals from SGE back to TP. This allows TP to drop on ingress when
	 * no FL bufs are available.  Otherwise the SGE can get stuck...
	 */
	if (!is_t4(dev->rdev.lldi.adapter_type)) {
		u32 v, conm;

		v = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
		    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_CONM_CTXT) |
		    V_FW_PARAMS_PARAM_YZ(iq->cntxt_id);
		conm = 1 << 19; /* CngTPMode 1 */
		rtnl_lock();
		ret = cxgb4_set_params(rqp->netdev, 1, &v, &conm);
		rtnl_unlock();
		if (ret) {
			pr_err("%s set conm ctx error %d\n", __func__,
			       ret);
			free_raw_rxq(dev, rqp);
			return ret;
		}
	}

	pr_debug("fl cntxt_id %d, size %d memsize %d, "
		 "iq cntxt_id %d size %d memsize %d packed %u\n", fl->cntxt_id,
		 fl->size, fl->memsize, iq->cntxt_id, iq->size, iq->memsize, fl->packed);
	return 0;
err:
	if (iq->desc)
		dma_free_coherent(dev->rdev.lldi.dev, iq->memsize, iq->desc,
				  iq->dma_addr);
	if (fl && fl->desc)
		dma_free_coherent(dev->rdev.lldi.dev, fl->memsize, fl->desc,
				  fl->dma_addr);
	return ret;
}

static void free_raw_srq(struct chrd_dev *dev, struct chrd_raw_srq *srq)
{
	struct fw_iq_cmd c;
	int ret;

	pr_debug("iq cntxt_id %d\n", srq->iq.cntxt_id);
	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_IQ_CMD_FREE | FW_LEN16(c));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP));
	c.iqid = htons(srq->iq.cntxt_id);
	c.fl0id = htons(srq->fl.cntxt_id);
	c.fl1id = htons(0xffff);
	rtnl_lock();
	ret = cxgb4_wr_mbox(srq->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s: %s mbox command failed with %d\n",
		       dev->rdev.lldi.name, __func__, ret);
		return;
	}
	dma_free_coherent(dev->rdev.lldi.dev, srq->iq.memsize, srq->iq.desc,
			  srq->iq.dma_addr);
	dma_free_coherent(dev->rdev.lldi.dev, srq->fl.memsize, srq->fl.desc,
			  srq->fl.dma_addr);
}

static int alloc_raw_srq(struct chrd_dev *dev, struct chrd_raw_srq *srq)
{
	int ret, flsz = 0;
	struct fw_iq_cmd c;
	u16 rid = dev->rdev.lldi.ciq_ids[cxgb4_port_idx(srq->netdev)];
	struct t4_iq *iq = &srq->iq;
	struct t4_fl *fl = &srq->fl;
	unsigned int chip_ver;

	chip_ver = CHELSIO_CHIP_VERSION(dev->rdev.lldi.adapter_type);
	iq->desc = alloc_ring(dev, iq->memsize, &iq->dma_addr, &iq->phys_addr,
			      0);
	if (!iq->desc)
		return -ENOMEM;

	fl->size = roundup(fl->size, 8);
	fl->desc = alloc_ring(dev, fl->memsize, &fl->dma_addr, &fl->phys_addr,
			      0);
	if (!fl->desc) {
 		ret = -ENOMEM;
 		goto err;
 	}
	flsz = fl->size / 8 + dev->rdev.hw_queue.t4_eq_status_entries;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_IQ_CMD_ALLOC | F_FW_IQ_CMD_IQSTART |
				 (sizeof(c) / 16));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP) |
		V_FW_IQ_CMD_IQASYNCH(0) |
		V_FW_IQ_CMD_VIID(cxgb4_port_viid(srq->netdev)) |
		V_FW_IQ_CMD_IQANUS(X_UPDATESCHEDULING_TIMER) |
		V_FW_IQ_CMD_IQANUD(X_UPDATEDELIVERY_INTERRUPT) |
		V_FW_IQ_CMD_IQANDST(X_INTERRUPTDESTINATION_IQ) |
		V_FW_IQ_CMD_IQANDSTINDEX(rid));
	c.iqdroprss_to_iqesize = htons(
		V_FW_IQ_CMD_IQPCIECH(cxgb4_port_chan(srq->netdev)) |
		F_FW_IQ_CMD_IQO |
		V_FW_IQ_CMD_IQINTCNTTHRESH(0) |
		V_FW_IQ_CMD_IQESIZE(ilog2(T4_IQE_LEN) - 4));
	c.iqsize = htons(iq->size);
	c.iqaddr = cpu_to_be64(iq->dma_addr);

	c.iqns_to_fl0congen =
		htonl(V_FW_IQ_CMD_FL0HOSTFCMODE(X_HOSTFCMODE_NONE) |
		      F_FW_IQ_CMD_FL0CONGEN |
		      V_FW_IQ_CMD_IQTYPE(FW_IQ_IQTYPE_NIC) |
		      F_FW_IQ_CMD_FL0CONGCIF |
		      V_FW_IQ_CMD_FL0FETCHRO(dev->rdev.lldi.relaxed_ordering) |
		      V_FW_IQ_CMD_FL0DATARO(dev->rdev.lldi.relaxed_ordering) |
		      (fl->packed ? F_FW_IQ_CMD_FL0PACKEN : 0)|
		      F_FW_IQ_CMD_FL0PADEN);
	c.fl0dcaen_to_fl0cidxfthresh =
		htons(V_FW_IQ_CMD_FL0FBMIN(X_FETCHBURSTMIN_64B) |
		      V_FW_IQ_CMD_FL0FBMAX(chip_ver <= CHELSIO_T5 ?
		      X_FETCHBURSTMAX_512B : X_FETCHBURSTMAX_256B));
	c.fl0size = htons(flsz);
	c.fl0addr = cpu_to_be64(fl->dma_addr);

	rtnl_lock();
	ret = cxgb4_wr_mbox(srq->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s mbox error %d\n", __func__, ret);
		goto err;
	}

	iq->cntxt_id = ntohs(c.iqid);
	iq->size--;			/* subtract status entry */

	fl->cntxt_id = ntohs(c.fl0id);
	fl->avail = fl->pend_cred = 0;
	fl->pidx = fl->cidx = 0;
	fl->db = dev->rdev.lldi.db_reg;

	/* 
	 * Set the congestion management context to enable congestion control
	 * signals from SGE back to TP. This allows TP to drop on ingress when
	 * no FL bufs are available.  Otherwise the SGE can get stuck...
	 */
	if (!is_t4(dev->rdev.lldi.adapter_type)) {
		u32 v, conm;

		v = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
		    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_CONM_CTXT) |
		    V_FW_PARAMS_PARAM_YZ(iq->cntxt_id);
		conm = 1 << 19; /* CngTPMode 1 */
		rtnl_lock();
		ret = cxgb4_set_params(srq->netdev, 1, &v, &conm);
		rtnl_unlock();
		if (ret) {
			pr_err("%s set conm ctx error %d\n", __func__,
			       ret);
			free_raw_srq(dev, srq);
			return ret;
		}
	}

	pr_debug("fl cntxt_id %d, size %d memsize %d, "
		 "iq cntxt_id %d size %d memsize %d packed %u\n", fl->cntxt_id,
		 fl->size, fl->memsize, iq->cntxt_id, iq->size, iq->memsize, fl->packed);
	return 0;
err:
	if (iq->desc)
		dma_free_coherent(dev->rdev.lldi.dev, iq->memsize, iq->desc,
				  iq->dma_addr);
	if (fl && fl->desc)
		dma_free_coherent(dev->rdev.lldi.dev, fl->memsize, fl->desc,
				  fl->dma_addr);
	return ret;
}

static int free_rc_queues(struct chrd_rdev *rdev, struct t4_wq *wq,
			  struct cxgb4_dev_ucontext *uctx, int has_rq)
{
	/*
	 * uP clears EQ contexts when the connection exits rdma mode,
	 * so no need to post a RESET WR for these EQs.
	 */
	if (has_rq)
		dma_free_coherent(rdev->lldi.dev,
				  wq->rq.memsize, wq->rq.queue,
				  dma_unmap_addr(&wq->rq, mapping));
	dealloc_sq(rdev, &wq->sq);
	if (has_rq) {
		chrd_rqtpool_free(rdev, wq->rq.rqt_hwaddr, wq->rq.rqt_size);
		kfree(wq->rq.sw_rq);
	}
	kfree(wq->sq.sw_sq);
	if (has_rq)
		cxgb4_uld_put_qpid(uctx, wq->rq.qid);
	cxgb4_uld_put_qpid(uctx, wq->sq.qid);
	return 0;
}

/*
 * Determine the BAR2 virtual address and qid. If pbar2_pa is not NULL,
 * then this is a user mapping so compute the page-aligned physical address
 * for mapping.
 */
void __iomem *chrd_bar2_addrs(struct chrd_rdev *rdev, unsigned int qid,
			      enum cxgb4_bar2_qtype qtype,
			      unsigned int *pbar2_qid, u64 *pbar2_pa)
{
	u64 bar2_qoffset;
	int ret;

	ret = cxgb4_bar2_sge_qregs(rdev->lldi.ports[0], qid, qtype,
				   pbar2_pa ? 1 : 0,
				   &bar2_qoffset, pbar2_qid);
	if (ret)
		return NULL;

	if (pbar2_pa)
		*pbar2_pa = (rdev->bar2_pa + bar2_qoffset) & PAGE_MASK;

	if (is_t4(rdev->lldi.adapter_type))
		return NULL;

	return rdev->bar2_kva + bar2_qoffset;
}

static int alloc_rc_queues(struct chrd_dev *rhp, struct chrd_qp *qhp,
			   struct t4_cq *rcq, struct t4_cq *scq,
			   struct cxgb4_dev_ucontext *uctx, int need_rq)
{
	struct chrd_wr_wait *wr_waitp = qhp->wr_waitp;
	struct chrd_rdev *rdev = &rhp->rdev;
	struct t4_wq *wq = &qhp->wq;
	struct fw_ri_res_wr *res_wr;
	struct fw_ri_res *res;
	struct sk_buff *skb;
	int user = (uctx != &rdev->uctx);
	int eqsize;
	int wr_len;
	int ret;

	wq->sq.qid = cxgb4_uld_get_qpid(rdev->rdma_res, uctx);
	if (!wq->sq.qid)
		return -ENOMEM;

	if (need_rq) {
		wq->rq.qid = cxgb4_uld_get_qpid(rdev->rdma_res, uctx);
		if (!wq->rq.qid)
			goto err1;
	}

	if (!user) {
		wq->sq.sw_sq = kzalloc(wq->sq.size * sizeof *wq->sq.sw_sq,
				 GFP_KERNEL);
		if (!wq->sq.sw_sq)
			goto err2;

		if (need_rq) {
			wq->rq.sw_rq = kzalloc(wq->rq.size * sizeof *wq->rq.sw_rq,
					 GFP_KERNEL);
			if (!wq->rq.sw_rq)
				goto err3;
		}
	}

	if (need_rq) {

		/*
		 * RQT must be a power of 2 and at least 16 deep.
		 */
		wq->rq.rqt_size = roundup_pow_of_two(max_t(u16, wq->rq.size, 16));
		wq->rq.rqt_hwaddr = chrd_rqtpool_alloc(rdev, wq->rq.rqt_size);
		if (!wq->rq.rqt_hwaddr)
			goto err4;
	}
	/* ToDo: Need RRQT populating support similar to above rqt pool alloc in FW */

	if (user) {
		if (alloc_oc_sq(rdev, &wq->sq) && alloc_host_sq(rdev, &wq->sq))
			goto err5;
	} else
		if (alloc_host_sq(rdev, &wq->sq))
			goto err5;
	memset(wq->sq.queue, 0, wq->sq.memsize);

	if (need_rq) {
		wq->rq.queue = dma_alloc_coherent(rdev->lldi.dev,
						  wq->rq.memsize, &(wq->rq.dma_addr),
						  GFP_KERNEL);
		if (!wq->rq.queue)
			goto err6;
		dma_unmap_addr_set(&wq->rq, mapping, wq->rq.dma_addr);
	}
	wq->db = rdev->lldi.db_reg;

	wq->sq.bar2_va = chrd_bar2_addrs(rdev, wq->sq.qid,
					 CXGB4_BAR2_QTYPE_EGRESS,
					 &wq->sq.bar2_qid, 
					 user ? &wq->sq.bar2_pa : NULL);
	if (need_rq)
		wq->rq.bar2_va = chrd_bar2_addrs(rdev, wq->rq.qid,
						 CXGB4_BAR2_QTYPE_EGRESS,
						 &wq->rq.bar2_qid,
						 user ? &wq->rq.bar2_pa : NULL);

	pr_debug("sq base va 0x%p pa 0x%llx rq base va 0x%p pa 0x%llx\n",
		 wq->sq.queue, (u64)virt_to_phys(wq->sq.queue),
		 wq->rq.queue, need_rq ? (u64)virt_to_phys(wq->rq.queue) : 0);

	/*
	 * User mode must have bar2 access.
	 */
	if (user && (!wq->sq.bar2_pa || (need_rq && !wq->rq.bar2_pa))) {
		pr_warn("%s: sqid %u or rqid %u not in BAR2 range.\n",
			rdev->lldi.name, wq->sq.qid, wq->rq.qid);
		goto err7;
	}

	wq->rdev = rdev;
	wq->rq.msn = 1;

	/* build fw_ri_res_wr */
	wr_len = sizeof *res_wr + sizeof *res;
	if (need_rq)
		wr_len += sizeof *res;

	skb = alloc_skb(wr_len, GFP_KERNEL | __GFP_NOFAIL);
	if (!skb) {
		ret = -ENOMEM;
		goto err7;
	}
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, NCHAN);

	res_wr = (struct fw_ri_res_wr *)__skb_put(skb, wr_len);
	memset(res_wr, 0, wr_len);
	res_wr->op_nres = cpu_to_be32(
			V_FW_WR_OP(FW_RI_RES_WR) |
			V_FW_RI_RES_WR_NRES(need_rq ? 2 : 1) |
			F_FW_WR_COMPL);
	res_wr->len16_pkd = cpu_to_be32(DIV_ROUND_UP(wr_len, 16));
	res_wr->cookie = (uintptr_t)wr_waitp;
	res = res_wr->res;
	res->u.sqrq.restype = FW_RI_RES_TYPE_SQ;
	res->u.sqrq.op = FW_RI_RES_OP_WRITE;

	/*
	 * eqsize is the number of 64B entries plus the status page size.
	 */
	eqsize = wq->sq.size * T4_SQ_NUM_SLOTS +
		rdev->hw_queue.t4_eq_status_entries;

	res->u.sqrq.fetchszm_to_iqid = cpu_to_be32(
		V_FW_RI_RES_WR_HOSTFCMODE(0) |	/* no host cidx updates */
		V_FW_RI_RES_WR_CPRIO(0) |	/* don't keep in chip cache */
		V_FW_RI_RES_WR_PCIECHN(0) |	/* set by uP at ri_init time */
		t4_sq_onchip(&wq->sq) ? F_FW_RI_RES_WR_ONCHIP : 0 |
		V_FW_RI_RES_WR_FETCHRO(rdev->lldi.relaxed_ordering) | 
		V_FW_RI_RES_WR_IQID(scq->cqid));
	res->u.sqrq.dcaen_to_eqsize = cpu_to_be32(
		V_FW_RI_RES_WR_DCAEN(0) |
		V_FW_RI_RES_WR_DCACPU(0) |
		V_FW_RI_RES_WR_FBMIN(2) |
		(t4_sq_onchip(&wq->sq) ? V_FW_RI_RES_WR_FBMAX(2) : V_FW_RI_RES_WR_FBMAX(3)) |
		V_FW_RI_RES_WR_CIDXFTHRESHO(0) |
		V_FW_RI_RES_WR_CIDXFTHRESH(0) |
		V_FW_RI_RES_WR_EQSIZE(eqsize));
	res->u.sqrq.eqid = cpu_to_be32(wq->sq.qid);
	res->u.sqrq.eqaddr = cpu_to_be64(wq->sq.dma_addr);
	if (need_rq) {
		res++;
		res->u.sqrq.restype = FW_RI_RES_TYPE_RQ;
		res->u.sqrq.op = FW_RI_RES_OP_WRITE;

		/*
		 * eqsize is the number of 64B entries plus the status page size.
		 */
		eqsize = wq->rq.size * T4_RQ_NUM_SLOTS +
			rdev->hw_queue.t4_eq_status_entries;
		res->u.sqrq.fetchszm_to_iqid = cpu_to_be32(
			V_FW_RI_RES_WR_HOSTFCMODE(0) |	/* no host cidx updates */
			V_FW_RI_RES_WR_CPRIO(0) |	/* don't keep in chip cache */
			V_FW_RI_RES_WR_PCIECHN(0) |	/* set by uP at ri_init time */
			V_FW_RI_RES_WR_FETCHRO(rdev->lldi.relaxed_ordering) | 
			V_FW_RI_RES_WR_IQID(rcq->cqid));
		res->u.sqrq.dcaen_to_eqsize = cpu_to_be32(
			V_FW_RI_RES_WR_DCAEN(0) |
			V_FW_RI_RES_WR_DCACPU(0) |
			V_FW_RI_RES_WR_FBMIN(2) |
			V_FW_RI_RES_WR_FBMAX(3) |
			V_FW_RI_RES_WR_CIDXFTHRESHO(0) |
			V_FW_RI_RES_WR_CIDXFTHRESH(0) |
			V_FW_RI_RES_WR_EQSIZE(eqsize));
		res->u.sqrq.eqid = cpu_to_be32(wq->rq.qid);
		res->u.sqrq.eqaddr = cpu_to_be64(wq->rq.dma_addr);
	}

	chrd_init_wr_wait(wr_waitp);

	ret = chrd_ref_send_wait(rdev, skb, wr_waitp, 0, wq->sq.qid, __func__);
	if (ret)
		goto err7;

	pr_debug("sqid 0x%x rqid 0x%x kdb 0x%p sq_bar2_addr %p rq_bar2_addr %p\n",
		 wq->sq.qid, wq->rq.qid, wq->db, wq->sq.bar2_va,
		 wq->rq.bar2_va);

	return 0;
err7:
	if (need_rq)
		dma_free_coherent(rdev->lldi.dev,
				  wq->rq.memsize, wq->rq.queue,
				  dma_unmap_addr(&wq->rq, mapping));
err6:
	dealloc_sq(rdev, &wq->sq);
err5:
	if (need_rq)
		chrd_rqtpool_free(rdev, wq->rq.rqt_hwaddr, wq->rq.rqt_size);
err4:
	if (need_rq)
		kfree(wq->rq.sw_rq);
err3:
	kfree(wq->sq.sw_sq);
err2:
	if (need_rq)
		cxgb4_uld_put_qpid(uctx, wq->rq.qid);
err1:
	cxgb4_uld_put_qpid(uctx, wq->sq.qid);
	return -ENOMEM;
}

void chrd_copy_wr_to_srq(struct t4_srq *srq, union t4_recv_wr *wqe, u8 len16)
{
	u64 *src, *dst;

	src = (u64 *)wqe;
	dst = (u64 *)((u8 *)srq->queue + srq->wq_pidx * T4_EQ_ENTRY_SIZE);
	while (len16) {
		*dst++ = *src++;
		if (dst >= (u64 *)&srq->queue[srq->size])
			dst = (u64 *)srq->queue;
		*dst++ = *src++;
		if (dst >= (u64 *)&srq->queue[srq->size])
			dst = (u64 *)srq->queue;
		len16--;
	}
}

static int build_immd(struct t4_sq *sq, struct fw_ri_immd *immdp,
		      const struct ib_send_wr *wr, int max, u32 *plenp)
{
	u8 *dstp, *srcp;
	u32 plen = 0;
	int i;
	int rem, len;

	dstp = (u8 *)immdp->data;
	for (i = 0; i < wr->num_sge; i++) {
		if ((plen + wr->sg_list[i].length) > max)
			return -EMSGSIZE;
		srcp = (u8 *)(unsigned long)wr->sg_list[i].addr;
		plen += wr->sg_list[i].length;
		rem = wr->sg_list[i].length;
		while (rem) {
			if (dstp == (u8 *)&sq->queue[sq->size])
				dstp = (u8 *)sq->queue;
			if (rem <= (u8 *)&sq->queue[sq->size] - dstp)
				len = rem;
			else
				len = (u8 *)&sq->queue[sq->size] - dstp;
			memcpy(dstp, srcp, len);
			dstp += len;
			srcp += len;
			rem -= len;
		}
	}
	len = roundup(plen + sizeof *immdp, 16) - (plen + sizeof *immdp);
	if (len)
		memset(dstp, 0, len);
	immdp->op = FW_RI_DATA_IMMD;
	immdp->r1 = 0;
	immdp->r2 = 0;
	immdp->immdlen = cpu_to_be32(plen);
	*plenp = plen;
	return 0;
}

static int build_isgl(__be64 *queue_start, __be64 *queue_end,
		      struct fw_ri_isgl *isglp, struct ib_sge *sg_list,
		      int num_sge, u32 *plenp)

{
	int i;
	u32 plen = 0;
	__be64 *flitp;

	if ((__be64 *)isglp == queue_end)
		isglp = (struct fw_ri_isgl *)queue_start;

	flitp = (__be64 *)isglp->sge;

	for (i = 0; i < num_sge; i++) {
		if ((plen + sg_list[i].length) < plen)
			return -EMSGSIZE;
		plen += sg_list[i].length;
		*flitp = cpu_to_be64(((u64)sg_list[i].lkey << 32) |
				     sg_list[i].length);
		if (++flitp == queue_end)
			flitp = queue_start;
		*flitp = cpu_to_be64(sg_list[i].addr);
		if (++flitp == queue_end)
			flitp = queue_start;
	}
	*flitp = (__force __be64)0;
	isglp->op = FW_RI_DATA_ISGL;
	isglp->r1 = 0;
	isglp->nsge = cpu_to_be16(num_sge);
	isglp->r2 = 0;
	if (plenp)
		*plenp = plen;
	return 0;
}

static int build_rdma_send(struct t4_sq *sq, union t4_wr *wqe,
			   const struct ib_send_wr *wr, u8 *len16)
{
	u32 plen;
	int size;
	int ret;

	if (wr->num_sge > T4_MAX_SEND_SGE)
		return -EINVAL;
	switch (wr->opcode) {
	case IB_WR_SEND:
		if (wr->send_flags & IB_SEND_SOLICITED)
			wqe->send.sendop_pkd = cpu_to_be32(
				V_FW_RI_SEND_WR_SENDOP(FW_RI_SEND_WITH_SE));
		else
			wqe->send.sendop_pkd = cpu_to_be32(
				V_FW_RI_SEND_WR_SENDOP(FW_RI_SEND));
		wqe->send.stag_inv = 0;
		break;
	case IB_WR_SEND_WITH_INV:
		if (wr->send_flags & IB_SEND_SOLICITED)
			wqe->send.sendop_pkd = cpu_to_be32(
				V_FW_RI_SEND_WR_SENDOP(FW_RI_SEND_WITH_SE_INV));
		else
			wqe->send.sendop_pkd = cpu_to_be32(
				V_FW_RI_SEND_WR_SENDOP(FW_RI_SEND_WITH_INV));
		wqe->send.stag_inv = cpu_to_be32(wr->ex.invalidate_rkey);
		break;

	default:
		return -EINVAL;
	}
	wqe->send.r3 = 0;
	wqe->send.r4 = 0;

	plen = 0;
	if (wr->num_sge) {
		if (wr->send_flags & IB_SEND_INLINE) {
			ret = build_immd(sq, wqe->send.u.immd_src, wr,
					 T4_MAX_SEND_INLINE, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->send + sizeof(struct fw_ri_immd) +
			       plen;
		} else {
			ret = build_isgl((__be64 *)sq->queue,
					 (__be64 *)&sq->queue[sq->size],
					 wqe->send.u.isgl_src,
					 wr->sg_list, wr->num_sge, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->send + sizeof(struct fw_ri_isgl) +
			       wr->num_sge * sizeof(struct fw_ri_sge);
		}
	} else {
		wqe->send.u.immd_src[0].op = FW_RI_DATA_IMMD;
		wqe->send.u.immd_src[0].r1 = 0;
		wqe->send.u.immd_src[0].r2 = 0;
		wqe->send.u.immd_src[0].immdlen = 0;
		size = sizeof wqe->send + sizeof(struct fw_ri_immd);
		plen = 0;
	}
	*len16 = DIV_ROUND_UP(size, 16);
	wqe->send.plen = cpu_to_be32(plen);
	return 0;
}

static int build_rdma_write(struct t4_sq *sq, union t4_wr *wqe,
			    const struct ib_send_wr *wr, u8 *len16)
{
	u32 plen;
	int size;
	int ret;

	if (wr->num_sge > T4_MAX_SEND_SGE)
		return -EINVAL;
	if (wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM)
		wqe->write.immd_data = wr->ex.imm_data;
	else
		wqe->write.immd_data = 0;
	wqe->write.stag_sink = cpu_to_be32(rdma_wr(wr)->rkey);
	wqe->write.to_sink = cpu_to_be64(rdma_wr(wr)->remote_addr);
	if (wr->num_sge) {
		if (wr->send_flags & IB_SEND_INLINE) {
			ret = build_immd(sq, wqe->write.u.immd_src, wr,
					 T4_MAX_WRITE_INLINE, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->write + sizeof(struct fw_ri_immd) +
			       plen;
		} else {
			ret = build_isgl((__be64 *)sq->queue,
					 (__be64 *)&sq->queue[sq->size],
					 wqe->write.u.isgl_src,
					 wr->sg_list, wr->num_sge, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->write + sizeof(struct fw_ri_isgl) +
			       wr->num_sge * sizeof(struct fw_ri_sge);
		}
	} else {
		wqe->write.u.immd_src[0].op = FW_RI_DATA_IMMD;
		wqe->write.u.immd_src[0].r1 = 0;
		wqe->write.u.immd_src[0].r2 = 0;
		wqe->write.u.immd_src[0].immdlen = 0;
		size = sizeof wqe->write + sizeof(struct fw_ri_immd);
		plen = 0;
	}
	*len16 = DIV_ROUND_UP(size, 16);
	wqe->write.plen = cpu_to_be32(plen);
	return 0;
}

static void build_immd_cmpl(struct t4_sq *sq, struct fw_ri_immd_cmpl *immdp,
			   const struct ib_send_wr *wr)
{
	memcpy((u8 *)immdp->data, (u8 *)(uintptr_t)wr->sg_list->addr, 16);
	memset(immdp->r1, 0, 6);
	immdp->op = FW_RI_DATA_IMMD;
	immdp->immdlen = 16;
	return;
}

static void build_rdma_write_cmpl(struct t4_sq *sq,
				  struct fw_ri_rdma_write_cmpl_wr *wcwr,
				  const struct ib_send_wr *wr, u8 *len16)
{
	u32 plen;
	int size;

	/*
	 * This code assumes the struct fields preceeding the write isgl
	 * fit in one 64B WR slot.  This is because the WQE is built
	 * directly in the dma queue, and wrapping is only handled
	 * by the code buildling sgls.  IE the "fixed part" of the wr
	 * structs must all fit in 64B.  The WQE build code should probably be
	 * redesigned to avoid this restriction, but for now just add
	 * the BUILD_BUG_ON() to catch if this WQE struct gets too big.
	 */
	BUILD_BUG_ON(offsetof(struct fw_ri_rdma_write_cmpl_wr, u) > 64);

	wcwr->stag_sink = cpu_to_be32(rdma_wr(wr)->rkey);
	wcwr->to_sink = cpu_to_be64(rdma_wr(wr)->remote_addr);
	if (wr->next->opcode == IB_WR_SEND)
		wcwr->stag_inv = 0;
	else
		wcwr->stag_inv = cpu_to_be32(wr->next->ex.invalidate_rkey);
	wcwr->r2 = 0;
	wcwr->r3 = 0;

 	/* SEND_INV SGL */
	if (wr->next->send_flags & IB_SEND_INLINE)
		build_immd_cmpl(sq, &wcwr->u_cmpl.immd_src, wr->next);
	else
		build_isgl((__be64 *)sq->queue, (__be64 *)&sq->queue[sq->size],
			   &wcwr->u_cmpl.isgl_src, wr->next->sg_list, 1, NULL);

	/* WRITE SGL */
	build_isgl((__be64 *)sq->queue, (__be64 *)&sq->queue[sq->size],
		   wcwr->u.isgl_src, wr->sg_list, wr->num_sge, &plen);

	size = sizeof *wcwr + sizeof(struct fw_ri_isgl) +
	       wr->num_sge * sizeof(struct fw_ri_sge);
	wcwr->plen = cpu_to_be32(plen);
	*len16 = DIV_ROUND_UP(size, 16);

	return;
}

static int build_rdma_read(union t4_wr *wqe, const struct ib_send_wr *wr, u8 *len16)
{
	if (wr->num_sge > 1)
		return -EINVAL;
	if (wr->num_sge && wr->sg_list[0].length) {
		wqe->read.stag_src = cpu_to_be32(rdma_wr(wr)->rkey);
		wqe->read.to_src_hi = cpu_to_be32((u32)(rdma_wr(wr)->remote_addr
							>> 32));
		wqe->read.to_src_lo = cpu_to_be32((u32)rdma_wr(wr)->remote_addr);
		wqe->read.stag_sink = cpu_to_be32(wr->sg_list[0].lkey);
		wqe->read.plen = cpu_to_be32(wr->sg_list[0].length);
		wqe->read.to_sink_hi = cpu_to_be32((u32)(wr->sg_list[0].addr
							 >> 32));
		wqe->read.to_sink_lo = cpu_to_be32((u32)(wr->sg_list[0].addr));
	} else {
		wqe->read.stag_src = cpu_to_be32(2);
		wqe->read.to_src_hi = 0;
		wqe->read.to_src_lo = 0;
		wqe->read.stag_sink = cpu_to_be32(2);
		wqe->read.plen = 0;
		wqe->read.to_sink_hi = 0;
		wqe->read.to_sink_lo = 0;
	}
	wqe->read.r2 = 0;
	wqe->read.r5 = 0;
	*len16 = DIV_ROUND_UP(sizeof wqe->read, 16);
	return 0;
}

static int build_rdma_recv(struct t4_wq *wq, union t4_recv_wr *wqe,
			   const struct ib_recv_wr *wr, u8 *len16)
{
	int ret;

	ret = build_isgl((__be64 *)wq->rq.queue,
			 (__be64 *)&wq->rq.queue[wq->rq.size],
			 &wqe->recv.isgl, wr->sg_list, wr->num_sge, NULL);
	if (ret)
		return ret;
	*len16 = DIV_ROUND_UP(sizeof wqe->recv +
			      wr->num_sge * sizeof(struct fw_ri_sge), 16);
	return 0;
}

static int build_srq_recv(union t4_recv_wr *wqe, const struct ib_recv_wr *wr,
			  u8 *len16)
{
	int ret;

	ret = build_isgl((__be64 *)wqe, (__be64 *)(wqe + 1),
			 &wqe->recv.isgl, wr->sg_list, wr->num_sge, NULL);
	if (ret)
		return ret;
	*len16 = DIV_ROUND_UP(sizeof wqe->recv +
			      wr->num_sge * sizeof(struct fw_ri_sge), 16);
	return 0;
}

static int build_tpte_memreg(struct fw_ri_fr_nsmr_tpte_wr *fr,
			     const struct ib_reg_wr *wr, struct chrd_mr *mhp,
			     u8 *len16)
{
	__be64 *p = (__be64 *)fr->pbl;

	if (wr->mr->page_size > T6_MAX_PAGE_SIZE)
		return -EINVAL;
	fr->r2 = cpu_to_be32(0);
	fr->stag = cpu_to_be32(mhp->ibmr.rkey);

	fr->tpte.valid_to_pdid = cpu_to_be32(F_FW_RI_TPTE_VALID |
		V_FW_RI_TPTE_STAGKEY((mhp->ibmr.rkey & M_FW_RI_TPTE_STAGKEY)) |
		V_FW_RI_TPTE_STAGSTATE(1) |
		V_FW_RI_TPTE_STAGTYPE(FW_RI_STAG_NSMR) |
		V_FW_RI_TPTE_PDID(mhp->attr.pdid));
	fr->tpte.locread_to_qpid = cpu_to_be32(
		V_FW_RI_TPTE_PERM(chrd_ib_to_tpt_access(wr->access)) |
		V_FW_RI_TPTE_ADDRTYPE(FW_RI_VA_BASED_TO) |
		V_FW_RI_TPTE_PS(ilog2(wr->mr->page_size) - 12));
	fr->tpte.nosnoop_pbladdr = cpu_to_be32(V_FW_RI_TPTE_PBLADDR(
		PBL_OFF(&mhp->rhp->rdev, mhp->attr.pbl_addr)>>3));
	fr->tpte.dca_mwbcnt_pstag = cpu_to_be32(0);
	fr->tpte.len_hi = cpu_to_be32(mhp->ibmr.length >> 32);
	fr->tpte.len_lo = cpu_to_be32(mhp->ibmr.length & 0xffffffff);
	fr->tpte.va_hi = cpu_to_be32(mhp->ibmr.iova >> 32);
	fr->tpte.va_lo_fbo = cpu_to_be32(mhp->ibmr.iova & 0xffffffff);

	p[0] = cpu_to_be64((u64)mhp->mpl[0]);
	p[1] = cpu_to_be64((u64)mhp->mpl[1]);

	*len16 = DIV_ROUND_UP(sizeof(*fr), 16);
	return 0;
}

static int build_memreg(struct t4_sq *sq, union t4_wr *wqe,
			const struct ib_reg_wr *wr, struct chrd_mr *mhp,
			u8 *len16, bool dsgl_supported)
{
	struct fw_ri_immd *imdp;
	__be64 *p;
	int i;
	int pbllen = roundup(mhp->mpl_len * sizeof(u64), 32);
	int rem;

	if (mhp->mpl_len > t4_max_fr_depth(&mhp->rhp->rdev, use_dsgl))
		return -EINVAL;
	if (wr->mr->page_size > T6_MAX_PAGE_SIZE)
		return -EINVAL;

	wqe->fr.qpbinde_to_dcacpu = 0;
	wqe->fr.pgsz_shift = ilog2(wr->mr->page_size) - 12;
	wqe->fr.addr_type = FW_RI_VA_BASED_TO;
	wqe->fr.mem_perms = chrd_ib_to_tpt_access(wr->access);
	wqe->fr.len_hi = cpu_to_be32(mhp->ibmr.length >> 32);
	wqe->fr.len_lo = cpu_to_be32(mhp->ibmr.length & 0xffffffff);
	wqe->fr.stag = cpu_to_be32(wr->key);
	wqe->fr.va_hi = cpu_to_be32(mhp->ibmr.iova >> 32);
	wqe->fr.va_lo_fbo = cpu_to_be32(mhp->ibmr.iova &
					0xffffffff);

	if (dsgl_supported && use_dsgl && (pbllen > max_fr_immd)) {
		struct fw_ri_dsgl *sglp;

		for (i = 0; i < mhp->mpl_len; i++)
			mhp->mpl[i] = (__force u64)cpu_to_be64((u64)mhp->mpl[i]);

		sglp = (struct fw_ri_dsgl *)(&wqe->fr + 1);
		sglp->op = FW_RI_DATA_DSGL;
		sglp->r1 = 0;
		sglp->nsge = cpu_to_be16(1);
		sglp->addr0 = cpu_to_be64(mhp->mpl_addr);
		sglp->len0 = cpu_to_be32(pbllen);

		*len16 = DIV_ROUND_UP(sizeof(wqe->fr) + sizeof(*sglp), 16);
	} else {
		imdp = (struct fw_ri_immd *)(&wqe->fr + 1);
		imdp->op = FW_RI_DATA_IMMD;
		imdp->r1 = 0;
		imdp->r2 = 0;
		imdp->immdlen = cpu_to_be32(pbllen);
		p = (__be64 *)(imdp + 1);
		rem = pbllen;
		for (i = 0; i < mhp->mpl_len; i++) {
			*p = cpu_to_be64((u64)mhp->mpl[i]);
			rem -= sizeof(*p);
			if (++p == (__be64 *)&sq->queue[sq->size])
				p = (__be64 *)sq->queue;
		}
		while (rem) {
			*p = 0;
			rem -= sizeof(*p);
			if (++p == (__be64 *)&sq->queue[sq->size])
				p = (__be64 *)sq->queue;
		}
		*len16 = DIV_ROUND_UP(sizeof(wqe->fr) + sizeof(*imdp)
				      + pbllen, 16);
	}
	return 0;
}

static int build_inv_stag(union t4_wr *wqe, const struct ib_send_wr *wr,
			  u8 *len16)
{
	wqe->inv.stag_inv = cpu_to_be32(wr->ex.invalidate_rkey);
	wqe->inv.r2 = 0;
	*len16 = DIV_ROUND_UP(sizeof wqe->inv, 16);
	return 0;
}

/* returns mss associated with roce_mtu */
static int roce_pmtu_to_mss(enum ib_mtu mtu)
{
	switch (mtu) {
	case IB_MTU_256:
		return 0;
	case IB_MTU_512:
		return 1;
	case IB_MTU_1024:
		return 2;
	case IB_MTU_2048:
		return 3;
	case IB_MTU_4096:
		return 4;
	default:
		pr_err("unsupported MTU %d\n", ib_mtu_enum_to_int(mtu));
	       	return -EINVAL;
	}
}

/*
	RoCE Build WRs Start
*/

static inline void roce_fill_tnl_lso(struct chrd_qp *qhp,
				     struct cpl_tx_tnl_lso *tnl_lso,
				     u32 isgl_plen, u32 plen,
				     bool vlan_present, bool ipv6,
				     struct chrd_xfrm_info *x)
{
	struct cpl_tx_pkt_core *tx_pkt_xt;
	struct port_info *pi;
	int eth_xtra_len = vlan_present ? 4 : 0;
	int eth_hdr_len = vlan_present ? 18 : 14;
	u32 l3hdr_len = ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
	u32 outer_l3hdr_len = 0;
	u32 tp_esphdr_len = 0;
	u32 val, ctrl0;
	u64 cntrl;

	if (x->ipsec_en) {
		if (x->ipsec_mode == XFRM_MODE_TUNNEL)
			outer_l3hdr_len = ESP_HDR_LEN + ((x->ipv6) ? sizeof(struct ipv6hdr) :
				sizeof(struct iphdr));
		else
			tp_esphdr_len = ESP_HDR_LEN;
	}

	val = V_CPL_TX_TNL_LSO_OPCODE(CPL_TX_TNL_LSO) |
		F_CPL_TX_TNL_LSO_FIRST |
		F_CPL_TX_TNL_LSO_LAST |
		(ipv6 ? F_CPL_TX_TNL_LSO_IPV6OUT : 0) |
		V_CPL_TX_TNL_LSO_ETHHDRLENOUT(eth_xtra_len / 4) |
		V_CPL_TX_TNL_LSO_IPHDRLENOUT(l3hdr_len / 4) |
		(ipv6 ? 0 : F_CPL_TX_TNL_LSO_IPHDRCHKOUT) | 
		F_CPL_TX_TNL_LSO_IPLENSETOUT |
		(ipv6 ? 0 : F_CPL_TX_TNL_LSO_IPIDINCOUT);
	tnl_lso->op_to_IpIdSplitOut = htonl(val);
	tnl_lso->IpIdOffsetOut = 0;
	if (!x->ipsec_en)
		tnl_lso->ipsecen_to_rocev2 = htonl(F_CPL_TX_TNL_LSO_ROCEV2);
	else
		tnl_lso->ipsecen_to_rocev2 = htonl(V_CPL_TX_TNL_LSO_IPSECEN(1) |
				V_CPL_TX_TNL_LSO_ENCAPDIS(1) |
				V_CPL_TX_TNL_LSO_IPSECMODE(x->ipsec_mode == XFRM_MODE_TRANSPORT) |
				F_CPL_TX_TNL_LSO_ROCEV2 |
				V_CPL_TX_TNL_LSO_IPSECTNLIPV6(x->ipv6) |
				V_CPL_TX_TNL_LSO_IPSECTNLIPHDRLEN(outer_l3hdr_len / 4));

	/* Tells the HW if there is additional, 32bit AETH/IETH, for now not needed in SW */
	tnl_lso->roce_eth = htonl(0);
	val = 0;
	val = V_CPL_TX_TNL_LSO_ETHHDRLEN(eth_xtra_len / 4) |
	      V_CPL_TX_TNL_LSO_IPV6(ipv6 ? 1 : 0) |
	      V_CPL_TX_TNL_LSO_IPHDRLEN((l3hdr_len + tp_esphdr_len) / 4) |
	      V_CPL_TX_TNL_LSO_TCPHDRLEN(20 / 4);
	tnl_lso->Flow_to_TcpHdrLen = htonl(val);
	tnl_lso->IpIdOffset = htons(0);
	tnl_lso->IpIdSplit_to_Mss = htons(V_CPL_TX_TNL_LSO_MSS_PMTU(roce_pmtu_to_mss(ib_mtu_int_to_enum(qhp->mtu))) |
					  V_CPL_TX_TNL_LSO_MSS_ACKREQ(roce_pmtu_to_mss(ib_mtu_int_to_enum(qhp->mtu))));
	/* Size of Eth/ipv4/udp/bth */
	tnl_lso->EthLenOffset_Size = htonl(V_CPL_TX_TNL_LSO_SIZE(plen + isgl_plen));

	pi = (struct port_info *)netdev_priv(qhp->netdev);
	ctrl0 = V_TXPKT_OPCODE(CPL_TX_PKT_XT) | V_TXPKT_INTF(pi->port_id) |
		V_TXPKT_PF(qhp->rhp->rdev.lldi.pf);
	tx_pkt_xt = (void *)(tnl_lso + 1);
	tx_pkt_xt->ctrl0 = htonl(ctrl0);
	tx_pkt_xt->pack = htons(0);
	tx_pkt_xt->len = htons(plen + isgl_plen);

	cntrl = F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS | V_TXPKT_CSUM_TYPE(13);
	if (x->ipsec_en)
		cntrl |= V_TXPKT_SA_IDX(x->ipsecidx);

	/* The RoCE IP header length will be stored in two 32-bit registers as shown below:
	 * 			---------------------------------------
	 * for ipv4(20/4)	|24-bits 0000 0001 | 0100 0000 24-bits |lsb
	 *  			---------------------------------------
	 */
	cntrl |= ((u64)V_CPL_TX_PKT_XT_ROCECHKINSMODE(x->ipsec_en) << 32) |
		 V_CPL_TX_PKT_XT_ROCEIPHDRLEN_LO(((l3hdr_len) / 4) & M_CPL_TX_PKT_XT_ROCEIPHDRLEN_LO) |
		 ((u64)V_CPL_TX_PKT_XT_ROCEIPHDRLEN_HI(((l3hdr_len) / 4) >> 2) << 32) |
		 V_CPL_TX_PKT_XT_ROCECHKSTARTOFFSET(eth_hdr_len + outer_l3hdr_len) |
		 V_CPL_TX_PKT_XT_CHKSTOPOFFSET(x->ipsec_en ? 6 : 4); /*Todo: remove Hardcodings*/

	pr_debug("cpl_tx_pkt_core tnl_lso 0x%llx tx_pkt_xt 0x%llx ctrl0 0x%x "
		 "cntrl 0x%llx\n", (unsigned long long)tnl_lso,
		 (unsigned long long)tx_pkt_xt, ctrl0, cntrl);
	tx_pkt_xt->ctrl1 = cpu_to_be64(cntrl);
}

/*
 * Modifies the header frame to insert the ESP header for IPsec.
 * And constructs the outer IP header in IPsec tunnel mode.
 */
static int add_ipsec_header(struct chrd_ah *ahp, u8 *ud_hdrp,
						   int hdr_len, bool has_vlan)
{
	const struct ib_global_route *grh = rdma_ah_read_grh(&ahp->attr);
	const struct chrd_xfrm_info *x = &ahp->xfrm;
	bool tunnel = x->ipsec_mode == XFRM_MODE_TUNNEL;
	unsigned int l2hdr_len = has_vlan ? sizeof(struct vlan_ethhdr) : sizeof(struct ethhdr);
	unsigned int l3hdr_len = x->ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
	unsigned int ipsec_start_offset = l2hdr_len + (tunnel ? 0 : l3hdr_len);
	unsigned int ipsec_end_offset = l2hdr_len + l3hdr_len + ESP_HDR_LEN;
	u8 *ip_hdrp = ud_hdrp + l2hdr_len;

	memmove((char *)ud_hdrp + ipsec_end_offset, ud_hdrp + ipsec_start_offset,
		   hdr_len - ipsec_start_offset);
	memset((char *)ud_hdrp + ipsec_start_offset, 0, ipsec_end_offset - ipsec_start_offset);

	if (x->ipv6) {
		struct ipv6hdr *ip_hdr = (struct ipv6hdr *)ip_hdrp;

		if (tunnel) {
			ip_hdr->version = 6;
			ip_hdr->priority = grh->traffic_class;
			ip_hdr->hop_limit = grh->hop_limit;
			ip_hdr->flow_lbl[0] = (grh->flow_label >> 16) & 0xFF;
			ip_hdr->flow_lbl[1] = (grh->flow_label >> 8) & 0xFF;
			ip_hdr->flow_lbl[2] = grh->flow_label & 0xFF;
			memcpy((u8 *)&ip_hdr->saddr, x->local_ip_addr, sizeof(struct in6_addr));
			memcpy((u8 *)&ip_hdr->daddr, x->dest_ip_addr, sizeof(struct in6_addr));
			hdr_len += sizeof(struct ipv6hdr);
		}
		ip_hdr->nexthdr = IPPROTO_ESP;
	} else {
		struct iphdr *ip_hdr = (struct iphdr *)ip_hdrp;

		if (tunnel) {
			ip_hdr->version = 4;
			ip_hdr->ihl = 5;
			ip_hdr->frag_off = htons(IP_DF);
			ip_hdr->saddr = x->local_ip_addr[3];
			ip_hdr->daddr = x->dest_ip_addr[3];
			ip_hdr->tos = htonl(grh->flow_label);
			ip_hdr->ttl = grh->hop_limit;
			hdr_len += sizeof(struct iphdr);
		}
		ip_hdr->protocol = IPPROTO_ESP;
		ip_hdr->tot_len = 0;
		ip_hdr->check = 0;
		ip_hdr->check = ~ip_fast_csum(ip_hdrp, l3hdr_len / 4);
	}
	hdr_len += ESP_HDR_LEN;

	return hdr_len;
}

static int build_v2_ud_rdma_send(struct chrd_qp *qhp, union t4_wr *wqe,
				 const struct ib_send_wr *wr, u8 *len16)
{
	struct chrd_ah *ahp = to_chrd_ah(ud_wr(wr)->ah);
	const struct ib_gid_attr *sgid_attr;
	const struct ib_global_route *grh;
	struct cpl_tx_tnl_lso *tnl_lso;
	struct t4_sq *sq = &qhp->wq.sq;
	struct fw_ri_immd *immd_src;
	struct fw_ri_isgl *isgl_src;
	struct ib_ud_header ud_hdr = {0};
	u32 dest_qp = ud_wr(wr)->remote_qpn;
	u32 q_key = ud_wr(wr)->remote_qkey;
	u16 p_key = ud_wr(wr)->pkey_index;
	int hlen = ud_wr(wr)->hlen;
	int mss = ud_wr(wr)->mss;
	u32 plen = 0, immdlen = 0;
	bool has_vlan = false;
	u16 vlan_id = 0;
	u32 hdr_len;
	u8 *ud_hdrp;
	int size;
	int ret;

	tnl_lso = (struct cpl_tx_tnl_lso *)wqe->v2_ud_send.tnl_lso;
	grh = rdma_ah_read_grh(&ahp->attr);
	sgid_attr = grh->sgid_attr;

	ret = rdma_read_gid_l2_fields(sgid_attr, &vlan_id, NULL);
	if (ret)
		return ret;

	if (vlan_id < VLAN_CFI_MASK)
		has_vlan = true;

	pr_debug("ahp 0x%llx num_sge %u, dest_qp %u, q_key %x, p_key %x, hlen %d, mss %d,"
		 " PSN %u, inline %s, solicited %s\n", (unsigned long long)ahp,
		 wr->num_sge, dest_qp, q_key, p_key, hlen, mss,
		 qhp->roce_attr.gsi_attr.psn_nxt,
		 wr->send_flags & IB_SEND_INLINE ? "true" : "false",
		 wr->send_flags & IB_SEND_SOLICITED ? "true" : "false");

	if (wr->num_sge > T4_MAX_SEND_SGE)
		return -EINVAL;

	switch (wr->opcode) {
	case IB_WR_SEND:
		if (wr->send_flags & IB_SEND_SOLICITED)
			wqe->v2_ud_send.sendop_psn = cpu_to_be32(
				V_FW_RI_V2_SEND_WR_SENDOP(FW_RI_SEND_WITH_SE) |
				V_FW_RI_V2_SEND_WR_PSN(qhp->roce_attr.gsi_attr.psn_nxt));
		else
			wqe->v2_ud_send.sendop_psn = cpu_to_be32(
				V_FW_RI_V2_SEND_WR_SENDOP(FW_RI_ROCEV2_SEND) |
				V_FW_RI_V2_SEND_WR_PSN(qhp->roce_attr.gsi_attr.psn_nxt));
		wqe->v2_ud_send.stag_inv = 0;
		break;
	default:
		return -EINVAL;
	}
	wqe->v2_ud_send.r2 = 0;
	wqe->v2_ud_send.r4 = 0;

	/* ROCE Headers build*/
	ret = ib_ud_header_init(0, false, true, has_vlan,
				(ahp->net_type == RDMA_NETWORK_IPV4 ? false : true),
				(ahp->net_type == RDMA_NETWORK_IPV4 ? 4 : 6), true, 0, &ud_hdr);
	if (ret)
		return ret;

	/* build headers here  */
	/* ETH + vlan header */
	ether_addr_copy(ud_hdr.eth.dmac_h, ahp->dmac);
	ether_addr_copy(ud_hdr.eth.smac_h, ahp->smac);
	if (has_vlan) {
		ud_hdr.eth.type = htons(ETH_P_8021Q);
		ud_hdr.vlan.tag = htons(vlan_id);
		ud_hdr.vlan.type = (ahp->net_type == RDMA_NETWORK_IPV4 ?
				    htons(ETH_P_IP) : htons(ETH_P_IPV6));
	} else {
		ud_hdr.eth.type = (ahp->net_type == RDMA_NETWORK_IPV4 ?
				   htons(ETH_P_IP) : htons(ETH_P_IPV6));
	}

	if (ahp->net_type == RDMA_NETWORK_IPV4) {
		/* IP header */
		ud_hdr.ip4.frag_off = htons(IP_DF);
		ud_hdr.ip4.protocol = IPPROTO_UDP;
		ud_hdr.ip4.tos = htonl(grh->flow_label);
		ud_hdr.ip4.ttl = grh->hop_limit;
		ud_hdr.ip4.tot_len = 0;
		memcpy(&ud_hdr.ip4.daddr, &ahp->dest_ip_addr[3], sizeof(struct in_addr));
		memcpy(&ud_hdr.ip4.saddr, &ahp->local_ip_addr[3], sizeof(struct in_addr));
		ud_hdr.ip4.check = ~ib_ud_ip4_csum(&ud_hdr);
		ud_hdr.grh_present = 0;
	} else {
		/* IPv6 header*/
		ud_hdr.grh_present = 1;
		ud_hdr.grh.flow_label = htonl(grh->flow_label);
		ud_hdr.grh.payload_length = 0;
		ud_hdr.grh.next_header = IPPROTO_UDP;
		ud_hdr.grh.hop_limit = grh->hop_limit;
		ud_hdr.grh.traffic_class = grh->traffic_class;
		memcpy(&ud_hdr.grh.destination_gid, &ahp->dest_ip_addr[0], sizeof(struct in6_addr));
		memcpy(&ud_hdr.grh.source_gid, &ahp->local_ip_addr[0], sizeof(struct in6_addr));
	}

	/* UDP header */
	ud_hdr.udp.sport = cpu_to_be16(ahp->src_port);
	ud_hdr.udp.dport = cpu_to_be16(ahp->dst_port);

	/* BTH header */
	ud_hdr.bth.pkey = cpu_to_be16(0xFFFF);
	ud_hdr.bth.destination_qpn = cpu_to_be32(ahp->dest_qp);
	ud_hdr.bth.psn = cpu_to_be32(qhp->roce_attr.gsi_attr.psn_nxt);

	/* DETH header */
	ud_hdr.deth.qkey = cpu_to_be32(0x80010000);
	ud_hdr.deth.source_qpn = cpu_to_be32(1);
	/* Init WR has 16B word boundary.may need to initialize last
        10B(64 - 54) with 0 */

	ud_hdrp = (u8 *)(wqe->v2_ud_send.tnl_lso +
				  sizeof(struct cpl_tx_tnl_lso) +
				  sizeof(struct cpl_tx_pkt_core));
	hdr_len = ib_ud_header_pack(&ud_hdr, ud_hdrp);

	if (ahp->xfrm.ipsec_en)
		hdr_len = add_ipsec_header(ahp, ud_hdrp, hdr_len, has_vlan);

	immdlen = sizeof(struct cpl_tx_tnl_lso) +
		  sizeof(struct cpl_tx_pkt_core) + hdr_len;
	wqe->v2_ud_send.immdlen = immdlen;
	immd_src = (struct fw_ri_immd *)(wqe->v2_ud_send.tnl_lso +
					 roundup(wqe->v2_ud_send.immdlen, 16));

	if (wr->num_sge) {
		if (wr->send_flags & IB_SEND_INLINE) {
			ret = build_immd(sq, immd_src, wr,
					 T4_MAX_SEND_INLINE, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->v2_ud_send + roundup(hdr_len, 16) +
				sizeof(struct fw_ri_immd) + plen;
		} else {
			isgl_src = (struct fw_ri_isgl *)(wqe->v2_ud_send.tnl_lso + roundup(wqe->v2_ud_send.immdlen, 16));
			ret = build_isgl((__be64 *)sq->queue,
					 (__be64 *)&sq->queue[sq->size],
					 isgl_src,
					 wr->sg_list, wr->num_sge, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->v2_ud_send + roundup(hdr_len, 16) +
			       sizeof(struct fw_ri_isgl) +
			       wr->num_sge * sizeof(struct fw_ri_sge);
		}
	} else {
		immd_src[0].op = FW_RI_DATA_IMMD;
		immd_src[0].r1 = 0;
		immd_src[0].r2 = 0;
		immd_src[0].immdlen = 0;
		size = sizeof wqe->v2_ud_send + sizeof(struct fw_ri_immd);
		plen = 0;
	}
	roce_fill_tnl_lso(qhp, tnl_lso, plen, hdr_len, has_vlan,
			  ahp->net_type == RDMA_NETWORK_IPV4 ? false : true, &ahp->xfrm);
	tnl_lso->TCPSeqOffset = htonl(V_CPL_TX_TNL_LSO_BTH_OPCODE(0x64) |
				      V_CPL_TX_TNL_LSO_TCPSEQOFFSET_PSN(qhp->roce_attr.gsi_attr.psn_nxt));
	*len16 = DIV_ROUND_UP(size, 16);
	wqe->v2_ud_send.plen = cpu_to_be32(plen);
	qhp->roce_attr.gsi_attr.psn_nxt += 1;
	qhp->roce_attr.gsi_attr.psn_nxt &= 0xFFFFFF;
	return 0;
}

static int build_v2_rdma_send(struct chrd_qp *qhp, union t4_wr *wqe,
			      const struct ib_send_wr *wr, u8 *len16)
{
	struct t4_sq *sq = &qhp->wq.sq;
	u32 plen;
	int size;
	int ret;

	if (wr->num_sge > T4_MAX_SEND_SGE)
		return -EINVAL;
	switch (wr->opcode) {
	case IB_WR_SEND:
		if (wr->send_flags & IB_SEND_SOLICITED)
			wqe->v2_send.sendop_psn = cpu_to_be32(
				V_FW_RI_V2_SEND_WR_SENDOP(FW_RI_SEND_WITH_SE) |
				V_FW_RI_V2_SEND_WR_PSN(qhp->roce_attr.gsi_attr.psn_nxt));
		else
			wqe->v2_send.sendop_psn = cpu_to_be32(
				V_FW_RI_V2_SEND_WR_SENDOP(FW_RI_ROCEV2_SEND) |
				V_FW_RI_V2_SEND_WR_PSN(qhp->roce_attr.gsi_attr.psn_nxt));
		wqe->v2_send.stag_inv = 0;
		break;
	case IB_WR_SEND_WITH_INV:
		if (wr->send_flags & IB_SEND_SOLICITED)
			wqe->v2_send.sendop_psn = cpu_to_be32(
				V_FW_RI_V2_SEND_WR_SENDOP(FW_RI_SEND_WITH_SE_INV) |
				V_FW_RI_V2_SEND_WR_PSN(qhp->roce_attr.gsi_attr.psn_nxt));
		else
			wqe->v2_send.sendop_psn = cpu_to_be32(
				V_FW_RI_V2_SEND_WR_SENDOP(FW_RI_ROCEV2_SEND_WITH_INV) |
				V_FW_RI_V2_SEND_WR_PSN(qhp->roce_attr.gsi_attr.psn_nxt));
		wqe->v2_send.stag_inv = cpu_to_be32(wr->ex.invalidate_rkey);
		break;
	default:
		return -EINVAL;
	}
	wqe->v2_send.r2 = 0;
	wqe->v2_send.r4 = 0;

	plen = 0;
	if (wr->num_sge) {
		if (wr->send_flags & IB_SEND_INLINE) {
			ret = build_immd(sq, wqe->v2_send.u.immd_src, wr,
					 T4_MAX_SEND_INLINE, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->v2_send + sizeof(struct fw_ri_immd) +
			       plen;
		} else {
			ret = build_isgl((__be64 *)sq->queue,
					 (__be64 *)&sq->queue[sq->size],
					 wqe->v2_send.u.isgl_src,
					 wr->sg_list, wr->num_sge, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->v2_send + sizeof(struct fw_ri_isgl) +
			       wr->num_sge * sizeof(struct fw_ri_sge);
		}
	} else {
		wqe->v2_send.u.immd_src[0].op = FW_RI_DATA_IMMD;
		wqe->v2_send.u.immd_src[0].r1 = 0;
		wqe->v2_send.u.immd_src[0].r2 = 0;
		wqe->v2_send.u.immd_src[0].immdlen = 0;
		size = sizeof wqe->v2_send + sizeof(struct fw_ri_immd);
		plen = 0;
	}
	pr_debug("num_sge %u, PSN %u, inline %s, solicited %s, size %u, plen %u\n",
		 wr->num_sge, qhp->roce_attr.gsi_attr.psn_nxt,
		 wr->send_flags & IB_SEND_INLINE ? "true" : "false",
		 wr->send_flags & IB_SEND_SOLICITED ? "true" : "false", size, plen);

	*len16 = DIV_ROUND_UP(size, 16);
	wqe->v2_send.plen = cpu_to_be32(plen);
	qhp->roce_attr.gsi_attr.psn_nxt += DIV_ROUND_UP(plen, qhp->mtu);
	qhp->roce_attr.gsi_attr.psn_nxt &= 0xFFFFFF;		/*Todo: hardcoded value */
	return 0;
}

static int build_v2_rdma_write(struct chrd_qp *qhp, union t4_wr *wqe,
			       const struct ib_send_wr *wr, u8 *len16)
{
	struct t4_sq *sq = &qhp->wq.sq;
	u32 plen;
	int size;
	int ret;

	if (wr->num_sge > T4_MAX_SEND_SGE)
		return -EINVAL;
	if (wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM)
		wqe->v2_write.immd_data = wr->ex.imm_data;
	else
		wqe->v2_write.immd_data = 0;
	wqe->v2_write.stag_sink = cpu_to_be32(rdma_wr(wr)->rkey);
	wqe->v2_write.to_sink = cpu_to_be64(rdma_wr(wr)->remote_addr);
	if (wr->num_sge) {
		if (wr->send_flags & IB_SEND_INLINE) {
			ret = build_immd(sq, wqe->v2_write.u.immd_src, wr,
					 T4_MAX_WRITE_INLINE, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->v2_write + sizeof(struct fw_ri_immd) +
			       plen;
		} else {
			ret = build_isgl((__be64 *)sq->queue,
					 (__be64 *)&sq->queue[sq->size],
					 wqe->v2_write.u.isgl_src,
					 wr->sg_list, wr->num_sge, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->v2_write + sizeof(struct fw_ri_isgl) +
			       wr->num_sge * sizeof(struct fw_ri_sge);
		}
	} else {
		wqe->v2_write.u.immd_src[0].op = FW_RI_DATA_IMMD;
		wqe->v2_write.u.immd_src[0].r1 = 0;
		wqe->v2_write.u.immd_src[0].r2 = 0;
		wqe->v2_write.u.immd_src[0].immdlen = 0;
		size = sizeof wqe->v2_write + sizeof(struct fw_ri_immd);
		plen = 0;
	}
	pr_debug("num_sge %u, PSN %u, size %u plen %u\n",
		 wr->num_sge, qhp->roce_attr.gsi_attr.psn_nxt, size, plen);

	wqe->v2_write.psn_pkd = cpu_to_be32(
			V_FW_RI_V2_RDMA_WRITE_WR_PSN(qhp->roce_attr.gsi_attr.psn_nxt));
	wqe->v2_write.r2 = 0;
	wqe->v2_write.r5 = 0;
	*len16 = DIV_ROUND_UP(size, 16);
	wqe->v2_write.plen = cpu_to_be32(plen);
	qhp->roce_attr.gsi_attr.psn_nxt += DIV_ROUND_UP(plen, qhp->mtu);
	qhp->roce_attr.gsi_attr.psn_nxt &= 0xFFFFFF;
	return 0;
}

/* Bhar: Check this later when FW enables it */
#if 0 
static void build_v2_rdma_write_cmpl(struct t4_sq *sq,
				  struct fw_ri_rdma_write_cmpl_wr *wcwr,
				  const struct ib_send_wr *wr, u8 *len16)
{
	u32 plen;
	int size;

	/*
	 * This code assumes the struct fields preceeding the write isgl
	 * fit in one 64B WR slot.  This is because the WQE is built
	 * directly in the dma queue, and wrapping is only handled
	 * by the code buildling sgls.  IE the "fixed part" of the wr
	 * structs must all fit in 64B.  The WQE build code should probably be
	 * redesigned to avoid this restriction, but for now just add
	 * the BUILD_BUG_ON() to catch if this WQE struct gets too big.
	 */
	BUILD_BUG_ON(offsetof(struct fw_ri_rdma_write_cmpl_wr, u) > 64);

	wcwr->stag_sink = cpu_to_be32(rdma_wr(wr)->rkey);
	wcwr->to_sink = cpu_to_be64(rdma_wr(wr)->remote_addr);
	if (wr->next->opcode == IB_WR_SEND)
		wcwr->stag_inv = 0;
	else
		wcwr->stag_inv = cpu_to_be32(wr->next->ex.invalidate_rkey);
	wcwr->r2 = 0;
	wcwr->r3 = 0;

 	/* SEND_INV SGL */
	if (wr->next->send_flags & IB_SEND_INLINE)
		build_immd_cmpl(sq, &wcwr->u_cmpl.immd_src, wr->next);
	else
		build_isgl((__be64 *)sq->queue, (__be64 *)&sq->queue[sq->size],
			   &wcwr->u_cmpl.isgl_src, wr->next->sg_list, 1, NULL);

	/* WRITE SGL */
	build_isgl((__be64 *)sq->queue, (__be64 *)&sq->queue[sq->size],
		   wcwr->u.isgl_src, wr->sg_list, wr->num_sge, &plen);

	size = sizeof *wcwr + sizeof(struct fw_ri_isgl) +
	       wr->num_sge * sizeof(struct fw_ri_sge);
	wcwr->plen = cpu_to_be32(plen);
	*len16 = DIV_ROUND_UP(size, 16);

	return;
}
#endif

static int build_v2_rdma_read(struct chrd_qp *qhp, union t4_wr *wqe,
			      const struct ib_send_wr *wr, u8 *len16)
{
	struct t4_sq *sq = &qhp->wq.sq;
	u32 plen;
	int size;
	int ret;
/* Bhar:
	- Change the hard coded max_num_sge to max_num_read_sge attr */

	if (wr->num_sge > 4)
		return -EINVAL;

	if (wr->num_sge) {
		wqe->v2_read.stag_src = cpu_to_be32(rdma_wr(wr)->rkey);
		wqe->v2_read.to_src = cpu_to_be64((u64)(rdma_wr(wr)->remote_addr));
		ret = build_isgl((__be64 *)sq->queue,
				 (__be64 *)&sq->queue[sq->size],
				 &wqe->v2_read.isgl_sink,
				 wr->sg_list, wr->num_sge, &plen);
		if (ret)
			return ret;
		size = sizeof wqe->v2_read +
			      wr->num_sge * sizeof(struct fw_ri_sge);
	} else {
		wqe->v2_read.stag_src = cpu_to_be32(2);
		wqe->v2_read.to_src = 0;
		size = sizeof wqe->v2_read;
		plen = 0;
	}
	pr_debug("qhp %p num_sge %u, PSN %u, size %u plen %u\n", qhp,
		 wr->num_sge, qhp->roce_attr.gsi_attr.psn_nxt, size, plen);

	wqe->v2_read.psn_pkd = cpu_to_be32(
			V_FW_RI_V2_RDMA_READ_WR_PSN(qhp->roce_attr.gsi_attr.psn_nxt));
	wqe->v2_read.r2 = 0;
	*len16 = DIV_ROUND_UP(size, 16);
	wqe->v2_read.plen = cpu_to_be32(plen);
	qhp->roce_attr.gsi_attr.psn_nxt += DIV_ROUND_UP(plen, qhp->mtu);
	qhp->roce_attr.gsi_attr.psn_nxt &= 0xFFFFFF;
	return 0;
}

static int build_v2_memreg(struct t4_sq *sq, union t4_wr *wqe,
			const struct ib_reg_wr *wr, struct chrd_mr *mhp,
			u8 *len16, bool dsgl_supported)
{
	struct fw_ri_immd *imdp;
	__be64 *p;
	int i;
	int pbllen = roundup(mhp->mpl_len * sizeof(u64), 32);
	int rem;

	if (mhp->mpl_len > t4_max_fr_depth(&mhp->rhp->rdev, use_dsgl))
		return -EINVAL;
	if (wr->mr->page_size > T6_MAX_PAGE_SIZE)
		return -EINVAL;

	wqe->v2_fr.qpbinde_to_dcacpu = 0;
	wqe->v2_fr.pgsz_shift = ilog2(wr->mr->page_size) - 12;
	wqe->v2_fr.addr_type = FW_RI_VA_BASED_TO;
	wqe->v2_fr.mem_perms = chrd_ib_to_tpt_access(wr->access);
	wqe->v2_fr.len_hi = cpu_to_be32(mhp->ibmr.length >> 32);
	wqe->v2_fr.len_lo = cpu_to_be32(mhp->ibmr.length & 0xffffffff);
	wqe->v2_fr.stag = cpu_to_be32(wr->key);
	wqe->v2_fr.va_hi = cpu_to_be32(mhp->ibmr.iova >> 32);
	wqe->v2_fr.va_lo_fbo = cpu_to_be32(mhp->ibmr.iova &
					0xffffffff);

	if (dsgl_supported && use_dsgl && (pbllen > max_fr_immd)) {
		struct fw_ri_dsgl *sglp;

		for (i = 0; i < mhp->mpl_len; i++)
			mhp->mpl[i] = (__force u64)cpu_to_be64((u64)mhp->mpl[i]);

		sglp = (struct fw_ri_dsgl *)(&wqe->v2_fr + 1);
		sglp->op = FW_RI_DATA_DSGL;
		sglp->r1 = 0;
		sglp->nsge = cpu_to_be16(1);
		sglp->addr0 = cpu_to_be64(mhp->mpl_addr);
		sglp->len0 = cpu_to_be32(pbllen);

		*len16 = DIV_ROUND_UP(sizeof(wqe->v2_fr) + sizeof(*sglp), 16);
	} else {
		imdp = (struct fw_ri_immd *)(&wqe->v2_fr + 1);
		imdp->op = FW_RI_DATA_IMMD;
		imdp->r1 = 0;
		imdp->r2 = 0;
		imdp->immdlen = cpu_to_be32(pbllen);
		p = (__be64 *)(imdp + 1);
		rem = pbllen;
		for (i = 0; i < mhp->mpl_len; i++) {
			*p = cpu_to_be64((u64)mhp->mpl[i]);
			rem -= sizeof(*p);
			if (++p == (__be64 *)&sq->queue[sq->size])
				p = (__be64 *)sq->queue;
		}
		while (rem) {
			*p = 0;
			rem -= sizeof(*p);
			if (++p == (__be64 *)&sq->queue[sq->size])
				p = (__be64 *)sq->queue;
		}
		*len16 = DIV_ROUND_UP(sizeof(wqe->v2_fr) + sizeof(*imdp)
				      + pbllen, 16);
	}
	wqe->v2_fr.r2 = 0;
	wqe->v2_fr.r3 = 0;
	return 0;
}
/*
	RoCE Build WRs End
*/

void chrd_iw_qp_add_ref(struct ib_qp *qp)
{
	pr_debug("ib_qp 0x%llx\n", (unsigned long long)qp);
	switch (qp->qp_type) {
	case IB_QPT_RC:
		set_bit(ROCE_QP_REFED, (&to_chrd_qp(qp)->history));
		refcount_inc(&to_chrd_qp(qp)->qp_refcnt);
		break;
	case IB_QPT_RAW_ETH:
		atomic_inc(&(to_chrd_raw_qp(qp)->refcnt));
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", qp->qp_type);
	}
}

void chrd_iw_qp_rem_ref(struct ib_qp *qp)
{
	pr_debug("ib_qp 0x%llx\n", (unsigned long long)qp);
	switch (qp->qp_type) {
	case IB_QPT_GSI:
	case IB_QPT_UD:
	case IB_QPT_RC:
		set_bit(ROCE_QP_DEREFED, (&to_chrd_qp(qp)->history));
		if (refcount_dec_and_test(&to_chrd_qp(qp)->qp_refcnt))
			complete(&to_chrd_qp(qp)->qp_rel_comp);
		break;
	case IB_QPT_RAW_ETH:
		if (atomic_dec_and_test(&(to_chrd_raw_qp(qp)->refcnt)))
			wake_up(&(to_chrd_raw_qp(qp)->wait));
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", qp->qp_type);
	}
}

static void add_to_fc_list(struct list_head *head, struct list_head *entry)
{
	if (list_empty(entry))
		list_add_tail(entry, head);
}

static int ring_kernel_txq_db(struct chrd_raw_qp *rqp, u16 inc)
{
	unsigned long flags;

	spin_lock_irqsave(&rqp->rhp->lock, flags);
	if (rqp->rhp->db_state == NORMAL)
		writel(V_QID(rqp->txq.cntxt_id) | V_PIDX(inc),
		       rqp->rhp->rdev.lldi.db_reg);
	else {
		add_to_fc_list(&rqp->rhp->db_fc_list, &rqp->fcl.db_fc_entry);
		rqp->txq.pidx_inc += inc;
	}
	spin_unlock_irqrestore(&rqp->rhp->lock, flags);
	return 0;
}

static int ring_kernel_sq_db(struct chrd_qp *qhp, u16 inc)
{
	unsigned long flags;

	xa_lock_irqsave(&qhp->rhp->qps, flags);
	spin_lock(&qhp->lock);
	if (qhp->rhp->db_state == NORMAL)
		t4_ring_sq_db(&qhp->wq, inc, NULL);
	else {
		add_to_fc_list(&qhp->rhp->db_fc_list, &qhp->fcl.db_fc_entry);
		qhp->wq.sq.wq_pidx_inc += inc;
	}
	spin_unlock(&qhp->lock);
	xa_unlock_irqrestore(&qhp->rhp->qps, flags);
	return 0;
}

static int ring_kernel_fl_db(struct chrd_raw_qp *rqp, u16 inc)
{
	unsigned long flags;
	u32 val = 0;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(rqp->rhp->rdev.lldi.adapter_type);

	switch (chip_ver) {
	case CHELSIO_T4:
		val = V_PIDX(inc) | F_DBPRIO;
		break;
	case CHELSIO_T5:
		val = F_DBPRIO;
		fallthrough; /* fallthrough */
	case CHELSIO_T6:
	case CHELSIO_T7:
	default:
		val |= V_PIDX_T5(inc);
		break;
	}

	spin_lock_irqsave(&rqp->rhp->lock, flags);
	if (rqp->rhp->db_state == NORMAL)
		writel(V_QID(rqp->fl.cntxt_id) | val,
		       rqp->rhp->rdev.lldi.db_reg);
	else {
		add_to_fc_list(&rqp->rhp->db_fc_list, &rqp->fcl.db_fc_entry);
		rqp->fl.pidx_inc += inc;
	}
	spin_unlock_irqrestore(&rqp->rhp->lock, flags);
	return 0;
}

static int ring_kernel_srq_db(struct chrd_raw_srq *srq, u16 inc)
{
	unsigned long flags;
	u32 val = 0;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(srq->dev->rdev.lldi.adapter_type);

	switch (chip_ver) {
	case CHELSIO_T4:
		val = V_PIDX(inc) | F_DBPRIO;
		break;
	case CHELSIO_T5:
		val = F_DBPRIO;
		fallthrough; /* fallthrough */
	case CHELSIO_T6:
	case CHELSIO_T7:
	default:
		val |= V_PIDX_T5(inc);
		break;
	}

	spin_lock_irqsave(&srq->dev->lock, flags);
	if (srq->dev->db_state == NORMAL)
		writel(V_QID(srq->fl.cntxt_id) | val,
		       srq->dev->rdev.lldi.db_reg);
	else {
		add_to_fc_list(&srq->dev->db_fc_list, &srq->fcl.db_fc_entry);
		srq->fl.pidx_inc += inc;
	}
	spin_unlock_irqrestore(&srq->dev->lock, flags);
	return 0;
}

static int ring_kernel_rq_db(struct chrd_qp *qhp, u16 inc)
{
	unsigned long flags;

	xa_lock_irqsave(&qhp->rhp->qps, flags);
	spin_lock(&qhp->lock);
	if (qhp->rhp->db_state == NORMAL)
		t4_ring_rq_db(&qhp->wq, inc, NULL);
	else {
		add_to_fc_list(&qhp->rhp->db_fc_list, &qhp->fcl.db_fc_entry);
		qhp->wq.rq.wq_pidx_inc += inc;
	}
	spin_unlock(&qhp->lock);
	xa_unlock_irqrestore(&qhp->rhp->qps, flags);
	return 0;
}

static int ib_to_fw_opcode(int ib_opcode)
{
	int opcode;

	switch (ib_opcode) {
	case IB_WR_SEND_WITH_INV:
		opcode = FW_RI_SEND_WITH_INV;
		break;
	case IB_WR_SEND:
		opcode = FW_RI_SEND;
		break;
	case IB_WR_RDMA_WRITE:
		opcode = FW_RI_RDMA_WRITE;
		break;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		opcode = FW_RI_WRITE_IMMEDIATE;
		break;
	case IB_WR_RDMA_READ:
	case IB_WR_RDMA_READ_WITH_INV:
		opcode = FW_RI_READ_REQ;
		break;
	case IB_WR_REG_MR:
		opcode = FW_RI_FAST_REGISTER;
		break;
	case IB_WR_LOCAL_INV:
		opcode = FW_RI_LOCAL_INV;
		break;
	default:
		opcode = -EINVAL;
	}
	return opcode;
}

static int complete_sq_drain_wr(struct chrd_qp *qhp,
				const struct ib_send_wr *wr)
{
	struct t4_cqe cqe = {};
	struct chrd_cq *schp;
	unsigned long flag;
	struct t4_cq *cq;
	int opcode;

	schp = to_chrd_cq(qhp->ibqp.send_cq);
	cq = &schp->cq;

	opcode = ib_to_fw_opcode(wr->opcode);
	if (opcode < 0)
		return opcode;

	pr_debug("drain sq id %u, opcode %d\n", qhp->wq.sq.qid, opcode);
	cqe.u.drain_cookie = wr->wr_id;
	if (rdma_protocol_roce(qhp->ibqp.device, 1)) {
		cqe.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
					 V_CQE_TYPE(1) |
					 V_CQE_SWCQE(1) |
					 V_CQE_DRAIN(1) |
					 V_CQE_QPID(qhp->wq.sq.qid));
		cqe.u.v2_com.v2_header |= cpu_to_be32(V_CQE_V2_OPCODE(opcode));
	} else {
		cqe.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
					 V_CQE_OPCODE(opcode) |
					 V_CQE_TYPE(1) |
					 V_CQE_SWCQE(1) |
					 V_CQE_DRAIN(1) |
					 V_CQE_QPID(qhp->wq.sq.qid));
	}
	spin_lock_irqsave(&schp->lock, flag);
	cqe.bits_type_ts = cpu_to_be64(V_CQE_GENBIT((u64)cq->gen));
	cq->sw_queue[cq->sw_pidx] = cqe;
	t4_swcq_produce(cq);
	spin_unlock_irqrestore(&schp->lock, flag);

	if (t4_clear_cq_armed(&schp->cq, qhp->ibqp.uobject)) {
		spin_lock_irqsave(&schp->comp_handler_lock, flag);
		(*schp->ibcq.comp_handler)(&schp->ibcq,
					   schp->ibcq.cq_context);
		spin_unlock_irqrestore(&schp->comp_handler_lock, flag);
	}
	return 0;
}

static int complete_sq_drain_wrs(struct chrd_qp *qhp, const struct ib_send_wr *wr,
				 const struct ib_send_wr **bad_wr)
{
	int ret = 0;

	while (wr) {
		ret = complete_sq_drain_wr(qhp, wr);
		if (ret) {
			*bad_wr = wr;
			break;
		}
		wr = wr->next;
	}
	return ret;
}

static void complete_rq_drain_wr(struct chrd_qp *qhp,
				 const struct ib_recv_wr *wr)
{
	struct t4_cqe cqe = {};
	struct chrd_cq *rchp;
	unsigned long flag;
	struct t4_cq *cq;

	rchp = to_chrd_cq(qhp->ibqp.recv_cq);
	cq = &rchp->cq;

	pr_debug("drain rq id %u\n", qhp->wq.sq.qid);
	cqe.u.drain_cookie = wr->wr_id;
	if (rdma_protocol_roce(qhp->ibqp.device, 1)) {
		cqe.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
					 V_CQE_TYPE(0) |
					 V_CQE_SWCQE(1) |
					 V_CQE_DRAIN(1) |
					 V_CQE_QPID(qhp->wq.sq.qid));
		cqe.u.v2_com.v2_header |= cpu_to_be32(V_CQE_V2_OPCODE(FW_RI_SEND));
	} else {
		cqe.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
					 V_CQE_OPCODE(FW_RI_SEND) |
					 V_CQE_TYPE(0) |
					 V_CQE_SWCQE(1) |
					 V_CQE_DRAIN(1) |
					 V_CQE_QPID(qhp->wq.sq.qid));
	}

	spin_lock_irqsave(&rchp->lock, flag);
	cqe.bits_type_ts = cpu_to_be64(V_CQE_GENBIT((u64)cq->gen));
	cq->sw_queue[cq->sw_pidx] = cqe;
	t4_swcq_produce(cq);
	spin_unlock_irqrestore(&rchp->lock, flag);

	if (t4_clear_cq_armed(&rchp->cq, qhp->ibqp.uobject)) {
		spin_lock_irqsave(&rchp->comp_handler_lock, flag);
		(*rchp->ibcq.comp_handler)(&rchp->ibcq,
					   rchp->ibcq.cq_context);
		spin_unlock_irqrestore(&rchp->comp_handler_lock, flag);
	}
}

static void complete_rq_drain_wrs(struct chrd_qp *qhp,
				  const struct ib_recv_wr *wr)
{
	while (wr) {
		complete_rq_drain_wr(qhp, wr);
		wr = wr->next;
	}
}

static void post_write_cmpl(struct chrd_qp *qhp, const struct ib_send_wr *wr)
{
	bool send_signaled = (wr->next->send_flags & IB_SEND_SIGNALED) ||
			     qhp->sq_sig_all;
	bool write_signaled = (wr->send_flags & IB_SEND_SIGNALED) ||
			      qhp->sq_sig_all;
	struct t4_swsqe *swsqe;
	union t4_wr *wqe;
	u16 write_wrid;
	u8 len16;
	u16 idx;

	/*
	 * The sw_sq entries still look like a WRITE and a SEND and consume
	 * 2 slots. The FW WR, however, will be a single uber-WR.
	 */
	wqe = (union t4_wr *)((u8 *)qhp->wq.sq.queue +
	      qhp->wq.sq.wq_pidx * T4_EQ_ENTRY_SIZE);
	build_rdma_write_cmpl(&qhp->wq.sq, &wqe->write_cmpl, wr, &len16);

	/* WRITE swsqe */
	swsqe = &qhp->wq.sq.sw_sq[qhp->wq.sq.pidx];
	swsqe->opcode = FW_RI_RDMA_WRITE;
	swsqe->idx = qhp->wq.sq.pidx;
	swsqe->complete = 0;
	swsqe->signaled = write_signaled;
	swsqe->flushed = 0;
	swsqe->wr_id = wr->wr_id;
	if (chrd_wr_log) {
		swsqe->sge_ts =
			cxgb4_read_sge_timestamp(qhp->rhp->rdev.lldi.ports[0]);
		swsqe->host_time = ktime_get();
	}

	write_wrid = qhp->wq.sq.pidx;

	/* just bump the sw_sq */
	qhp->wq.sq.in_use++;
	if (++qhp->wq.sq.pidx == qhp->wq.sq.size)
		qhp->wq.sq.pidx = 0;

	/* SEND_WITH_INV swsqe */
	swsqe = &qhp->wq.sq.sw_sq[qhp->wq.sq.pidx];
	if (wr->next->opcode == IB_WR_SEND)
		swsqe->opcode = FW_RI_SEND;
	else
		swsqe->opcode = FW_RI_SEND_WITH_INV;
	swsqe->idx = qhp->wq.sq.pidx;
	swsqe->complete = 0;
	swsqe->signaled = send_signaled;
	swsqe->flushed = 0;
	swsqe->wr_id = wr->next->wr_id;
	if (chrd_wr_log) {
		swsqe->sge_ts =
			cxgb4_read_sge_timestamp(qhp->rhp->rdev.lldi.ports[0]);
		swsqe->host_time = ktime_get();
	}

	wqe->write_cmpl.flags_send = send_signaled ? FW_RI_COMPLETION_FLAG : 0;
	wqe->write_cmpl.wrid_send = qhp->wq.sq.pidx;

	init_wr_hdr(wqe, write_wrid, FW_RI_RDMA_WRITE_CMPL_WR,
		    write_signaled ? FW_RI_COMPLETION_FLAG : 0, len16);
	t4_sq_produce(&qhp->wq, len16);
	idx = DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);

	t4_ring_sq_db(&qhp->wq, idx, wqe);
	return;
}

static int iw_post_rc_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			const struct ib_send_wr **bad_wr)
{
	int err = 0;
	u8 len16 = 0;
	enum fw_wr_opcodes fw_opcode = 0;
	enum fw_ri_wr_flags fw_flags;
	struct chrd_qp *qhp;
	union t4_wr *wqe = NULL;
	u32 num_wrs;
	struct t4_swsqe *swsqe;
	unsigned long flag;
	u16 idx = 0;
	unsigned int chip_ver;

	qhp = to_chrd_qp(ibqp);
	spin_lock_irqsave(&qhp->lock, flag);

	/*
	 * If the qp has been flushed, then just insert a special
	 * drain cqe.
	 */
	if (qhp->wq.flushed) {
		spin_unlock_irqrestore(&qhp->lock, flag);
		err = complete_sq_drain_wrs(qhp, wr, bad_wr);
		return err;
	}
	num_wrs = t4_sq_avail(&qhp->wq);
	if (num_wrs == 0) {
		spin_unlock_irqrestore(&qhp->lock, flag);
		*bad_wr = wr;
		return -ENOMEM;
	}

	chip_ver = CHELSIO_CHIP_VERSION(qhp->rhp->rdev.lldi.adapter_type);

	/*
	 * Fastpath for NVMe-oF target WRITE + SEND_WITH_INV wr chain which is
	 * the response for small NVMEe-oF READ requests.  If the chain is
	 * exactly a WRITE->SEND_WITH_INV or a WRITE->SEND and the sgl depths 
	 * and lengths meet the requirements of the fw_ri_write_cmpl_wr work 
	 * request, then build and post the write_cmpl WR. If any of the tests 
	 * below are not true, then we continue on with the tradtional WRITE
	 * and SEND WRs.
	 */
	if (qhp->rhp->rdev.lldi.write_cmpl_support &&
	    chip_ver >= CHELSIO_T5 && wr && wr->next &&
	    !wr->next->next &&
	    wr->opcode == IB_WR_RDMA_WRITE &&
	    wr->sg_list[0].length && wr->num_sge <= T4_WRITE_CMPL_MAX_SGL &&
	    (wr->next->opcode == IB_WR_SEND ||
	    wr->next->opcode == IB_WR_SEND_WITH_INV) &&
	    wr->next->num_sge == 1 && num_wrs >= 2) {
		post_write_cmpl(qhp, wr);
		spin_unlock_irqrestore(&qhp->lock, flag);
		return 0;
	}

	while (wr) {
		if (num_wrs == 0) {
			err = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		wqe = (union t4_wr *)((u8 *)qhp->wq.sq.queue +
		      qhp->wq.sq.wq_pidx * T4_EQ_ENTRY_SIZE);

		fw_flags = 0;
		if (wr->send_flags & IB_SEND_SOLICITED)
			fw_flags |= FW_RI_SOLICITED_EVENT_FLAG;
		if (wr->send_flags & IB_SEND_SIGNALED || qhp->sq_sig_all)
			fw_flags |= FW_RI_COMPLETION_FLAG;
		swsqe = &qhp->wq.sq.sw_sq[qhp->wq.sq.pidx];
		switch (wr->opcode) {
		case IB_WR_SEND_WITH_INV:
		case IB_WR_SEND:
			if (wr->send_flags & IB_SEND_FENCE)
				fw_flags |= FW_RI_READ_FENCE_FLAG;
			fw_opcode = FW_RI_SEND_WR;
			if (wr->opcode == IB_WR_SEND)
				swsqe->opcode = FW_RI_SEND;
			else
				swsqe->opcode = FW_RI_SEND_WITH_INV;
			err = build_rdma_send(&qhp->wq.sq, wqe, wr, &len16);
			break;
		case IB_WR_RDMA_WRITE_WITH_IMM:
			if (unlikely(!qhp->rhp->rdev.lldi.write_w_imm_support)) {
				err = -ENOSYS;
				break;
			}
			fw_flags |= FW_RI_RDMA_WRITE_WITH_IMMEDIATE;
			fallthrough; /* fallthrough */
		case IB_WR_RDMA_WRITE:
			fw_opcode = FW_RI_RDMA_WRITE_WR;
			swsqe->opcode = FW_RI_RDMA_WRITE;
			err = build_rdma_write(&qhp->wq.sq, wqe, wr, &len16);
			break;
		case IB_WR_RDMA_READ:
		case IB_WR_RDMA_READ_WITH_INV:
			fw_opcode = FW_RI_RDMA_READ_WR;
			swsqe->opcode = FW_RI_READ_REQ;
			if (wr->opcode == IB_WR_RDMA_READ_WITH_INV) {
				chrd_invalidate_mr(qhp->rhp,
						   wr->sg_list[0].lkey);
				fw_flags = FW_RI_RDMA_READ_INVALIDATE;
			} else {
				fw_flags = 0;
			}
			err = build_rdma_read(wqe, wr, &len16);
			if (err)
				break;
			swsqe->read_len = wr->sg_list[0].length;
			if (!qhp->wq.sq.oldest_read)
				qhp->wq.sq.oldest_read = swsqe;
			break;
		case IB_WR_REG_MR: {
			struct chrd_mr *mhp = to_chrd_mr(reg_wr(wr)->mr);

			swsqe->opcode = FW_RI_FAST_REGISTER;
			if (qhp->rhp->rdev.lldi.fr_nsmr_tpte_wr_support &&
			    !mhp->attr.state && mhp->mpl_len <= 2) {
				fw_opcode = FW_RI_FR_NSMR_TPTE_WR;
				err = build_tpte_memreg(&wqe->fr_tpte, reg_wr(wr),
							mhp, &len16);
			} else {
				fw_opcode = FW_RI_FR_NSMR_WR;
				err = build_memreg(&qhp->wq.sq, wqe, reg_wr(wr),
				       mhp, &len16,
				       qhp->rhp->rdev.lldi.ulptx_memwrite_dsgl);
			}
			if (err)
				break;
			mhp->attr.state = 1;
			break;
		}
		case IB_WR_LOCAL_INV:
			if (wr->send_flags & IB_SEND_FENCE)
				fw_flags |= FW_RI_LOCAL_FENCE_FLAG;
			fw_opcode = FW_RI_INV_LSTAG_WR;
			swsqe->opcode = FW_RI_LOCAL_INV;
			err = build_inv_stag(wqe, wr, &len16);
			chrd_invalidate_mr(qhp->rhp, wr->ex.invalidate_rkey);
			break;
		default:
			pr_debug("post of type=%d TBD!\n", wr->opcode);
			err = -EINVAL;
		}
		if (err) {
			*bad_wr = wr;
			break;
		}
		swsqe->idx = qhp->wq.sq.pidx;
		swsqe->complete = 0;
		swsqe->signaled = (wr->send_flags & IB_SEND_SIGNALED) ||
				  qhp->sq_sig_all;
		swsqe->flushed = 0;
		swsqe->wr_id = wr->wr_id;
		if (chrd_wr_log) {
			swsqe->sge_ts =
				cxgb4_read_sge_timestamp(qhp->rhp->rdev.lldi.ports[0]);
			swsqe->host_time = ktime_get();
		}

		init_wr_hdr(wqe, qhp->wq.sq.pidx, fw_opcode, fw_flags, len16);

		pr_debug("cookie 0x%llx pidx 0x%x opcode 0x%x read_len %u qid %u sig %u flag 0x%x\n",
			 (unsigned long long)wr->wr_id, qhp->wq.sq.pidx, swsqe->opcode,
			 swsqe->read_len, qhp->wq.sq.qid, swsqe->signaled, fw_flags);
		wr = wr->next;
		num_wrs--;
		t4_sq_produce(&qhp->wq, len16);
		idx += DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);
	}
	if (!qhp->rhp->rdev.status_page->db_off) {
		t4_ring_sq_db(&qhp->wq, idx, wqe);
		spin_unlock_irqrestore(&qhp->lock, flag);
	} else {
		spin_unlock_irqrestore(&qhp->lock, flag);
		ring_kernel_sq_db(qhp, idx);
	}
	return err;
}

int chrd_iw_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
		   const struct ib_send_wr **bad_wr)
{
	int ret = 0;

	switch (ibqp->qp_type) {
	case IB_QPT_RC:
		ret = iw_post_rc_send(ibqp, wr, bad_wr);
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", ibqp->qp_type);
	}
	return ret;
}

static int post_rc_receive(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		      const struct ib_recv_wr **bad_wr)
{
	int err = 0;
	struct chrd_qp *qhp;
	union t4_recv_wr *wqe = NULL;
	u32 num_wrs;
	u8 len16 = 0;
	unsigned long flag;
	u16 idx = 0;

	qhp = to_chrd_qp(ibqp);
	spin_lock_irqsave(&qhp->lock, flag);

	/*
	 * If the qp has been flushed, then just insert a special
	 * drain cqe.
	 */
	if (qhp->wq.flushed) {
		spin_unlock_irqrestore(&qhp->lock, flag);
		complete_rq_drain_wrs(qhp, wr);
		return err;
	}
	num_wrs = t4_rq_avail(&qhp->wq);
	if (num_wrs == 0) {
		spin_unlock_irqrestore(&qhp->lock, flag);
		*bad_wr = wr;
		return -ENOMEM;
	}
	while (wr) {
		if (wr->num_sge > T4_MAX_RECV_SGE) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}
		wqe = (union t4_recv_wr *)((u8 *)qhp->wq.rq.queue +
					   qhp->wq.rq.wq_pidx *
					   T4_EQ_ENTRY_SIZE);
		if (num_wrs)
			err = build_rdma_recv(&qhp->wq, wqe, wr, &len16);
		else
			err = -ENOMEM;
		if (err) {
			*bad_wr = wr;
			break;
		}

		qhp->wq.rq.sw_rq[qhp->wq.rq.pidx].wr_id = wr->wr_id;
		if (chrd_wr_log) {
			qhp->wq.rq.sw_rq[qhp->wq.rq.pidx].sge_ts =
				cxgb4_read_sge_timestamp(qhp->rhp->rdev.lldi.ports[0]);
			qhp->wq.rq.sw_rq[qhp->wq.rq.pidx].host_time = ktime_get();
		}

		wqe->recv.opcode = FW_RI_RECV_WR;
		wqe->recv.r1 = 0;
		wqe->recv.wrid = qhp->wq.rq.pidx;
		wqe->recv.r2[0] = 0;
		wqe->recv.r2[1] = 0;
		wqe->recv.r2[2] = 0;
		wqe->recv.len16 = len16;
		pr_debug("cookie 0x%llx pidx %u qid %u\n",
			 (unsigned long long)wr->wr_id, qhp->wq.rq.pidx, qhp->wq.sq.qid);
		t4_rq_produce(&qhp->wq, len16);
		idx += DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);
		wr = wr->next;
		num_wrs--;
	}
	if (!qhp->rhp->rdev.status_page->db_off) {
		t4_ring_rq_db(&qhp->wq, idx, wqe);
		spin_unlock_irqrestore(&qhp->lock, flag);
	} else {
		spin_unlock_irqrestore(&qhp->lock, flag);
		ring_kernel_rq_db(qhp, idx);
	}
	return err;
}

int chrd_post_receive(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		      const struct ib_recv_wr **bad_wr)
{
	int ret = 0;

	switch (ibqp->qp_type) {
	case IB_QPT_RC:
	case IB_QPT_GSI:
	case IB_QPT_UD:
		ret = post_rc_receive(ibqp, wr, bad_wr);
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", ibqp->qp_type);
	}
	return ret;
}

static int roce_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			  const struct ib_send_wr **bad_wr)
{
	int err = 0;
	u8 len16 = 0;
	enum fw_wr_opcodes fw_opcode = 0;
	enum fw_ri_wr_flags fw_flags;
	struct chrd_qp *qhp;
	union t4_wr *wqe = NULL;
	u32 num_wrs;
	struct t4_swsqe *swsqe;
	unsigned long flag;
	u16 idx = 0;
	unsigned int chip_ver;

	qhp = to_chrd_qp(ibqp);
	spin_lock_irqsave(&qhp->lock, flag);

	/*
	 * If the qp has been flushed, then just insert a special
	 * drain cqe.
	 */
	if (qhp->wq.flushed) {
		spin_unlock_irqrestore(&qhp->lock, flag);
		err = complete_sq_drain_wrs(qhp, wr, bad_wr);
		pr_debug("complete_sq_drain_wrs qid %u ret %d\n", qhp->wq.sq.qid, err);
		return err;
	}
	num_wrs = t4_sq_avail(&qhp->wq);
	if (num_wrs == 0) {
		spin_unlock_irqrestore(&qhp->lock, flag);
		*bad_wr = wr;
		return -ENOMEM;
	}

	chip_ver = CHELSIO_CHIP_VERSION(qhp->rhp->rdev.lldi.adapter_type);

	/* Bhar: Recheck UD QP cosiderations 
		 PSN math is in FW */
	while (wr) {
		if (num_wrs == 0) {
			err = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		wqe = (union t4_wr *)((u8 *)qhp->wq.sq.queue +
		      qhp->wq.sq.wq_pidx * T4_EQ_ENTRY_SIZE);

		fw_flags = 0;
		if (wr->send_flags & IB_SEND_SOLICITED)
			fw_flags |= FW_RI_SOLICITED_EVENT_FLAG;
		if (wr->send_flags & IB_SEND_SIGNALED || qhp->sq_sig_all)
			fw_flags |= FW_RI_COMPLETION_FLAG;
		swsqe = &qhp->wq.sq.sw_sq[qhp->wq.sq.pidx];
		switch (wr->opcode) {
		case IB_WR_SEND_WITH_INV:
		case IB_WR_SEND:
			if (wr->send_flags & IB_SEND_FENCE)
				fw_flags |= FW_RI_READ_FENCE_FLAG;
			fw_opcode = FW_RI_V2_SEND_WR;
			if (qhp->qp_type == IB_QPT_GSI || qhp->qp_type == IB_QPT_UD) {
				swsqe->opcode = FW_RI_SEND;
				err = build_v2_ud_rdma_send(qhp, wqe, wr, &len16);
			} else {
				if (wr->opcode == IB_WR_SEND)
					swsqe->opcode = FW_RI_SEND;
				else
					swsqe->opcode = FW_RI_SEND_WITH_INV;
				err = build_v2_rdma_send(qhp, wqe, wr, &len16);
			}
			break;
		case IB_WR_RDMA_WRITE_WITH_IMM:
			if (unlikely(!qhp->rhp->rdev.lldi.write_w_imm_support)) {
				err = -ENOSYS;
				break;
			}
			fw_flags |= FW_RI_RDMA_WRITE_WITH_IMMEDIATE;
			fallthrough; /* fallthrough */
		case IB_WR_RDMA_WRITE:
			fw_opcode = FW_RI_V2_RDMA_WRITE_WR;
			swsqe->opcode = FW_RI_RDMA_WRITE;
			err = build_v2_rdma_write(qhp, wqe, wr, &len16);
			break;
		case IB_WR_RDMA_READ:
		case IB_WR_RDMA_READ_WITH_INV:
			fw_opcode = FW_RI_V2_RDMA_READ_WR;
			swsqe->opcode = FW_RI_READ_REQ;
			if (wr->opcode == IB_WR_RDMA_READ_WITH_INV) {
				chrd_invalidate_mr(qhp->rhp,
						   wr->sg_list[0].lkey);
				fw_flags |= FW_RI_RDMA_READ_INVALIDATE;
			}
			err = build_v2_rdma_read(qhp, wqe, wr, &len16);
			if (err)
				break;
			swsqe->read_len = wr->sg_list[0].length; //Bhar: fix length for multi sgl (trivial)
			if (!qhp->wq.sq.oldest_read) {
				qhp->wq.sq.oldest_read = swsqe;
				pr_debug("Oldest Read 0x%llx\n",
					 (unsigned long long)qhp->wq.sq.oldest_read);
			}
			break;
		case IB_WR_REG_MR: {
			struct chrd_mr *mhp = to_chrd_mr(reg_wr(wr)->mr);

			swsqe->opcode = FW_RI_FAST_REGISTER;
			if (qhp->rhp->rdev.lldi.fr_nsmr_tpte_wr_support &&
			    !mhp->attr.state && mhp->mpl_len <= 2) {
				fw_opcode = FW_RI_FR_NSMR_TPTE_WR;
				err = build_tpte_memreg(&wqe->fr_tpte, reg_wr(wr),
							mhp, &len16);
			} else {
				fw_opcode = FW_RI_V2_FR_NSMR_WR;
				err = build_v2_memreg(&qhp->wq.sq, wqe, reg_wr(wr),
				       mhp, &len16,
				       qhp->rhp->rdev.lldi.ulptx_memwrite_dsgl);
			}
			if (err)
				break;
			mhp->attr.state = 1;
			break;
		}
		case IB_WR_LOCAL_INV:
			if (wr->send_flags & IB_SEND_FENCE)
				fw_flags |= FW_RI_LOCAL_FENCE_FLAG;
			fw_opcode = FW_RI_V2_INV_LSTAG_WR;
			swsqe->opcode = FW_RI_LOCAL_INV;
			err = build_inv_stag(wqe, wr, &len16);
			chrd_invalidate_mr(qhp->rhp, wr->ex.invalidate_rkey);
			break;
		default:
			pr_debug("post of type=%d TBD!\n", wr->opcode);
			err = -EINVAL;
		}
		if (err) {
			*bad_wr = wr;
			break;
		}
		swsqe->idx = qhp->wq.sq.pidx;
		swsqe->complete = 0;
		swsqe->signaled = (wr->send_flags & IB_SEND_SIGNALED) ||
				  qhp->sq_sig_all;
		swsqe->flushed = 0;
		swsqe->wr_id = wr->wr_id;
		if (chrd_wr_log) {
			swsqe->sge_ts =
				cxgb4_read_sge_timestamp(qhp->rhp->rdev.lldi.ports[0]);
			swsqe->host_time = ktime_get();
		}

		init_wr_hdr(wqe, qhp->wq.sq.pidx, fw_opcode, fw_flags, len16);
		wr = wr->next;
		num_wrs--;
		t4_sq_produce(&qhp->wq, len16);
		pr_debug("qid %u in_use %u\n", qhp->wq.sq.qid, qhp->wq.sq.in_use);
		idx += DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);
	}
	if (!qhp->rhp->rdev.status_page->db_off) {
		t4_ring_sq_db(&qhp->wq, idx, wqe);
		spin_unlock_irqrestore(&qhp->lock, flag);
	} else {
		spin_unlock_irqrestore(&qhp->lock, flag);
		ring_kernel_sq_db(qhp, idx);
	}
	return err;
}

int chrd_roce_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			const struct ib_send_wr **bad_wr)
{
	int ret = 0;

	switch (ibqp->qp_type) {
	case IB_QPT_GSI:
	case IB_QPT_UD:
	case IB_QPT_RC:
		ret = roce_post_send(ibqp, wr, bad_wr);
		pr_debug("POST SEND ret %d\n", ret);
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", ibqp->qp_type);
	}
	return ret;
}

static void defer_srq_wr(struct t4_srq *srq, union t4_recv_wr *wqe,
			 uint64_t wr_id, u8 len16)
{
	struct t4_srq_pending_wr *pwr = &srq->pending_wrs[srq->pending_pidx];

	pr_debug("cidx %u pidx %u wq_pidx %u in_use %u ooo_count %u wr_id "
		 "0x%llx pending_cidx %u pending_pidx %u pending_in_use %u\n",
		 srq->cidx, srq->pidx, srq->wq_pidx,
		 srq->in_use, srq->ooo_count, (unsigned long long)wr_id,
		 srq->pending_cidx, srq->pending_pidx, srq->pending_in_use);
	pwr->wr_id = wr_id;
	pwr->len16 = len16;
	memcpy(&pwr->wqe, wqe, len16*16);
	t4_srq_produce_pending_wr(srq);
}

int chrd_post_srq_recv(struct ib_srq *ibsrq, const struct ib_recv_wr *wr,
		       const struct ib_recv_wr **bad_wr)
{
	int err = 0;
	struct chrd_srq *srq;
	union t4_recv_wr *wqe, lwqe;
	u32 num_wrs;
	u8 len16 = 0;
	u16 idx = 0;
	unsigned long flag;

	srq = to_chrd_srq(ibsrq);
	spin_lock_irqsave(&srq->lock, flag);
	num_wrs = t4_srq_avail(&srq->wq);
	if (num_wrs == 0) {
		spin_unlock_irqrestore(&srq->lock, flag);
		return -ENOMEM;
	}
	while (wr) {
		if (wr->num_sge > T4_MAX_RECV_SGE) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}
		wqe = &lwqe;
		if (num_wrs)
			err = build_srq_recv(wqe, wr, &len16);
		else
			err = -ENOMEM;
		if (err) {
			*bad_wr = wr;
			break;
		}

		wqe->recv.opcode = FW_RI_RECV_WR;
		wqe->recv.r1 = 0;
		wqe->recv.wrid = srq->wq.pidx;
		wqe->recv.r2[0] = 0;
		wqe->recv.r2[1] = 0;
		wqe->recv.r2[2] = 0;
		wqe->recv.len16 = len16;

		if (srq->wq.ooo_count || srq->wq.pending_in_use || srq->wq.sw_rq[srq->wq.pidx].valid)
			defer_srq_wr(&srq->wq, wqe, wr->wr_id, len16);
		else {
			srq->wq.sw_rq[srq->wq.pidx].wr_id = wr->wr_id;
			srq->wq.sw_rq[srq->wq.pidx].valid = 1;
			chrd_copy_wr_to_srq(&srq->wq, wqe, len16);
			pr_debug("cidx %u pidx %u wq_pidx %u in_use %u "
				 "wr_id 0x%llx \n", srq->wq.cidx,
				 srq->wq.pidx, srq->wq.wq_pidx, srq->wq.in_use,
				 (unsigned long long)wr->wr_id);
			t4_srq_produce(&srq->wq, len16);
			idx += DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);
		}
		wr = wr->next;
		num_wrs--;
	}
	if (idx)
		t4_ring_srq_db(&srq->wq, idx, len16, wqe);
	spin_unlock_irqrestore(&srq->lock, flag);
	return err;
}

static inline void build_term_codes(struct t4_cqe *err_cqe, u8 *layer_type,
				    u8 *ecode)
{
	int status;
	int tagged;
	int opcode;
	int rqtype;
	int send_inv;

	if (!err_cqe) {
		*layer_type = LAYER_RDMAP|DDP_LOCAL_CATA;
		*ecode = 0;
		return;
	}

	status = CQE_STATUS(err_cqe);
	opcode = CQE_OPCODE(err_cqe);
	rqtype = RQ_TYPE(err_cqe);
	send_inv = (opcode == FW_RI_SEND_WITH_INV) ||
		   (opcode == FW_RI_SEND_WITH_SE_INV);
	tagged = (opcode == FW_RI_RDMA_WRITE) ||
		 (rqtype && (opcode == FW_RI_READ_RESP));

	switch (status) {
	case T4_ERR_STAG:
		if (send_inv) {
			*layer_type = LAYER_RDMAP|RDMAP_REMOTE_OP;
			*ecode = RDMAP_CANT_INV_STAG;
		} else {
			*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
			*ecode = RDMAP_INV_STAG;
		}
		break;
	case T4_ERR_PDID:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
		if ((opcode == FW_RI_SEND_WITH_INV) ||
		    (opcode == FW_RI_SEND_WITH_SE_INV))
			*ecode = RDMAP_CANT_INV_STAG;
		else
			*ecode = RDMAP_STAG_NOT_ASSOC;
		break;
	case T4_ERR_QPID:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
		*ecode = RDMAP_STAG_NOT_ASSOC;
		break;
	case T4_ERR_ACCESS:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
		*ecode = RDMAP_ACC_VIOL;
		break;
	case T4_ERR_WRAP:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
		*ecode = RDMAP_TO_WRAP;
		break;
	case T4_ERR_BOUND:
		if (tagged) {
			*layer_type = LAYER_DDP|DDP_TAGGED_ERR;
			*ecode = DDPT_BASE_BOUNDS;
		} else {
			*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
			*ecode = RDMAP_BASE_BOUNDS;
		}
		break;
	case T4_ERR_INVALIDATE_SHARED_MR:
	case T4_ERR_INVALIDATE_MR_WITH_MW_BOUND:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_OP;
		*ecode = RDMAP_CANT_INV_STAG;
		break;
	case T4_ERR_ECC:
	case T4_ERR_ECC_PSTAG:
	case T4_ERR_INTERNAL_ERR:
		*layer_type = LAYER_RDMAP|RDMAP_LOCAL_CATA;
		*ecode = 0;
		break;
	case T4_ERR_OUT_OF_RQE:
		*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
		*ecode = DDPU_INV_MSN_NOBUF;
		break;
	case T4_ERR_PBL_ADDR_BOUND:
		*layer_type = LAYER_DDP|DDP_TAGGED_ERR;
		*ecode = DDPT_BASE_BOUNDS;
		break;
	case T4_ERR_CRC:
		*layer_type = LAYER_MPA|DDP_LLP;
		*ecode = MPA_CRC_ERR;
		break;
	case T4_ERR_MARKER:
		*layer_type = LAYER_MPA|DDP_LLP;
		*ecode = MPA_MARKER_ERR;
		break;
	case T4_ERR_PDU_LEN_ERR:
		*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
		*ecode = DDPU_MSG_TOOBIG;
		break;
	case T4_ERR_DDP_VERSION:
		if (tagged) {
			*layer_type = LAYER_DDP|DDP_TAGGED_ERR;
			*ecode = DDPT_INV_VERS;
		} else {
			*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
			*ecode = DDPU_INV_VERS;
		}
		break;
	case T4_ERR_RDMA_VERSION:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_OP;
		*ecode = RDMAP_INV_VERS;
		break;
	case T4_ERR_OPCODE:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_OP;
		*ecode = RDMAP_INV_OPCODE;
		break;
	case T4_ERR_DDP_QUEUE_NUM:
		*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
		*ecode = DDPU_INV_QN;
		break;
	case T4_ERR_MSN:
	case T4_ERR_MSN_GAP:
	case T4_ERR_MSN_RANGE:
	case T4_ERR_IRD_OVERFLOW:
		*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
		*ecode = DDPU_INV_MSN_RANGE;
		break;
	case T4_ERR_TBIT:
		*layer_type = LAYER_DDP|DDP_LOCAL_CATA;
		*ecode = 0;
		break;
	case T4_ERR_MO:
		*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
		*ecode = DDPU_INV_MO;
		break;
	default:
		*layer_type = LAYER_RDMAP|DDP_LOCAL_CATA;
		*ecode = 0;
		break;
	}
}

static void post_terminate(struct chrd_qp *qhp, struct t4_cqe *err_cqe,
			   gfp_t gfp)
{
	struct fw_ri_wr *wqe;
	struct sk_buff *skb;
	struct terminate_message *term;

	pr_debug("qhp 0x%llx qid 0x%x tid %u\n", (unsigned long long)qhp, qhp->wq.sq.qid,
		 qhp->ep->hwtid);

	skb = skb_dequeue(&qhp->ep->com.ep_skb_list);

	set_wr_txq(skb, CPL_PRIORITY_DATA, qhp->ep->com.txq_idx);

	wqe = (struct fw_ri_wr *)__skb_put(skb, sizeof(*wqe));
	memset(wqe, 0, sizeof *wqe);
	wqe->op_compl = cpu_to_be32(V_FW_WR_OP(FW_RI_WR));
	wqe->flowid_len16 = cpu_to_be32(
		V_FW_WR_FLOWID(qhp->ep->hwtid) |
		V_FW_WR_LEN16(DIV_ROUND_UP(sizeof *wqe, 16)));

	wqe->u.terminate.type = FW_RI_TYPE_TERMINATE;
	wqe->u.terminate.immdlen = cpu_to_be32(sizeof *term);
	term = (struct terminate_message *)wqe->u.terminate.termmsg;
	if (qhp->attr.layer_etype == (LAYER_MPA|DDP_LLP)) {
		term->layer_etype = qhp->attr.layer_etype;
		term->ecode = qhp->attr.ecode;
	} else
		build_term_codes(err_cqe, &term->layer_etype, &term->ecode);
	chrd_ofld_send(&qhp->rhp->rdev, skb);
}

static void flush_raw_qp(struct chrd_raw_qp *rqp)
{
	return;
}

static int raw_init(struct chrd_raw_qp *rqp)
{
	return 0;
}

static int raw_fini(struct chrd_raw_qp *rqp)
{
	return 0;
}

static int modify_raw_qp(struct chrd_raw_qp *rqp,
			 enum chrd_qp_attr_mask mask,
			 struct chrd_common_qp_attributes *attrs)
{
	int ret = 0;

	mutex_lock(&rqp->mutex);

	if (mask & CHRD_QP_ATTR_SQ_DB) {
		ret = ring_kernel_txq_db(rqp, attrs->sq_db_inc);
		goto out;
	}
	if (mask & CHRD_QP_ATTR_RQ_DB) {
		ret = ring_kernel_fl_db(rqp, attrs->rq_db_inc);
		goto out;
	}

	if (!(mask & CHRD_QP_ATTR_NEXT_STATE))
		goto out;
	if (rqp->state == attrs->next_state)
		goto out;

	switch (rqp->state) {
	case CHRD_QP_STATE_IDLE:
		switch (attrs->next_state) {
		case CHRD_QP_STATE_RTS:
			rqp->state = CHRD_QP_STATE_RTS;
			raw_init(rqp);
			break;
		case CHRD_QP_STATE_ERROR:
			flush_raw_qp(rqp);
			rqp->state = CHRD_QP_STATE_ERROR;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	case CHRD_QP_STATE_RTS:
		switch (attrs->next_state) {
		case CHRD_QP_STATE_ERROR:
			raw_fini(rqp);
			flush_raw_qp(rqp);
			rqp->state = CHRD_QP_STATE_ERROR;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	case CHRD_QP_STATE_ERROR:
		switch (attrs->next_state) {
		case CHRD_QP_STATE_IDLE:
			rqp->state = CHRD_QP_STATE_IDLE;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	default:
		pr_err("%s in a bad state %d\n",
		       __func__, rqp->state);
		ret = -EINVAL;
		goto out;
	}
out:
	mutex_unlock(&rqp->mutex);
	return ret;
}

/*
 * Assumes qhp lock is held.
 */
static void __flush_qp(struct chrd_qp *qhp, struct chrd_cq *rchp,
		       struct chrd_cq *schp)
{
	int count;
	int rq_flushed = 0;
	int sq_flushed = 0;
	unsigned long flag;

	pr_debug("qhp 0x%llx rchp 0x%llx schp 0x%llx\n", (unsigned long long)qhp,
		 (unsigned long long)rchp, (unsigned long long)schp);

	/* locking heirarchy: cqs lock first, then qp lock. */
	spin_lock_irqsave(&rchp->lock, flag);
	if (schp != rchp)
		 spin_lock(&schp->lock);
	spin_lock(&qhp->lock);
	
	if (qhp->wq.flushed) {
		spin_unlock(&qhp->lock);
		if (schp != rchp)
			spin_unlock(&schp->lock);
		spin_unlock_irqrestore(&rchp->lock, flag);
		return;
	}
	qhp->wq.flushed = 1;
	t4_set_wq_in_error(&qhp->wq, 0);

	chrd_flush_hw_cq(rchp, qhp);
	if (!qhp->srq) {
		chrd_count_rcqes(&rchp->cq, &qhp->wq, &count);
		rq_flushed = chrd_flush_rq(qhp, &rchp->cq, count);
	}
	if (schp != rchp)
		chrd_flush_hw_cq(schp, qhp);
	sq_flushed = chrd_flush_sq(qhp);

	spin_unlock(&qhp->lock);
	if (schp != rchp)
		spin_unlock(&schp->lock);
	spin_unlock_irqrestore(&rchp->lock, flag);
	if (schp == rchp) {
		if ((rq_flushed || sq_flushed) &&
		    t4_clear_cq_armed(&rchp->cq, qhp->ibqp.uobject) &&
		    rchp->ibcq.comp_handler) {
			spin_lock_irqsave(&rchp->comp_handler_lock, flag);
			(*rchp->ibcq.comp_handler)(&rchp->ibcq,
						   rchp->ibcq.cq_context);
			spin_unlock_irqrestore(&rchp->comp_handler_lock, flag);
		}
	} else {
		if (rq_flushed && t4_clear_cq_armed(&rchp->cq, qhp->ibqp.uobject) &&
		    rchp->ibcq.comp_handler) {
			spin_lock_irqsave(&rchp->comp_handler_lock, flag);
			(*rchp->ibcq.comp_handler)(&rchp->ibcq,
						   rchp->ibcq.cq_context);
			spin_unlock_irqrestore(&rchp->comp_handler_lock, flag);
		}
		if (sq_flushed && t4_clear_cq_armed(&schp->cq, qhp->ibqp.uobject) &&
		    schp->ibcq.comp_handler) {
			spin_lock_irqsave(&schp->comp_handler_lock, flag);
			(*schp->ibcq.comp_handler)(&schp->ibcq,
						   schp->ibcq.cq_context);
			spin_unlock_irqrestore(&schp->comp_handler_lock, flag);
		}
	}
}

static void flush_qp(struct chrd_qp *qhp)
{
	struct chrd_cq *rchp, *schp;
	unsigned long flag;

	rchp = to_chrd_cq(qhp->ibqp.recv_cq);
	schp = to_chrd_cq(qhp->ibqp.send_cq);

	if (qhp->ibqp.uobject) {

		/* qhp->wq.flush is protected by qhp->mutex */
		if (qhp->wq.flushed)
			return;

		qhp->wq.flushed = 1;
		t4_set_wq_in_error(&qhp->wq, 0);
		t4_set_cq_in_error(&rchp->cq);
		spin_lock_irqsave(&rchp->comp_handler_lock, flag);
		(*rchp->ibcq.comp_handler)(&rchp->ibcq, rchp->ibcq.cq_context);
		spin_unlock_irqrestore(&rchp->comp_handler_lock, flag);
		if (schp != rchp) {
			t4_set_cq_in_error(&schp->cq);
			spin_lock_irqsave(&schp->comp_handler_lock, flag);
			(*schp->ibcq.comp_handler)(&schp->ibcq,
						   schp->ibcq.cq_context);
			spin_unlock_irqrestore(&schp->comp_handler_lock, flag);
		}
		return;
	}
	__flush_qp(qhp, rchp, schp);
}

static int rdma_fini(struct chrd_dev *rhp, struct chrd_qp *qhp,
		     struct chrd_ep *ep)
{
	struct fw_ri_wr *wqe;
	int ret;
	struct sk_buff *skb;

	pr_debug("qhp 0x%llx qid 0x%x tid %u\n", (unsigned long long)qhp, qhp->wq.sq.qid,
		 ep->hwtid);

	skb = skb_dequeue(&ep->com.ep_skb_list);

	set_wr_txq(skb, CPL_PRIORITY_DATA, ep->com.txq_idx);

	wqe = (struct fw_ri_wr *)__skb_put(skb, sizeof(*wqe));
	memset(wqe, 0, sizeof *wqe);
	wqe->op_compl = cpu_to_be32(
		V_FW_WR_OP(FW_RI_WR) |
		F_FW_WR_COMPL);
	wqe->flowid_len16 = cpu_to_be32(
		V_FW_WR_FLOWID(ep->hwtid) |
		V_FW_WR_LEN16(DIV_ROUND_UP(sizeof *wqe, 16)));
	wqe->cookie = (uintptr_t)ep->com.wr_waitp;

	wqe->u.fini.type = FW_RI_TYPE_FINI;
	ret = chrd_ref_send_wait(&rhp->rdev, skb, ep->com.wr_waitp,
				 qhp->ep->hwtid, qhp->wq.sq.qid, __func__);
	
	pr_debug("ret %d\n", ret);
	return ret;
}
static int rdma_roce_fini(struct chrd_dev *rhp, struct chrd_qp *qhp)
{
	struct fw_ri_wr *wqe;
	int ret, wrlen;
	struct sk_buff *skb;
	struct chrd_ah *ahp;
	u32 tid;

	pr_debug("qhp 0x%llx qid 0x%x\n", (unsigned long long)qhp, qhp->wq.sq.qid);
	if (qhp->qp_type == IB_QPT_GSI) {
		tid = qhp->roce_attr.gsi_ftid;
	} else if (qhp->qp_type == IB_QPT_RC) {
		tid = qhp->roce_attr.hwtid;
		ahp = &qhp->roce_attr.roce_ah;
		cxgb4_uld_tid_remove(qhp->netdev, 0, ahp->sgid_addr.saddr_in.sin_family, tid);
	} else {
		pr_err("Unwanted QP type!!!!!!\n");
		BUG_ON(1);
	}

	wrlen = sizeof *wqe;

	if (wrlen%16)
		roundup(wrlen, 16);
	skb = alloc_skb(wrlen, GFP_KERNEL | __GFP_NOFAIL);
	pr_debug("rdma_fini skb %p\n", skb);
	set_wr_txq(skb, CPL_PRIORITY_DATA, qhp->txq_id);

	wqe = (struct fw_ri_wr *)__skb_put(skb, wrlen);
	memset(wqe, 0, wrlen);
	if ((qhp->qp_type == IB_QPT_GSI) || (qhp->qp_type == IB_QPT_UD))
		wqe->op_compl = cpu_to_be32(V_FW_WR_OP(FW_RI_WR) |
					    F_FW_WR_COMPL |
					    V_FW_RI_WR_TRANSPORT_TYPE(FW_QP_TRANSPORT_TYPE_ROCEV2_UD));
	else
		wqe->op_compl = cpu_to_be32(V_FW_WR_OP(FW_RI_WR) |
					    F_FW_WR_COMPL |
					    V_FW_RI_WR_TRANSPORT_TYPE(FW_QP_TRANSPORT_TYPE_ROCEV2_RC));

	wqe->flowid_len16 = cpu_to_be32(
					V_FW_WR_FLOWID(tid) |
					V_FW_WR_LEN16(DIV_ROUND_UP(wrlen, 16)));
	wqe->cookie = (uintptr_t)qhp->wr_waitp;
	wqe->u.fini.type = FW_RI_TYPE_FINI;

	if (unlikely((qhp->qp_type == IB_QPT_GSI) || (qhp->qp_type == IB_QPT_UD))) {
		ret = chrd_ref_send_wait(&rhp->rdev, skb, qhp->wr_waitp,
					 tid,
					 qhp->wq.sq.qid, __func__);
	} else {
		ret = chrd_ref_send_wait(&rhp->rdev, skb, qhp->wr_waitp,
					 qhp->roce_attr.hwtid,
					 qhp->wq.sq.qid, __func__);
	}

	return ret;
}

static void build_rtr_msg(u8 p2p_type, struct fw_ri_init *init)
{
	pr_debug("p2p_type = %d\n", p2p_type);
	memset(&init->u, 0, sizeof init->u);
	switch (p2p_type) {
	case FW_RI_INIT_P2PTYPE_RDMA_WRITE:
		init->u.write.opcode = FW_RI_RDMA_WRITE_WR;
		init->u.write.stag_sink = cpu_to_be32(1);
		init->u.write.to_sink = cpu_to_be64(1);
		init->u.write.u.immd_src[0].op = FW_RI_DATA_IMMD;
		init->u.write.len16 = DIV_ROUND_UP(sizeof init->u.write +
						   sizeof(struct fw_ri_immd),
						   16);
		break;
	case FW_RI_INIT_P2PTYPE_READ_REQ:
		init->u.write.opcode = FW_RI_RDMA_READ_WR;
		init->u.read.stag_src = cpu_to_be32(1);
		init->u.read.to_src_lo = cpu_to_be32(1);
		init->u.read.stag_sink = cpu_to_be32(1);
		init->u.read.to_sink_lo = cpu_to_be32(1);
		init->u.read.len16 = DIV_ROUND_UP(sizeof init->u.read, 16);
		break;
	}
}

static int rdma_init(struct chrd_dev *rhp, struct chrd_qp *qhp)
{
	struct fw_ri_wr *wqe;
	int ret;
	struct sk_buff *skb;

	pr_debug("qhp 0x%llx qid 0x%x tid %u ird %u ord %u\n", (unsigned long long)qhp,
		 qhp->wq.sq.qid, qhp->ep->hwtid, qhp->ep->ird, qhp->ep->ord);

	skb = alloc_skb(sizeof *wqe, GFP_KERNEL | __GFP_NOFAIL);
	if (!skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = alloc_ird(rhp, qhp->attr.max_ird);
	if (ret) {
		qhp->attr.max_ird = 0;
		kfree_skb(skb);
		goto out;
	}
	set_wr_txq(skb, CPL_PRIORITY_DATA, qhp->ep->com.txq_idx);

	wqe = (struct fw_ri_wr *)__skb_put(skb, sizeof(*wqe));
	memset(wqe, 0, sizeof *wqe);
	wqe->op_compl = cpu_to_be32(
		V_FW_WR_OP(FW_RI_WR) |
		F_FW_WR_COMPL |
		V_FW_RI_WR_TRANSPORT_TYPE(FW_QP_TRANSPORT_TYPE_IWARP));
	wqe->flowid_len16 = cpu_to_be32(
		V_FW_WR_FLOWID(qhp->ep->hwtid) |
		V_FW_WR_LEN16(DIV_ROUND_UP(sizeof *wqe, 16)));
	wqe->cookie = (uintptr_t)qhp->ep->com.wr_waitp;

	wqe->u.init.type = FW_RI_TYPE_INIT;
	wqe->u.init.mpareqbit_p2ptype =
		V_FW_RI_WR_MPAREQBIT(qhp->attr.mpa_attr.initiator) |
		V_FW_RI_WR_P2PTYPE(qhp->attr.mpa_attr.p2p_type);
	wqe->u.init.mpa_attrs = FW_RI_MPA_IETF_ENABLE;
	if (qhp->attr.mpa_attr.recv_marker_enabled)
		wqe->u.init.mpa_attrs |= FW_RI_MPA_RX_MARKER_ENABLE;
	if (qhp->attr.mpa_attr.xmit_marker_enabled)
		wqe->u.init.mpa_attrs |= FW_RI_MPA_TX_MARKER_ENABLE;
	if (qhp->attr.mpa_attr.crc_enabled)
		wqe->u.init.mpa_attrs |= FW_RI_MPA_CRC_ENABLE;

	wqe->u.init.qp_caps = FW_RI_QP_RDMA_READ_ENABLE |
			    FW_RI_QP_RDMA_WRITE_ENABLE |
			    FW_RI_QP_BIND_ENABLE;
	if (!qhp->ibqp.uobject)
		wqe->u.init.qp_caps |= FW_RI_QP_FAST_REGISTER_ENABLE |
				     FW_RI_QP_STAG0_ENABLE;
	wqe->u.init.nrqe = cpu_to_be16(t4_rqes_posted(&qhp->wq));
	wqe->u.init.pdid = cpu_to_be32(qhp->attr.pd);
	wqe->u.init.qpid = cpu_to_be32(qhp->wq.sq.qid);
	wqe->u.init.sq_eqid = cpu_to_be32(qhp->wq.sq.qid);
	if (qhp->srq)
		wqe->u.init.rq_eqid = cpu_to_be32(FW_RI_INIT_RQEQID_SRQ |
						  qhp->srq->idx);
	else {
		wqe->u.init.rq_eqid = cpu_to_be32(qhp->wq.rq.qid);
		wqe->u.init.hwrqsize = cpu_to_be32(qhp->wq.rq.rqt_size);
		wqe->u.init.hwrqaddr = cpu_to_be32(qhp->wq.rq.rqt_hwaddr -
						   rhp->rdev.lldi.vr->rq.start);
	}
	wqe->u.init.scqid = cpu_to_be32(qhp->attr.scq);
	wqe->u.init.rcqid = cpu_to_be32(qhp->attr.rcq);
	wqe->u.init.ord_max = cpu_to_be32(qhp->attr.max_ord);
	wqe->u.init.ird_max = cpu_to_be32(qhp->attr.max_ird);
	wqe->u.init.iss = cpu_to_be32(qhp->ep->snd_seq);
	wqe->u.init.irs = cpu_to_be32(qhp->ep->rcv_seq);
	if (qhp->attr.mpa_attr.initiator)
		build_rtr_msg(qhp->attr.mpa_attr.p2p_type, &wqe->u.init);

	ret = chrd_ref_send_wait(&rhp->rdev, skb, qhp->ep->com.wr_waitp,
				 qhp->ep->hwtid, qhp->wq.sq.qid, __func__);

	if (!ret)
		goto out;

	free_ird(rhp, qhp->attr.max_ird);
out:
	pr_debug("ret %d\n", ret);
	return ret;
}

int chrd_modify_iw_rc_qp(struct chrd_qp *qhp, enum chrd_qp_attr_mask mask,
		      struct chrd_common_qp_attributes *attrs, int internal)
{
	int ret = 0;
	struct chrd_common_qp_attributes newattr = qhp->attr;
	int disconnect = 0;
	int terminate = 0;
	int abort = 0;
	int free = 0;
	struct chrd_ep *ep = NULL;
	struct chrd_dev *rhp = qhp->rhp;

	pr_debug("qhp 0x%llx sqid 0x%x rqid 0x%x ep %p state %d -> %d\n",
		 (unsigned long long)qhp, qhp->wq.sq.qid, qhp->wq.rq.qid,
		 qhp->ep, qhp->attr.state,
		 (mask & CHRD_QP_ATTR_NEXT_STATE) ? attrs->next_state : -1);

	mutex_lock(&qhp->mutex);

	/* Process attr changes if in IDLE */
	if (mask & CHRD_QP_ATTR_VALID_MODIFY) {
		if (qhp->attr.state != CHRD_QP_STATE_IDLE) {
			ret = -EIO;
			goto out;
		}
		if (mask & CHRD_QP_ATTR_ENABLE_RDMA_READ)
			newattr.enable_rdma_read = attrs->enable_rdma_read;
		if (mask & CHRD_QP_ATTR_ENABLE_RDMA_WRITE)
			newattr.enable_rdma_write = attrs->enable_rdma_write;
		if (mask & CHRD_QP_ATTR_ENABLE_RDMA_BIND)
			newattr.enable_bind = attrs->enable_bind;
		if (mask & CHRD_QP_ATTR_MAX_ORD) {
			if (attrs->max_ord > chrd_max_read_depth) {
				ret = -EINVAL;
				goto out;
			}
			newattr.max_ord = attrs->max_ord;
		}
		if (mask & CHRD_QP_ATTR_MAX_IRD) {
			if (attrs->max_ird > cur_max_read_depth(rhp)) {
				ret = -EINVAL;
				goto out;
			}
			newattr.max_ird = attrs->max_ird;
		}
		qhp->attr = newattr;
	}

	if (mask & CHRD_QP_ATTR_SQ_DB) {
		ret = ring_kernel_sq_db(qhp, attrs->sq_db_inc);
		goto out;
	}
	if (mask & CHRD_QP_ATTR_RQ_DB) {
		ret = ring_kernel_rq_db(qhp, attrs->rq_db_inc);
		goto out;
	}

	if (!(mask & CHRD_QP_ATTR_NEXT_STATE))
		goto out;
	if (qhp->attr.state == attrs->next_state)
		goto out;

	switch (qhp->attr.state) {
	case CHRD_QP_STATE_IDLE:
		switch (attrs->next_state) {
		case CHRD_QP_STATE_RTS:
			if (!(mask & CHRD_QP_ATTR_LLP_STREAM_HANDLE)) {
				ret = -EINVAL;
				goto out;
			}
			if (!(mask & CHRD_QP_ATTR_MPA_ATTR)) {
				ret = -EINVAL;
				goto out;
			}
			qhp->attr.mpa_attr = attrs->mpa_attr;
			qhp->attr.llp_stream_handle = attrs->llp_stream_handle;
			qhp->ep = qhp->attr.llp_stream_handle;
			set_state(qhp, CHRD_QP_STATE_RTS);

			/*
			 * Ref the endpoint here and deref when we
			 * disassociate the endpoint from the QP.  This
			 * happens in CLOSING->IDLE transition or *->ERROR
			 * transition.
			 */
			chrd_get_ep(&qhp->ep->com);
			ret = rdma_init(rhp, qhp);
			if (ret)
				goto err;
			break;
		case CHRD_QP_STATE_ERROR:
			set_state(qhp, CHRD_QP_STATE_ERROR);
			flush_qp(qhp);
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	case CHRD_QP_STATE_RTS:
		switch (attrs->next_state) {
		case CHRD_QP_STATE_CLOSING:
			t4_set_wq_in_error(&qhp->wq, 0);
			set_state(qhp, CHRD_QP_STATE_CLOSING);
			ep = qhp->ep;
			if (!internal) {
				abort = 0;
				disconnect = 1;
				chrd_get_ep(&qhp->ep->com);
			}
			ret = rdma_fini(rhp, qhp, ep);
			if (ret)
				goto err;
			break;
		case CHRD_QP_STATE_TERMINATE:
			t4_set_wq_in_error(&qhp->wq, 0);
			set_state(qhp, CHRD_QP_STATE_TERMINATE);
			qhp->attr.layer_etype = attrs->layer_etype;
			qhp->attr.ecode = attrs->ecode;
			ep = qhp->ep;
			if (!internal) {
				chrd_get_ep(&qhp->ep->com);
				terminate = 1;
				disconnect = 1;
			} else {
				terminate = qhp->attr.send_term;
				ret = rdma_fini(rhp, qhp, ep);
				if (ret)
					goto err;
			}
			break;
		case CHRD_QP_STATE_ERROR:
			t4_set_wq_in_error(&qhp->wq, 0);
			set_state(qhp, CHRD_QP_STATE_ERROR);
			if (!internal) {
				abort = 1;
				disconnect = 1;
				ep = qhp->ep;
				chrd_get_ep(&qhp->ep->com);
			}
			goto err;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	case CHRD_QP_STATE_CLOSING:

		/*
		 * Allow kernel users to move to ERROR for qp draining.
		 */
		if (!internal && (qhp->ibqp.uobject || attrs->next_state !=
				  CHRD_QP_STATE_ERROR)) {
			ret = -EINVAL;
			goto out;
		}
		switch (attrs->next_state) {
		case CHRD_QP_STATE_IDLE:
			flush_qp(qhp);
			set_state(qhp, CHRD_QP_STATE_IDLE);
			qhp->attr.llp_stream_handle = NULL;
			chrd_put_ep(&qhp->ep->com);
			qhp->ep = NULL;
			wake_up(&qhp->wait);
			break;
		case CHRD_QP_STATE_ERROR:
			goto err;
		default:
			ret = -EINVAL;
			goto err;
		}
		break;
	case CHRD_QP_STATE_ERROR:
		if (attrs->next_state != CHRD_QP_STATE_IDLE) {
			ret = -EINVAL;
			goto out;
		}
		if (!t4_sq_empty(&qhp->wq) || !t4_rq_empty(&qhp->wq)) {
			ret = -EINVAL;
			goto out;
		}
		set_state(qhp, CHRD_QP_STATE_IDLE);
		break;
	case CHRD_QP_STATE_TERMINATE:
		if (!internal) {
			ret = -EINVAL;
			goto out;
		}
		goto err;
		break;
	default:
		pr_err("%s in a bad state %d\n", __func__, qhp->attr.state);
		ret = -EINVAL;
		goto err;
		break;
	}
	goto out;
err:
	pr_debug("disassociating ep %p qpid 0x%x\n", qhp->ep, qhp->wq.sq.qid);

	/* disassociate the LLP connection */
	qhp->attr.llp_stream_handle = NULL;
	if (!ep)
		ep = qhp->ep;
	qhp->ep = NULL;
	set_state(qhp, CHRD_QP_STATE_ERROR);
	free = 1;
	abort = 1;
	flush_qp(qhp);
	wake_up(&qhp->wait);
out:
	mutex_unlock(&qhp->mutex);

	if (terminate)
		post_terminate(qhp, NULL, internal ? GFP_ATOMIC : GFP_KERNEL);

	/*
	 * If disconnect is 1, then we need to initiate a disconnect
	 * on the EP.  This can be a normal close (RTS->CLOSING) or
	 * an abnormal close (RTS/CLOSING->ERROR).
	 */
	if (disconnect) {
		chrd_ep_disconnect(ep, abort, internal ? GFP_ATOMIC :
							 GFP_KERNEL);
		chrd_put_ep(&ep->com);
	}

	/*
	 * If free is 1, then we've disassociated the EP from the QP
	 * and we need to dereference the EP.
	 */
	if (free)
		chrd_put_ep(&ep->com);
	pr_debug("exit state %d\n", qhp->attr.state);
	return ret;
}

static int send_roce_flowc(struct chrd_qp *qhp)
{
	struct fw_flowc_wr *flowc;
	struct sk_buff *skb;
	int flowclen, flowclen16;
	int nparams = 6; //Bhar: modify this later based on fw
	u16 rss_qid;
	u32 tx_chan;
	int step, err;
	struct cxgb4_uld_txq_info txq_info = { 0 };

	tx_chan = cxgb4_port_chan(qhp->netdev);
	step = qhp->rhp->rdev.lldi.nrxq / qhp->rhp->rdev.lldi.nchan;
	rss_qid = qhp->rhp->rdev.lldi.rxq_ids[cxgb4_port_idx(qhp->netdev) * step];
	step = qhp->rhp->rdev.lldi.ntxq / qhp->rhp->rdev.lldi.nchan;
	txq_info.uld_index = cxgb4_port_idx(qhp->netdev) * step;
	/* cxgb4_uld_txq_alloc() will take refernce to txq */
	err = cxgb4_uld_txq_alloc(qhp->netdev, CXGB4_ULD_TYPE_RDMA, &txq_info);
	if (err < 0)
		return err;
	qhp->txq_id = txq_info.lld_index;
	cxgb4_uld_tid_qid_sel_update(qhp->netdev,
				     CXGB4_ULD_TYPE_RDMA, (qhp->qp_type == IB_QPT_GSI ?
				     qhp->roce_attr.gsi_ftid : qhp->roce_attr.hwtid),
				     &qhp->txq_id);

	flowclen = offsetof(struct fw_flowc_wr, mnemval[nparams]);
	flowclen16 = DIV_ROUND_UP(flowclen, 16);
	flowclen = flowclen16 * 16;

	skb = get_skb(NULL, flowclen, GFP_KERNEL);
	if (WARN_ON(!skb))
		return -ENOMEM;

	flowc = (struct fw_flowc_wr *)__skb_put(skb, flowclen);
	memset(flowc, 0, flowclen);

	flowc->op_to_nparams = cpu_to_be32(V_FW_WR_OP(FW_FLOWC_WR) |
					   V_FW_FLOWC_WR_NPARAMS(nparams));
	flowc->flowid_len16 = cpu_to_be32(V_FW_WR_LEN16(flowclen16) |
					  V_FW_WR_FLOWID(qhp->qp_type == IB_QPT_GSI ?
					  qhp->roce_attr.gsi_ftid : qhp->roce_attr.hwtid));

	flowc->mnemval[0].mnemonic = FW_FLOWC_MNEM_PFNVFN;
	flowc->mnemval[0].val = cpu_to_be32(
		V_FW_PFVF_CMD_PFN(qhp->rhp->rdev.lldi.pf));
	flowc->mnemval[1].mnemonic = FW_FLOWC_MNEM_CH;
	flowc->mnemval[1].val = cpu_to_be32(tx_chan);
	flowc->mnemval[2].mnemonic = FW_FLOWC_MNEM_PORT;
	flowc->mnemval[2].val = cpu_to_be32(tx_chan);
	flowc->mnemval[3].mnemonic = FW_FLOWC_MNEM_ULP_MODE;
	flowc->mnemval[3].val = cpu_to_be32(ULP_MODE_RDMA_V2);
	flowc->mnemval[4].mnemonic = FW_FLOWC_MNEM_MSS;
	flowc->mnemval[4].val = cpu_to_be32(qhp->mtu);
	flowc->mnemval[5].mnemonic = FW_FLOWC_MNEM_IQID;
	flowc->mnemval[5].val = cpu_to_be32(rss_qid);
	if(qhp->roce_attr.roce_ah.insert_vlan_tag) {
		u16 vlan = qhp->roce_attr.roce_ah.vlan_id;
		if (vlan == CPL_L2T_VLAN_NONE)
			nparams = 9;
		else
			nparams = 10;
		if (nparams == 10) {
			u16 pri;
			pri = (vlan & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
			flowc->mnemval[9].mnemonic = FW_FLOWC_MNEM_SCHEDCLASS;
			flowc->mnemval[9].val = cpu_to_be32(pri);
		}
	}
	set_wr_txq(skb, CPL_PRIORITY_DATA, qhp->txq_id);
	return chrd_ofld_send(&qhp->rhp->rdev, skb);
}

static u64 roce_select_ntuple(struct net_device *dev,
			      struct chrd_qp *qhp)
{
	struct chrd_ah *ahp = &qhp->roce_attr.roce_ah;
	struct adapter *adap = netdev2adap(dev);
	struct tp_params *tp = &adap->params.tp;
	u64 ntuple = 0;
	
	/* Initialize each of the fields which we care about which are present
	 * in the Compressed Filter Tuple.
	 */
	if (tp->vlan_shift >= 0 && qhp->roce_attr.roce_ah.vlan_id != CPL_L2T_VLAN_NONE)
		ntuple |= (u64)(F_FT_VLAN_VLD | qhp->roce_attr.roce_ah.vlan_id) << tp->vlan_shift;

	if (tp->protocol_shift >= 0)
		ntuple |= (u64)IPPROTO_UDP << tp->protocol_shift;

	ntuple |= (u64)(1) << tp->roce_shift;
	if (ahp->xfrm.ipsec_en)
		ntuple |= (u64)(ahp->xfrm.ipsecidx) << tp->ipsecidx_shift;

	return ntuple;
}

static int roce_act_open_req(struct chrd_qp *qhp)
{
	struct chrd_ah *ahp = &qhp->roce_attr.roce_ah;
	struct cpl_t7_act_open_req6 *t7req6 = NULL;
	struct cpl_t7_act_open_req *t7req = NULL;
	struct net_device *netdev = qhp->netdev;
	struct cpl_act_open_req6 *req6 = NULL;
	struct cpl_act_open_req *req = NULL;
	struct chrd_dev *dev = qhp->rhp;
	unsigned int chip_ver;
	int sizev4, wrlen, sizev6;
	struct port_info *pi;
	struct sk_buff *skb;
	u32 smac_idx;
	u16 rss_qid;
	u32 tx_chan;
	u64 params;
	u64 opt0;
	u32 opt2;
	int ret, step;

	struct sockaddr_in *la = (struct sockaddr_in *)&ahp->sgid_addr.saddr_in;
	struct sockaddr_in *ra = (struct sockaddr_in *)&ahp->dgid_addr.saddr_in;
	struct sockaddr_in6 *la6 = (struct sockaddr_in6 *)&ahp->sgid_addr.saddr_in6;
	struct sockaddr_in6 *ra6 = (struct sockaddr_in6 *)&ahp->dgid_addr.saddr_in6;

	chip_ver = CHELSIO_CHIP_VERSION(qhp->rhp->rdev.lldi.adapter_type);
	switch (chip_ver) {
	case CHELSIO_T7:
	default:
		sizev4 = sizeof(struct cpl_t7_act_open_req);
		sizev6 = sizeof(struct cpl_t7_act_open_req6);
	}

	wrlen = (ahp->net_type == RDMA_NETWORK_IPV4) ? roundup(sizev4, 16) : roundup(sizev6, 16);
	ret = cxgb4_uld_atid_alloc(netdev, qhp);
	if (ret < 0) {
		pr_err("%s - cannot allocate atid.\n", __func__);
		return ret;
	}

	qhp->roce_attr.atid = ret;
	qhp->roce_attr.hwtid = -1;					/*Todo: hardcoded value*/

	//Bhar: add atid to xarray for debug and rpl processing`
//     err = xa_insert_irq(&ep->com.dev->atids, ep->atid, ep, GFP_KERNEL);		/*Todo: Check the Commented Code*/
//     if (err)
//             goto fail2a;

	pr_debug("qhp 0x%llx roce_attr 0x%llx ahp 0x%llx atid %u\n",
		 (unsigned long long)qhp, (unsigned long long)&qhp->roce_attr,
		 (unsigned long long)ahp, qhp->roce_attr.atid);

	pr_debug("ahp 0x%llx sport %u dport %u smac %pM dmac %pM "
		 "dest_ip %pI4, src_ip %pI4\n", (unsigned long long)ahp,
		 ahp->src_port, ahp->dst_port, ahp->smac, ahp->dmac,
		 &ahp->dest_ip_addr[3], &ahp->local_ip_addr[3]);

	skb = get_skb(NULL, wrlen, GFP_KERNEL);
	if (!skb) {
		pr_err("%s - failed to alloc skb\n", __func__);
		return -ENOMEM;
	}
	set_wr_txq(skb, CPL_PRIORITY_SETUP,
		   NCHAN + cxgb4_port_idx(netdev));

	//Bhar: set bellow fields appropriately based on port
	tx_chan = cxgb4_port_chan(netdev);
	step = dev->rdev.lldi.nrxq / dev->rdev.lldi.nchan;
	pi = (struct port_info *)netdev_priv(netdev);
	rss_qid = dev->rdev.lldi.rxq_ids[pi->port_id * step];
	smac_idx = pi->smt_idx;

	opt0 = F_TCAM_BYPASS |
	       F_NON_OFFLOAD |
	       F_KEEP_ALIVE |
	       F_DELACK |
	       V_L2T_IDX(0) |
	       V_TX_CHAN(tx_chan) |
	       V_SMAC_SEL(smac_idx) |
	       V_ULP_MODE(ULP_MODE_RDMA_V2);

	opt2 = V_TX_QUEUE(dev->rdev.lldi.tx_modq[tx_chan]) |
	       V_RX_CHANNEL(0) |
	       V_CCTRL_ECN(0) |
	       F_RSS_QUEUE_VALID | V_RSS_QUEUE(rss_qid);

	params = roce_select_ntuple(netdev, qhp);

	if (ahp->net_type == RDMA_NETWORK_IPV6) {
		ret = cxgb4_clip_get(qhp->rhp->rdev.lldi.ports[0],
				(const u32 *)&la6->sin6_addr.s6_addr, 1);
		if (ret)
			return ret;
	}

	if (ahp->net_type == RDMA_NETWORK_IPV4) {
		switch (chip_ver) {
		case CHELSIO_T7:
		default:
			t7req = (struct cpl_t7_act_open_req *)__skb_put(skb, wrlen);
			INIT_TP_WR(t7req, 0);
			req = (struct cpl_act_open_req *)t7req;
			break;
		}

		OPCODE_TID(req) = cpu_to_be32(
                       MK_OPCODE_TID(CPL_ACT_OPEN_REQ,
                       ((rss_qid<<14)|qhp->roce_attr.atid)));
		req->local_port = cpu_to_be16(qhp->wq.sq.qid >> 8);
		req->peer_port = cpu_to_be16((qhp->wq.sq.qid & 0xff) << 8);
		req->local_ip = la->sin_addr.s_addr;
		req->peer_ip = ra->sin_addr.s_addr;
		req->opt0 = cpu_to_be64(opt0);
		opt2 |= F_T5_OPT_2_VALID;
		t7req->params = cpu_to_be64(V_T7_FILTER_TUPLE(params));
		t7req->iss = cpu_to_be32(0);
		t7req->opt2 = cpu_to_be32(opt2);
		t7req->rsvd2 = 0;
		t7req->opt3 = 0;
		pr_debug("ahp 0x%llx sport %u dport %u smac %pM dmac %pM "
			 "dest_ip %pI4, src_ip %pI4\n", (unsigned long long)ahp,
			 req->local_port, req->peer_port, ahp->smac, ahp->dmac,
			 &req->peer_ip, &req->local_ip);

	} else {
		switch (chip_ver) {
		case CHELSIO_T7:
		default:
			t7req6 = (struct cpl_t7_act_open_req6 *) skb_put(skb,
			                wrlen);
			INIT_TP_WR(t7req6, 0);
			req6 = (struct cpl_act_open_req6 *)t7req6;
			break;
		}

		OPCODE_TID(req6) = cpu_to_be32(MK_OPCODE_TID(CPL_ACT_OPEN_REQ6,
                                       ((rss_qid<<14)|qhp->roce_attr.atid)));
		req6->local_port = cpu_to_be16(qhp->wq.sq.qid >> 8);
		req6->peer_port = cpu_to_be16((qhp->wq.sq.qid & 0xff) << 8);
		req6->local_ip_hi = *((__be64 *)(la6->sin6_addr.s6_addr));
		req6->local_ip_lo = *((__be64 *)(la6->sin6_addr.s6_addr + 8));
		req6->peer_ip_hi = *((__be64 *)(ra6->sin6_addr.s6_addr));
		req6->peer_ip_lo = *((__be64 *)(ra6->sin6_addr.s6_addr + 8));
		req6->opt0 = cpu_to_be64(opt0);

		opt2 |= F_T5_OPT_2_VALID;
		t7req6->params = cpu_to_be64(V_T7_FILTER_TUPLE(params));
		t7req6->iss = cpu_to_be32(0);
		t7req6->opt2 = cpu_to_be32(opt2);
		t7req6->rsvd2 = 0;
		t7req6->opt3 = 0;
	}
	set_bit(ROCE_ACT_OPEN_REQ, &qhp->history);
	chrd_ref_send_wait(&qhp->rhp->rdev, skb, qhp->wr_waitp, 0, qhp->wq.sq.qid, __func__);

	return ret;
}

static int rdma_roce_init(struct chrd_dev *rhp, struct chrd_qp *qhp)
{
	struct fw_ri_immd *immdp;
	struct fw_ri_wr *wqe;
	struct chrd_ah *ahp;
	struct sk_buff *skb;
	int rc_wrlen = 0;
	int ret, wrlen;
	int ipsechdr_len = 0;
	u32 tid;

	ahp = &qhp->roce_attr.roce_ah;
	if (qhp->qp_type == IB_QPT_GSI) {
		tid = qhp->roce_attr.gsi_ftid;
	} else if (qhp->qp_type == IB_QPT_RC) {
		tid = qhp->roce_attr.hwtid;
	} else {
		pr_err("Unsupported QP type!!!!!!\n");
		BUG_ON(1);
	}

	if (ahp->xfrm.ipsec_en) {
		ipsechdr_len = ESP_HDR_LEN;
		if (ahp->xfrm.ipsec_mode == XFRM_MODE_TUNNEL)
			ipsechdr_len += (ahp->xfrm.ipv6 ? sizeof(struct ipv6hdr) :
				sizeof(struct iphdr));
	}

	if (ahp->insert_vlan_tag)
		rc_wrlen = sizeof(struct vlan_ethhdr) +
			   (ahp->net_type == RDMA_NETWORK_IPV4 ? sizeof(struct iphdr) :
			    sizeof(struct ipv6hdr)) + sizeof(struct udphdr) + 12 + ipsechdr_len;
	else
		rc_wrlen = sizeof(struct ethhdr) +
			   (ahp->net_type == RDMA_NETWORK_IPV4 ? sizeof(struct iphdr) :
			    sizeof(struct ipv6hdr)) + sizeof(struct udphdr) + 12 + ipsechdr_len;
	if (qhp->qp_type == IB_QPT_GSI)
		wrlen = sizeof *wqe;
	else
		wrlen = sizeof *wqe + roundup(sizeof(struct fw_ri_immd) +
			rc_wrlen, 16);

	pr_debug("qhp 0x%llx qid 0x%x tid %d wrlen %d wqesz %lu rimmsz %lu\n",
		 (unsigned long long)qhp, qhp->wq.sq.qid, tid, wrlen,
		 sizeof(*wqe), sizeof(struct fw_ri_immd));

	if (wrlen%16)
		roundup(wrlen, 16);

	skb = alloc_skb(wrlen, GFP_KERNEL | __GFP_NOFAIL);
	if (!skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = alloc_ird(rhp, qhp->attr.max_ird);
	if (ret) {
		qhp->attr.max_ird = 0;
		kfree_skb(skb);
		goto out;
	}
	set_wr_txq(skb, CPL_PRIORITY_DATA, qhp->txq_id);

	wqe = (struct fw_ri_wr *)__skb_put(skb, wrlen);
	memset(wqe, 0, wrlen);
	if ((qhp->qp_type == IB_QPT_GSI) || (qhp->qp_type == IB_QPT_UD))
		wqe->op_compl = cpu_to_be32(V_FW_WR_OP(FW_RI_WR) |
			F_FW_WR_COMPL |
			V_FW_RI_WR_TRANSPORT_TYPE(FW_QP_TRANSPORT_TYPE_ROCEV2_UD));
	else
		wqe->op_compl = cpu_to_be32(V_FW_WR_OP(FW_RI_WR) |
			F_FW_WR_COMPL |
			V_FW_RI_WR_TRANSPORT_TYPE(FW_QP_TRANSPORT_TYPE_ROCEV2_RC));
	wqe->flowid_len16 = cpu_to_be32(
		V_FW_WR_FLOWID(tid) |
		V_FW_WR_LEN16(DIV_ROUND_UP(wrlen, 16)));
	wqe->cookie = (uintptr_t)qhp->wr_waitp;

	wqe->u.rocev2_init.type = FW_RI_TYPE_INIT;

	wqe->u.rocev2_init.qp_caps = FW_RI_QP_RDMA_READ_ENABLE |
			    FW_RI_QP_RDMA_WRITE_ENABLE |
			    FW_RI_QP_BIND_ENABLE;
	if (!qhp->ibqp.uobject)
		wqe->u.rocev2_init.qp_caps |= FW_RI_QP_FAST_REGISTER_ENABLE |
				     FW_RI_QP_STAG0_ENABLE;
	wqe->u.rocev2_init.nrqe = cpu_to_be16(t4_rqes_posted(&qhp->wq));
	wqe->u.rocev2_init.pdid = cpu_to_be32(qhp->attr.pd);
	wqe->u.rocev2_init.qpid = cpu_to_be32(qhp->wq.sq.qid);
	wqe->u.rocev2_init.sq_eqid = cpu_to_be32(qhp->wq.sq.qid);
	if (qhp->srq)
		wqe->u.rocev2_init.rq_eqid = cpu_to_be32(FW_RI_INIT_RQEQID_SRQ |
						  qhp->srq->idx);
	else {
		wqe->u.rocev2_init.rq_eqid = cpu_to_be32(qhp->wq.rq.qid);
		wqe->u.rocev2_init.hwrqsize = cpu_to_be32(qhp->wq.rq.rqt_size);
		wqe->u.rocev2_init.hwrqaddr = cpu_to_be32(qhp->wq.rq.rqt_hwaddr -
						   rhp->rdev.lldi.vr->rq.start);
	}
	wqe->u.rocev2_init.scqid = cpu_to_be32(qhp->attr.scq);
	wqe->u.rocev2_init.rcqid = cpu_to_be32(qhp->attr.rcq);
	wqe->u.rocev2_init.ord_max = cpu_to_be32(qhp->attr.max_ord);
	wqe->u.rocev2_init.ird_max = cpu_to_be32(qhp->attr.max_ird);
	wqe->u.rocev2_init.psn_pkd = cpu_to_be32(qhp->roce_attr.gsi_attr.psn_nxt);
	wqe->u.rocev2_init.epsn_pkd = cpu_to_be32(qhp->roce_attr.gsi_attr.epsn);
	wqe->u.rocev2_init.q_key = cpu_to_be32(0x80010000);
	wqe->u.rocev2_init.p_key = cpu_to_be16(0xFFFF);
	wqe->u.rocev2_init.r = 0;

	pr_debug("ird %u ord %u psn_pkd %u epsn_pkd %u\n", qhp->attr.max_ord,
		 qhp->attr.max_ird, qhp->roce_attr.gsi_attr.psn_nxt,
		 qhp->roce_attr.gsi_attr.epsn);
	if (unlikely(qhp->qp_type == IB_QPT_GSI)) {
		wqe->u.rocev2_init.pkthdrsize = 0;
	} else {
		const struct ib_gid_attr *sgid_attr;
		const struct ib_global_route *grh;
		struct ib_ud_header ud_hdr = {0};
		int hdr_len = 0;
		u8 *ud_hdrp;

		grh = rdma_ah_read_grh(&ahp->attr);
		sgid_attr = grh->sgid_attr;

		immdp = (struct fw_ri_immd *)(wqe->u.rocev2_init.tnl_lso +
					      sizeof(struct cpl_tx_tnl_lso) +
					      sizeof(struct cpl_tx_pkt_core));
		ud_hdrp = wqe->u.rocev2_init.tnl_lso +
			  sizeof(struct cpl_tx_tnl_lso) +
			  sizeof(struct cpl_tx_pkt_core) +
			  sizeof(struct fw_ri_immd);

		/* build headers here  */
		ret = ib_ud_header_init(0, false, true, ahp->insert_vlan_tag,
					(ahp->net_type == RDMA_NETWORK_IPV4 ? false : true),
					(ahp->net_type == RDMA_NETWORK_IPV4 ? 4 : 6), true, 0, &ud_hdr);
		if (ret)
			return ret;

		/* ETH + vlan header */
		ether_addr_copy(ud_hdr.eth.dmac_h, ahp->dmac);
		ether_addr_copy(ud_hdr.eth.smac_h, ahp->smac);
		if (ahp->insert_vlan_tag) {
			ud_hdr.eth.type = htons(ETH_P_8021Q);
			ud_hdr.vlan.tag = htons(ahp->vlan_id);
			ud_hdr.vlan.type = (ahp->net_type == RDMA_NETWORK_IPV4 ? htons(ETH_P_IP) :
					    htons(ETH_P_IPV6));
		} else {
			ud_hdr.eth.type = (ahp->net_type == RDMA_NETWORK_IPV4 ? htons(ETH_P_IP) :
					   htons(ETH_P_IPV6));
		}
		if (ahp->net_type == RDMA_NETWORK_IPV4) {
			/* IP header */
			ud_hdr.ip4.frag_off = htons(IP_DF);
			ud_hdr.ip4.protocol = IPPROTO_UDP;
			ud_hdr.ip4.tos = htonl(grh->flow_label);
			ud_hdr.ip4.ttl = grh->hop_limit;
			ud_hdr.ip4.tot_len = 0;
			memcpy(&ud_hdr.ip4.daddr, &ahp->dest_ip_addr[3], 4);
			memcpy(&ud_hdr.ip4.saddr, &ahp->local_ip_addr[3], 4);
			ud_hdr.ip4.check = ~ib_ud_ip4_csum(&ud_hdr);
			ud_hdr.grh_present = 0;
		} else {
			/* IPv6 header*/
			ud_hdr.grh_present = 1;
			ud_hdr.grh.flow_label = htonl(grh->flow_label);
			ud_hdr.grh.payload_length = 0;
			ud_hdr.grh.next_header = IPPROTO_UDP;
			ud_hdr.grh.hop_limit = grh->hop_limit;
			ud_hdr.grh.traffic_class = grh->traffic_class;
			memcpy(&ud_hdr.grh.destination_gid, &ahp->dest_ip_addr[0], sizeof(struct in6_addr));
			memcpy(&ud_hdr.grh.source_gid, &ahp->local_ip_addr[0], sizeof(struct in6_addr));
		}

		/* UDP header */
		ud_hdr.udp.sport = cpu_to_be16(ahp->src_port);
		ud_hdr.udp.dport = cpu_to_be16(ahp->dst_port);

		/* BTH header */
		ud_hdr.bth.pkey = cpu_to_be16(0xFFFF);
		ud_hdr.bth.destination_qpn = cpu_to_be32(ahp->dest_qp);
		hdr_len = ib_ud_header_pack(&ud_hdr, ud_hdrp);

		if (ahp->xfrm.ipsec_en)
			hdr_len = add_ipsec_header(ahp, ud_hdrp, hdr_len, ahp->insert_vlan_tag);

		wqe->u.rocev2_init.pkthdrsize = roundup(hdr_len - 8, 16);
		immdp->op = FW_RI_DATA_IMMD;
		immdp->r1 = 0;
		immdp->r2 = 0;
		immdp->immdlen = cpu_to_be32(hdr_len - 8);

		roce_fill_tnl_lso(qhp,
				  (struct cpl_tx_tnl_lso *)wqe->u.rocev2_init.tnl_lso,
				  0, hdr_len - 8, ahp->insert_vlan_tag,
				  (ahp->net_type == RDMA_NETWORK_IPV4 ? false : true), &ahp->xfrm);

		/* Init WR has 16B word boundary.may need to initialize last 
			10B(64 - 54) with 0 */
		cxgb4_uld_tid_insert(qhp->netdev, ahp->sgid_addr.saddr_in.sin_family, tid, qhp);
	}
	set_bit(ROCE_RDMA_INIT, &qhp->history);
	if (unlikely((qhp->qp_type == IB_QPT_GSI) || (qhp->qp_type == IB_QPT_UD))) {
		ret = chrd_ref_send_wait(&rhp->rdev, skb, qhp->wr_waitp,
					 qhp->roce_attr.gsi_ftid,
					 qhp->wq.sq.qid, __func__);
	} else {
		ret = chrd_ref_send_wait(&rhp->rdev, skb, qhp->wr_waitp,
					 qhp->roce_attr.hwtid,
					 qhp->wq.sq.qid, __func__);
	}

	if (!ret)
		goto out;

	free_ird(rhp, qhp->attr.max_ird);
out:
	pr_debug("ret %d\n", ret);
	return ret;
}

static int chrd_modify_roce_qp(struct chrd_qp *qhp, int attr_mask,
			       struct ib_qp_attr *attr, int internal)
{
	struct chrd_roce_qp_attributes new_roce_attr = qhp->roce_attr;
	struct chrd_common_qp_attributes newattr = qhp->attr;
	struct chrd_common_qp_attributes attrs;
	const struct ib_gid_attr *sgid_attr;
	struct ib_qp *ibqp = &qhp->ibqp;
	struct chrd_dev *rhp = qhp->rhp;
	enum chrd_qp_attr_mask mask = 0;
	enum ib_qp_state cur_state;
	enum ib_qp_state new_state;
	struct chrd_ah *ahp;
	int abort = 0;
	int free = 0;
	int ret = 0;
	u16 vlan_id;

	memset(&attrs, 0, sizeof attrs);
	cur_state = attr_mask & IB_QP_CUR_STATE ? attr->cur_qp_state : qhp->attr.state;
	new_state = attr_mask & IB_QP_STATE ? attr->qp_state : cur_state;

	attrs.next_state = chrd_convert_v2_state(attr->qp_state);
	attrs.enable_rdma_read = (attr->qp_access_flags &
			       IB_ACCESS_REMOTE_READ) ?  1 : 0;
	attrs.enable_rdma_write = (attr->qp_access_flags &
				IB_ACCESS_REMOTE_WRITE) ? 1 : 0;
	attrs.enable_bind = (attr->qp_access_flags & IB_ACCESS_MW_BIND) ? 1 : 0;

	mask |= (attr_mask & IB_QP_STATE) ? CHRD_QP_ATTR_NEXT_STATE : 0;
	mask |= (attr_mask & IB_QP_ACCESS_FLAGS) ?
			(CHRD_QP_ATTR_ENABLE_RDMA_READ |
			 CHRD_QP_ATTR_ENABLE_RDMA_WRITE |
			 CHRD_QP_ATTR_ENABLE_RDMA_BIND) : 0;

	pr_debug("qhp 0x%llx roce_attr 0x%llx new_roce_attr 0x%llx ahp 0x%llx sqid 0x%x rqid 0x%x"
		 " mask 0x%X state %d -> %d, attr_mask 0x%X %d > %d\n",
		 (unsigned long long)qhp, (unsigned long long)&qhp->roce_attr,
		 (unsigned long long)&new_roce_attr, (unsigned long long)&qhp->roce_attr.roce_ah,
		 qhp->wq.sq.qid, qhp->wq.rq.qid, mask, qhp->attr.state,
		 (mask & CHRD_QP_ATTR_NEXT_STATE) ? attrs.next_state : -1, attr_mask, cur_state,
		 new_state);
	if (!ib_modify_qp_is_ok(cur_state, new_state,
				qhp->ibqp.qp_type, attr_mask)) {
		pr_err("%s Invalid modify QP parameters\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&qhp->mutex);

	/* Process attr changes if in IDLE */
	if (mask & CHRD_QP_ATTR_VALID_MODIFY) {
		if (attr_mask & IB_QP_STATE && qhp->attr.state != CHRD_QP_V2_STATE_RESET) {
			pr_debug("check here!\n");
		//      ret = -EIO;								/*Todo: Check the Commented Code*/
		//      goto out;
		}
		if (mask & CHRD_QP_ATTR_ENABLE_RDMA_READ)
			newattr.enable_rdma_read = attrs.enable_rdma_read;
		if (mask & CHRD_QP_ATTR_ENABLE_RDMA_WRITE)
			newattr.enable_rdma_write = attrs.enable_rdma_write;
		if (mask & CHRD_QP_ATTR_ENABLE_RDMA_BIND)
			newattr.enable_bind = attrs.enable_bind;
		if (mask & CHRD_QP_ATTR_MAX_ORD) {
			if (attrs.max_ord > chrd_max_read_depth) {
				ret = -EINVAL;
				goto out;
			}
			newattr.max_ord = attrs.max_ord;
		}
		if (mask & CHRD_QP_ATTR_MAX_IRD) {
			if (attrs.max_ird > cur_max_read_depth(rhp)) {
				ret = -EINVAL;
				goto out;
			}
			newattr.max_ird = attrs.max_ird;
		}
		qhp->attr = newattr;
	}

	if (attr_mask & ~IB_QP_ATTR_STANDARD_BITS) {
		return -EOPNOTSUPP;
		goto out;
	}
	if (attr_mask & IB_QP_PKEY_INDEX) {
		new_roce_attr.roce_ah.p_key = attr->pkey_index;
		pr_debug("pkey_index %u\n", attr->pkey_index);
	}
	if (attr_mask & IB_QP_DEST_QPN) {
		new_roce_attr.roce_ah.dest_qp = attr->dest_qp_num;
		pr_debug("attr->dest_qp_num %u\n", attr->dest_qp_num);
	}
	if (attr_mask & IB_QP_QKEY) {
		new_roce_attr.q_key = attr->qkey;
		pr_debug("attr->qkey %u\n", attr->qkey);
	}
	if (attr_mask & IB_QP_PATH_MTU) {
		new_roce_attr.gsi_attr.snd_mss = ib_mtu_enum_to_int(attr->path_mtu);
		pr_debug("snd_mss %u path_mtu %u\n", new_roce_attr.gsi_attr.snd_mss, attr->path_mtu);
	}
	if (attr_mask & IB_QP_SQ_PSN) {
		new_roce_attr.gsi_attr.psn_nxt = attr->sq_psn & CHRD_ROCE_PSN_MASK;
		new_roce_attr.gsi_attr.lsn =  0xffff;
		new_roce_attr.gsi_attr.psn_una = attr->sq_psn & CHRD_ROCE_PSN_MASK;
		new_roce_attr.gsi_attr.psn_max = attr->sq_psn & CHRD_ROCE_PSN_MASK;
		pr_debug("attr->sq_psn %u new_roce_attr.gsi_attr.psn_nxt %u \n",
			 attr->sq_psn, new_roce_attr.gsi_attr.psn_nxt);
	}
	if (attr_mask & IB_QP_RQ_PSN) {
		new_roce_attr.gsi_attr.epsn = attr->rq_psn & CHRD_ROCE_PSN_MASK;
		pr_debug("attr->rq_psn %u\n", attr->rq_psn);
	}
	if (attr_mask & IB_QP_RNR_RETRY) {
		new_roce_attr.gsi_attr.rnr_nak_thresh = attr->rnr_retry;
		pr_debug("attr->attr->rnr_retry %u\n", attr->rnr_retry);
	}
	if (attr_mask & IB_QP_RETRY_CNT) {
		new_roce_attr.gsi_attr.rexmit_thresh = attr->retry_cnt;
		pr_debug("attr->retry_cnt %u\n", attr->retry_cnt);
	}
	if (attr_mask & IB_QP_AV) {
		ahp = &new_roce_attr.roce_ah;
		pr_debug("Mask AV qhp 0x%llx roce_attr 0x%llx ahp 0x%llx\n",
			 (unsigned long long)qhp, (unsigned long long)&qhp->roce_attr,
			 (unsigned long long)ahp);
		vlan_id = VLAN_N_VID;
		ahp->attr = attr->ah_attr;
		ahp->dst_port = CHRD_ROCE_PORT;

		if (attr->ah_attr.ah_flags & IB_AH_GRH) {
			new_roce_attr.gsi_attr.ttl = attr->ah_attr.grh.hop_limit;
			new_roce_attr.gsi_attr.flow_label = attr->ah_attr.grh.flow_label;
			new_roce_attr.gsi_attr.tos = attr->ah_attr.grh.traffic_class;
			ahp->src_port = rdma_get_udp_sport(new_roce_attr.gsi_attr.flow_label,
						   ibqp->qp_num, ahp->dest_qp);
			pr_debug("NA for v2, GRH set, src_port %u dst_port %u\n",
				 ahp->src_port, ahp->dst_port);
		} else {
			ahp->src_port = 0xd000;
			pr_debug("GRH not set, src_port %u dst_port %u\n",
				 ahp->src_port, ahp->dst_port);
		}

		sgid_attr = attr->ah_attr.grh.sgid_attr;
		ahp->net_type = rdma_gid_attr_network_type(sgid_attr);
		memcpy(ahp->dmac, attr->ah_attr.roce.dmac, ETH_ALEN);
		ret = rdma_read_gid_l2_fields(sgid_attr, &vlan_id, ahp->smac);
		if (ret)
			return ret;
		pr_debug("smac %pM dmac %pM\n", ahp->smac, ahp->dmac);

		if (vlan_id < VLAN_N_VID) {
			new_roce_attr.roce_ah.insert_vlan_tag = true;
			new_roce_attr.roce_ah.vlan_id = vlan_id;
		} else {
			new_roce_attr.roce_ah.insert_vlan_tag = false;
		}

		rdma_gid2ip((struct sockaddr *)&ahp->sgid_addr, &sgid_attr->gid);
		rdma_gid2ip((struct sockaddr *)&ahp->dgid_addr, &attr->ah_attr.grh.dgid);
		if (ahp->net_type == RDMA_NETWORK_IPV6) {
			__be32 *daddr =
				ahp->dgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32;
			__be32 *saddr =
				ahp->sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32;

			memcpy(ahp->dest_ip_addr, daddr, sizeof(ahp->dest_ip_addr));
			memcpy(ahp->local_ip_addr, saddr, sizeof(ahp->local_ip_addr));

			ahp->ipv4 = false;

			ahp->dst = find_route6(rhp, (__u8 *)ahp->local_ip_addr,
					       (__u8 *)ahp->dest_ip_addr,
					       ahp->src_port, ahp->dst_port,
					       0, 0);

			pr_debug("ahp 0x%llx sport %u dport %u smac %pM dmac %pM"
				 " dest_ip %pI6, src_ip %pI6\n", (unsigned long long)ahp,
				 ahp->src_port, ahp->dst_port, ahp->smac, ahp->dmac,
				 &ahp->dest_ip_addr[0], &ahp->local_ip_addr[0]);

		} else if (ahp->net_type == RDMA_NETWORK_IPV4) {
			ahp->ipv4 = true;
			memset(ahp->dest_ip_addr, 0, sizeof(ahp->dest_ip_addr));
			memset(ahp->local_ip_addr, 0, sizeof(ahp->local_ip_addr));

			ahp->dest_ip_addr[3] = ahp->dgid_addr.saddr_in.sin_addr.s_addr;
			ahp->local_ip_addr[3] = ahp->sgid_addr.saddr_in.sin_addr.s_addr;

			ahp->dst = find_route(rhp, ahp->local_ip_addr[3], ahp->dest_ip_addr[3],
					      ahp->src_port, ahp->dst_port, 0);

			pr_debug("ahp 0x%llx sport %u dport %u smac %pM dmac %pM"
				 " dest_ip %pI4, src_ip %pI4\n", (unsigned long long)ahp,
				 ahp->src_port, ahp->dst_port, ahp->smac, ahp->dmac,
				 &ahp->dest_ip_addr[3], &ahp->local_ip_addr[3]);
		}
	}

	if (ahp->dst && !IS_ERR(ahp->dst)) {
		struct xfrm_state *x = ahp->dst->xfrm;

		ahp->xfrm.ipsec_en = false;
		if (x && x->xso.offload_handle) {
			ahp->xfrm.ipsecidx = cxgb4_uld_xfrm_ipsecidx_get(x);
			if (ahp->xfrm.ipsecidx && ahp->xfrm.ipsecidx != 0xffff) {
				ahp->xfrm.ipsec_en = true;
				ahp->xfrm.ipsec_mode = x->props.mode;
				ahp->xfrm.ipv6 = x->props.family == AF_INET6;

				if (ahp->xfrm.ipv6) {
					memcpy(ahp->xfrm.dest_ip_addr, x->id.daddr.a6,
					       sizeof(ahp->xfrm.dest_ip_addr));
					memcpy(ahp->xfrm.local_ip_addr, x->props.saddr.a6,
					       sizeof(ahp->xfrm.local_ip_addr));
				} else {
					ahp->xfrm.dest_ip_addr[3] = x->id.daddr.a4;
					ahp->xfrm.local_ip_addr[3] = x->props.saddr.a4;
				}
			} else
				pr_err("%s Invalid IPsec configuration\n", __func__);
		}
	}

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		if (attr->max_rd_atomic)
			new_roce_attr.ord_size = attr->max_rd_atomic;
	}

	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		if (attr->max_dest_rd_atomic)
			new_roce_attr.ird_size = attr->max_dest_rd_atomic;
	}
	qhp->roce_attr = new_roce_attr;

	if (!(mask & CHRD_QP_ATTR_NEXT_STATE))
		goto out;
	if (qhp->attr.state == attrs.next_state)
		goto out;

	if (!ib_modify_qp_is_ok(cur_state, new_state,
				qhp->ibqp.qp_type, attr_mask)) {
		pr_err("%s Invalid modify QP parameters\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	switch (qhp->attr.state) {
	case CHRD_QP_V2_STATE_RESET:
		switch (attrs.next_state) {
		case CHRD_QP_V2_STATE_IDLE:
			if (qhp->qp_type == IB_QPT_RC)
				qhp->netdev = rhp->rdev.lldi.ports[attr->port_num - 1];
			set_v2_state(qhp, CHRD_QP_V2_STATE_IDLE);
			break;
		default:
			pr_debug("check here!\n");
			ret = -EINVAL;
			goto out;
		}
		break;
	case CHRD_QP_V2_STATE_IDLE:
		switch (attrs.next_state) {
		case CHRD_QP_V2_STATE_IDLE:
			set_v2_state(qhp, CHRD_QP_V2_STATE_IDLE);
			break;
		case CHRD_QP_V2_STATE_RTR:
			set_v2_state(qhp, CHRD_QP_V2_STATE_RTR);
			break;
		case CHRD_QP_V2_STATE_RTS:
			set_v2_state(qhp, CHRD_QP_V2_STATE_RTS);
			break;
		case CHRD_QP_V2_STATE_ERROR:
			set_v2_state(qhp, CHRD_QP_V2_STATE_ERROR);
			flush_qp(qhp);
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	case CHRD_QP_V2_STATE_RTR:
		switch (attrs.next_state) {
		case CHRD_QP_V2_STATE_RTS:
			set_v2_state(qhp, CHRD_QP_V2_STATE_RTS);

			if (qhp->qp_type == IB_QPT_RC) {
				ret = roce_act_open_req(qhp);
				if (ret)
					goto err;
			}
			ret = send_roce_flowc(qhp);
			if (ret)
				goto err;
			ret = rdma_roce_init(rhp, qhp);
			if (ret)
				goto err;
			break;
		case CHRD_QP_V2_STATE_ERROR:
			set_v2_state(qhp, CHRD_QP_V2_STATE_ERROR);
			flush_qp(qhp);
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	case CHRD_QP_V2_STATE_RTS:
		switch (attrs.next_state) {
		case CHRD_QP_V2_STATE_CLOSING:
			t4_set_wq_in_error(&qhp->wq, 0);
			set_v2_state(qhp, CHRD_QP_V2_STATE_CLOSING);
			ret = rdma_roce_fini(rhp, qhp);
			if (ret)
				goto err;
			break;
		case CHRD_QP_V2_STATE_TERMINATE:
			t4_set_wq_in_error(&qhp->wq, 0);
			set_v2_state(qhp, CHRD_QP_V2_STATE_TERMINATE);
			break;
		case CHRD_QP_V2_STATE_ERROR:
			t4_set_wq_in_error(&qhp->wq, 0);
			set_v2_state(qhp, CHRD_QP_V2_STATE_ERROR);
			ret = rdma_roce_fini(rhp, qhp);
			flush_qp(qhp);
			if (ret)
				goto err;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	case CHRD_QP_V2_STATE_CLOSING:

		/*
		 * Allow kernel users to move to ERROR for qp draining.
		 */
		if (!internal && (qhp->ibqp.uobject || attrs.next_state !=
				  CHRD_QP_V2_STATE_ERROR)) {
			ret = -EINVAL;
			goto out;
		}
		switch (attrs.next_state) {
		case CHRD_QP_V2_STATE_IDLE:
			flush_qp(qhp);
			set_v2_state(qhp, CHRD_QP_V2_STATE_IDLE);
			wake_up(&qhp->wait);
			break;
		case CHRD_QP_V2_STATE_ERROR:
			goto err;
		default:
			ret = -EINVAL;
			goto err;
		}
		break;
	case CHRD_QP_V2_STATE_ERROR:
		if (attrs.next_state != CHRD_QP_V2_STATE_IDLE) {
			ret = -EINVAL;
			goto out;
		}
		if (!t4_sq_empty(&qhp->wq) || !t4_rq_empty(&qhp->wq)) {
			ret = -EINVAL;
			goto out;
		}
		set_v2_state(qhp, CHRD_QP_V2_STATE_IDLE);
		break;
	case CHRD_QP_V2_STATE_TERMINATE:
		if (!internal) {
			ret = -EINVAL;
			goto out;
		}
		goto err;
		break;
	default:
		pr_err("%s in a bad state %d\n", __func__, qhp->attr.state);
		ret = -EINVAL;
		goto err;
		break;
	}
	goto out;
err:
	set_v2_state(qhp, CHRD_QP_V2_STATE_ERROR);
	free = 1;
	abort = 1;
	flush_qp(qhp);
	wake_up(&qhp->wait);
out:
	mutex_unlock(&qhp->mutex);

	pr_debug("exit state %d ret %d\n", qhp->attr.state, ret);
	return ret;
}

static void destroy_raw_qp(struct ib_qp *ib_qp)
{
	struct cxgb4_uld_txq_info txq_info = { 0 };
	struct chrd_common_qp_attributes attrs;
	struct chrd_raw_qp *rqp;
	struct chrd_dev *rhp;

	rqp = to_chrd_raw_qp(ib_qp);
	rhp = rqp->rhp;

	pr_debug("qpid %d\n", ib_qp->qp_num);
	attrs.next_state = CHRD_QP_STATE_ERROR;
	modify_raw_qp(rqp, CHRD_QP_ATTR_NEXT_STATE, &attrs);

	if (!ib_qp->srq)
		xa_erase_irq(&rhp->rawiqs, rqp->iq.cntxt_id);
	xa_erase_irq(&rhp->rawqps, rqp->txq.cntxt_id);
	xa_erase_irq(&rhp->fids, rqp->fid);

	atomic_dec(&rqp->refcnt);
	wait_event(rqp->wait, !atomic_read(&rqp->refcnt));

	spin_lock_irq(&rhp->lock);
	if (!list_empty(&rqp->fcl.db_fc_entry)) {
		list_del_init(&rqp->fcl.db_fc_entry);
	}
	spin_unlock_irq(&rhp->lock);

	free_raw_txq(rhp, rqp);

	/*
	 * Stop rxq in order to start it draining.
	 */
	if (!ib_qp->srq)
		stop_raw_rxq(rhp, rqp);

	/*
	 * Delete the filter.
	 */
	put_fid(rqp);

	/*
	 * free the rxq.
	 */
	if (!ib_qp->srq)
		free_raw_rxq(rhp, rqp);

	txq_info.lld_index = rqp->txq_idx;
	cxgb4_uld_txq_free(rqp->netdev, CXGB4_ULD_TYPE_RDMA, &txq_info);
	return;
}

static void destroy_rc_qp(struct ib_qp *ib_qp)
{
	struct chrd_dev *rhp;
	struct chrd_qp *qhp;
	struct chrd_ucontext *ucontext;
	struct chrd_common_qp_attributes attrs;
	struct ib_qp_attr attr;
	struct cxgb4_uld_txq_info txq_info = { 0 };

	qhp = to_chrd_qp(ib_qp);
	rhp = qhp->rhp;
	ucontext = qhp->ucontext;

	pr_debug("qp %p qp_type %d\n", qhp, ib_qp->qp_type);
	if (rdma_protocol_roce(&rhp->ibdev, 1)) {
		if (qhp->attr.state != CHRD_QP_V2_STATE_ERROR) {
			attr.qp_state = IB_QPS_ERR;
			if (qhp->attr.state == CHRD_QP_V2_STATE_TERMINATE)
				chrd_modify_roce_qp(qhp, CHRD_QP_ATTR_NEXT_STATE, &attr, 1);
	 		else
				chrd_modify_roce_qp(qhp, CHRD_QP_ATTR_NEXT_STATE, &attr, 0);
		}
	} else {
		attrs.next_state = CHRD_QP_STATE_ERROR;
		if (qhp->attr.state == CHRD_QP_STATE_TERMINATE)
			chrd_modify_iw_rc_qp(qhp, CHRD_QP_ATTR_NEXT_STATE, &attrs, 1);
		else
			chrd_modify_iw_rc_qp(qhp, CHRD_QP_ATTR_NEXT_STATE, &attrs, 0);
	}
	wait_event(qhp->wait, !qhp->ep);

	xa_lock_irq(&rhp->qps);
	__xa_erase(&rhp->qps, qhp->wq.sq.qid);
	if (!list_empty(&qhp->fcl.db_fc_entry)) {
		list_del_init(&qhp->fcl.db_fc_entry);
	}
	xa_unlock_irq(&rhp->qps);
	
	free_ird(rhp, qhp->attr.max_ird);
	chrd_iw_qp_rem_ref(ib_qp);
	wait_for_completion(&qhp->qp_rel_comp);

	if (rdma_protocol_roce(&rhp->ibdev, 1)) {
		txq_info.lld_index  = qhp->txq_id;
		cxgb4_uld_txq_free(qhp->netdev, CXGB4_ULD_TYPE_RDMA,
				   &txq_info);
	}
	pr_debug("ib_qp 0x%llx qpid 0x%0x\n", (unsigned long long)ib_qp, qhp->wq.sq.qid);
	pr_debug("qhp 0x%llx ucontext %p\n", (unsigned long long)qhp, ucontext);

	free_rc_queues(&rhp->rdev, &qhp->wq, ucontext ?
		       &ucontext->uctx : &rhp->rdev.uctx, !qhp->srq);
	if (unlikely(qhp->qp_type == IB_QPT_GSI)) {
		del_filter((struct chrd_raw_qp *)qhp, qhp->roce_attr.gsi_ftid);
	}
	chrd_put_wr_wait(qhp->wr_waitp);

	return;
}

int chrd_destroy_qp(struct ib_qp *ib_qp, struct ib_udata *udata)
{
	pr_debug("qpid %d\n", ib_qp->qp_num);
	switch (ib_qp->qp_type) {
	case IB_QPT_RC:
	case IB_QPT_GSI:
	case IB_QPT_UD:
		destroy_rc_qp(ib_qp);
		break;
	case IB_QPT_RAW_ETH:
		destroy_raw_qp(ib_qp);
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", ib_qp->qp_type);
		break;
	}
	return 0;
}

static int chrd_validate_qp_attrs(struct chrd_dev *rhp,
				  struct ib_qp_init_attr *attrs,
				  struct ib_udata *udata)
{
	if (attrs->cap.max_inline_data > T4_MAX_SEND_INLINE)
		return -EINVAL;

	if (rdma_protocol_roce(&rhp->ibdev, 1)) {
		if (attrs->qp_type != IB_QPT_RC &&
			attrs->qp_type != IB_QPT_UD &&
			attrs->qp_type != IB_QPT_GSI)
			return -EOPNOTSUPP;
	} else {
			if (attrs->qp_type != IB_QPT_RC)
			return -EOPNOTSUPP;
	}

	if (!attrs->srq) {
		if (attrs->cap.max_recv_wr > rhp->rdev.hw_queue.t4_max_rq_size)
			return -E2BIG;
	}

	if (attrs->cap.max_send_wr > rhp->rdev.hw_queue.t4_max_sq_size)
		return -E2BIG;

	return 0;
}

# if 0
static int create_gsi_qp(struct chrd_pd *php, struct chrd_dev *rhp,
				  struct ib_qp_init_attr *attrs,
				  struct ib_udata *udata)
{
	struct ch_filter filt;
	struct filter_ctx ctx;

	qhp->rhp = rhp;
	qhp->qp_type = IB_QPT_GSI;
	qhp->qp_trans = IB_QPT_GSI;
	qhp->ibqp.qp_num = 1;
	qhp->attr.pd = php->pdid;
	qhp->attr.sq_num_entries = attrs->cap.max_send_wr;
	qhp->attr.sq_max_sges = attrs->cap.max_send_sge;
	qhp->attr.rq_num_entries = attrs->cap.max_recv_wr;
	qhp->attr.rq_max_sges = attrs->cap.max_recv_sge;
	qhp->attr.state = CHRD_QP_V2_STATE_RESET;
	qhp->attr.next_state = CHRD_QP_STATE_RESET;
	qhp->sq_sig_all = attrs->sq_sig_type == IB_SIGNAL_ALL_WR;

	spin_lock_init(&qhp->lock);
	mutex_init(&qhp->mutex);
	init_waitqueue_head(&qhp->wait);
	init_completion(&qhp->qp_rel_comp);
	refcount_set(&qhp->qp_refcnt, 1);

	/* ToDo: Allocate SQ and RQ SW queues */

	// Create ipv4 and ipv6 filters for RoCE port 4791
	memset(&filt, 0, sizeof filt);
	netdev = rhp->rdev.lldi.ports[0];
	//filt.filter_id = cxgb4_get_free_ftid(netdev, PF_INET, 0); /*set prio as 1 if you need hpf*/
	filt.filter_ver = CH_FILTER_SPECIFICATION_ID;
	// Todo: set vlan specific filt fields in case of vlan
	filt.fs.val.lport = CHRD_ROCE_PORT;
	filt.fs.mask.lport = -1;
	filt.fs.val.proto = IPPROTO_UDP;
	filt.fs.mask.proto = -1;
	filt.fs.action = FILTER_PASS;
	filt.fs.dirsteer = 1;
	//filt.fs.iq = rhp->rdev.lldi.rxq_ids[0];		/*Todo: Check the Commented Code */
	filt.fs.rpttid = 1;
	filt.fs.hitcnts = 1;
	filt.cmd = CHELSIO_SET_FILTER;

	init_completion(&ctx.completion);
	rtnl_lock();
	ret = cxgb4_uld_filter_create(netdev, CXGB4_FILTER_ID_ANY, &filt.fs,
				      &ctx, GFP_KERNEL);
	rtnl_unlock();
	if (ret >= 0) {
		filt.filter_id = ret;
		ret = wait_for_completion_timeout(&ctx.completion, 10*HZ);
		if (!ret) {
			printk("%s: filter creation timed out\n", __func__);
			goto free_rq;
		} else {
			ret = ctx.result;
		}
	}

	rhp->rdev.gsi_scq = get_chp(rhp, ((struct chrd_cq *)attrs->send_cq)->cq.cqid);
	rhp->rdev.gsi_rcq = get_chp(rhp, ((struct chrd_cq *)attrs->recv_cq)->cq.cqid);
	rhp->rdev.gsi_qp = qhp;
	rhp->rdev.gsi_qp_inuse = 1;
	rhp->rdev.gsi_scq->gsi_cq = 1;
	rhp->rdev.gsi_rcq->gsi_cq = 1;

	return &qhp->ibqp;
free_rq:
	kfree(wq->rq.sw_rq);
free_sq:
	kfree(wq->sq.sw_sq);
free_qhp:
	kfree(qhp);
	return ERR_PTR(ret);
}
#endif

static int create_gsi_filter(struct net_device *netdev, struct chrd_qp *qhp, u8 port_num)
{
	struct chrd_dev *rhp = qhp->rhp;
	struct ch_filter filt = qhp->gsi_filt;
	struct filter_ctx ctx;
	int ret = 0;

	memset(&filt, 0, sizeof filt);
	pr_debug("netdev 0x%llx\n", (unsigned long long)netdev);
	filt.filter_ver = CH_FILTER_SPECIFICATION_ID;
	filt.fs.val.lport = 0x0;
	filt.fs.mask.lport = -1;
	filt.fs.val.fport = 0x0100;	/*Todo: hardcoded value */
	filt.fs.mask.fport = -1;
	filt.fs.val.iport = port_num;
	filt.fs.mask.iport = -1;
	filt.fs.action = FILTER_PASS;
	filt.fs.dirsteer = 1;
	filt.fs.prio = 1;
	filt.fs.hitcnts = 1;
	filt.fs.val.roce = 1;
	filt.fs.mask.roce = -1;
	/* GSI QP number */
	filt.fs.val.rocev2_qpn = 1;
	filt.cmd = CHELSIO_SET_FILTER;
	filt.fs.type = 1;

	init_completion(&ctx.completion);
	rtnl_lock();
	ret = cxgb4_uld_filter_create(netdev, CXGB4_FILTER_ID_ANY, &filt.fs,
				      &ctx, GFP_KERNEL);
	rtnl_unlock();
	pr_debug("cxgb4_uld_filter_create() tid %d ret: %d\n", ctx.tid, ret);
	if (ret >= 0) {
		filt.filter_id = ret;
		pr_debug("NON HPF cxgb4_get_free_ftid: %d\n", filt.filter_id);
		ret = wait_for_completion_timeout(&ctx.completion, 10*HZ);
		if (!ret) {
			pr_err("%s: filter creation timed out\n", __func__);
		}
	}

	qhp->roce_attr.gsi_ftid = filt.filter_id;
	rhp->rdev.gsi_qp_inuse = 1;
	rhp->rdev.gsi_qp = qhp;

	return ret;
}

static int create_rc_qp(struct ib_qp *qp, struct ib_qp_init_attr *attrs,
			 struct ib_udata *udata)
{
	struct chrd_create_qp_resp uresp = {0};
	struct chrd_ucontext *ucontext;
	struct ib_pd *pd = qp->pd;
	struct chrd_dev *rhp;
	struct chrd_qp *qhp = to_chrd_qp(qp);
	struct chrd_pd *php;
	struct chrd_cq *schp;
	struct chrd_cq *rchp;
	int sqsize, rqsize = 0;
	int ret = 0;
	struct chrd_mm_entry *sq_key_mm, *rq_key_mm = NULL, *sq_db_key_mm;
	struct chrd_mm_entry *rq_db_key_mm = NULL, *ma_sync_key_mm = NULL;
	struct resource *res;

	ucontext = rdma_udata_to_drv_context(udata, struct chrd_ucontext,
					     ibucontext);
	php = to_chrd_pd(pd);
	rhp = php->rhp;

	res = cxgb4_bar_resource(rhp->rdev.lldi.ports[0], 0);
	if (!res)
		return -EOPNOTSUPP;

	schp = get_chp(rhp, ((struct chrd_cq *)attrs->send_cq)->cq.cqid);
	rchp = get_chp(rhp, ((struct chrd_cq *)attrs->recv_cq)->cq.cqid);
	if (!schp || !rchp)
		return -EINVAL;

	ret = chrd_validate_qp_attrs(rhp, attrs, udata);
	if (ret)
		return ret;
	/* 
	 * Temporary workaround for iSER. iSER needs relatively large SQ for iw_cxgb4.
	 * Therefore we factor max_send_wr with 3 based on unique SQ size of iSER
	 */
	if (!ucontext && (attrs->cap.max_send_wr == ISER_SQ_SIZE))
		sqsize = min_t(int, 3 * attrs->cap.max_send_wr + 1,
			     rhp->rdev.hw_queue.t4_max_sq_size);
	else
		sqsize = attrs->cap.max_send_wr + 1;

	if (sqsize < 8)
		sqsize = 8;
	if (!attrs->srq) {
		rqsize = attrs->cap.max_recv_wr + 1;
		if (rqsize < 8)
			rqsize = 8;
	}

	qhp->wr_waitp = chrd_alloc_wr_wait(GFP_KERNEL);
	if (!qhp->wr_waitp)
		return -ENOMEM;

	qhp->wq.sq.size = sqsize;
	qhp->wq.sq.memsize =
		(sqsize + rhp->rdev.hw_queue.t4_eq_status_entries) *
		sizeof *qhp->wq.sq.queue + 16*sizeof(__be64);
	qhp->wq.sq.flush_cidx = -1;
	if (!attrs->srq) {
		qhp->wq.rq.size = rqsize;
		qhp->wq.rq.memsize =
			(rqsize + rhp->rdev.hw_queue.t4_eq_status_entries) *
			sizeof *qhp->wq.rq.queue;
	}
	if (ucontext) {
		qhp->wq.sq.memsize = roundup(qhp->wq.sq.memsize, PAGE_SIZE);
		if (!attrs->srq)
			qhp->wq.rq.memsize = roundup(qhp->wq.rq.memsize, PAGE_SIZE);
	}

	if (rdma_protocol_roce(&rhp->ibdev, 1)) {
		qhp->qp_trans = CHRD_TRANSPORT_ROCEV2;
		/*
		 * Todo: Other Vendors follow PF per port design, so they always
		 * have one port per device, However, we follow PF per adapter. 
		 * Need to figure out how to pass port num from user space.
		 */
		if (udata)
			qhp->netdev = rhp->rdev.lldi.ports[0];
		else
			qhp->netdev = rhp->rdev.lldi.ports[attrs->port_num - 1];
		qhp->mtu = ib_mtu_enum_to_int(ib_mtu_int_to_enum(qhp->netdev->mtu));
	} else {
		qhp->qp_trans = CHRD_TRANSPORT_IWARP;
	}
	qhp->qp_type = attrs->qp_type;

	ret = alloc_rc_queues(rhp, qhp, &schp->cq, &rchp->cq,
			      ucontext ? &ucontext->uctx : &rhp->rdev.uctx,
			      !attrs->srq);
	if (ret)
		goto err_free_wr_wait;

	attrs->cap.max_recv_wr = rqsize - 1;
	attrs->cap.max_send_wr = sqsize - 1;
	attrs->cap.max_inline_data = T4_MAX_SEND_INLINE;

	qhp->rhp = rhp;
	qhp->attr.pd = php->pdid;
	qhp->attr.scq = ((struct chrd_cq *) attrs->send_cq)->cq.cqid;
	qhp->attr.rcq = ((struct chrd_cq *) attrs->recv_cq)->cq.cqid;
	qhp->attr.sq_num_entries = attrs->cap.max_send_wr;
	qhp->attr.sq_max_sges = attrs->cap.max_send_sge;
	qhp->attr.sq_max_sges_rdma_write = attrs->cap.max_send_sge;
	if (!attrs->srq) {
		qhp->attr.rq_num_entries = attrs->cap.max_recv_wr;
		qhp->attr.rq_max_sges = attrs->cap.max_recv_sge;
	}
	if (rdma_protocol_roce(&rhp->ibdev, 1)) {
		qhp->attr.state = CHRD_QP_V2_STATE_RESET;
		qhp->attr.next_state = CHRD_QP_V2_STATE_RESET;
	} else {
		qhp->attr.state = CHRD_QP_STATE_IDLE;
		qhp->attr.next_state = CHRD_QP_STATE_IDLE;
	}
	qhp->attr.enable_rdma_read = 1;
	qhp->attr.enable_rdma_write = 1;
	qhp->attr.enable_bind = 1;
	qhp->attr.max_ord = 0;
	qhp->attr.max_ird = 0;
	qhp->sq_sig_all = attrs->sq_sig_type == IB_SIGNAL_ALL_WR;
	spin_lock_init(&qhp->lock);
	mutex_init(&qhp->mutex);
	init_waitqueue_head(&qhp->wait);
	init_completion(&qhp->qp_rel_comp);
	refcount_set(&qhp->qp_refcnt, 1);

	ret = xa_insert_irq(&rhp->qps, qhp->wq.sq.qid, qhp, GFP_KERNEL);
	if (ret)
		goto err_destroy_qp;

	if (udata) {
		sq_key_mm = kmalloc(sizeof *sq_key_mm, GFP_KERNEL);
		if (!sq_key_mm) {
			ret = -ENOMEM;
			goto err_remove_handle;
		}
		if (!attrs->srq) {
			rq_key_mm = kmalloc(sizeof *rq_key_mm, GFP_KERNEL);
			if (!rq_key_mm) {
				ret = -ENOMEM;
				goto err_free_sq_key;
			}
		}
		sq_db_key_mm = kmalloc(sizeof *sq_db_key_mm, GFP_KERNEL);
		if (!sq_db_key_mm) {
			ret = -ENOMEM;
			goto err_free_rq_key;
		}
		if (!attrs->srq) {
			rq_db_key_mm = kmalloc(sizeof *rq_db_key_mm, GFP_KERNEL);
			if (!rq_db_key_mm) {
				ret = -ENOMEM;
				goto err_free_sq_db_key;
			}
		}
		if (t4_sq_onchip(&qhp->wq.sq)) {
			ma_sync_key_mm = kmalloc(sizeof *ma_sync_key_mm,
						 GFP_KERNEL);
			if (!ma_sync_key_mm) {
				ret = -ENOMEM;
				goto err_free_rq_db_key;
			}
			uresp.flags = CHRD_QPF_ONCHIP;
		} else
			uresp.flags = 0;
		if (rhp->rdev.lldi.write_w_imm_support)
			uresp.flags |= CHRD_QPF_WRITE_W_IMM;
		uresp.qid_mask = rhp->rdev.rdma_res->qpmask;
		uresp.sqid = qhp->wq.sq.qid;
		uresp.sq_size = qhp->wq.sq.size;
		uresp.sq_memsize = qhp->wq.sq.memsize;
		if (!attrs->srq) {
			uresp.rqid = qhp->wq.rq.qid;
			uresp.rq_size = qhp->wq.rq.size;
			uresp.rq_memsize = qhp->wq.rq.memsize;
		}
		spin_lock(&ucontext->mmap_lock);
		if (ma_sync_key_mm) {
			uresp.ma_sync_key = ucontext->key;
			ucontext->key += PAGE_SIZE;
		}
		uresp.sq_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		if (!attrs->srq) {
			uresp.rq_key = ucontext->key;
			ucontext->key += PAGE_SIZE;
		}
		uresp.sq_db_gts_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		if (!attrs->srq) {
			uresp.rq_db_gts_key = ucontext->key;
			ucontext->key += PAGE_SIZE;
		}
		spin_unlock(&ucontext->mmap_lock);
		ret = ib_copy_to_udata(udata, &uresp, sizeof uresp);
		if (ret)
			goto err_free_ma_sync_key;
		sq_key_mm->key = uresp.sq_key;
		sq_key_mm->addr = qhp->wq.sq.phys_addr;
		sq_key_mm->vaddr = qhp->wq.sq.queue;
		sq_key_mm->dma_addr = qhp->wq.sq.dma_addr;
		sq_key_mm->len = PAGE_ALIGN(qhp->wq.sq.memsize);
		insert_mmap(ucontext, sq_key_mm);
		if (!attrs->srq) {
			rq_key_mm->key = uresp.rq_key;
			rq_key_mm->addr = virt_to_phys(qhp->wq.rq.queue);
			rq_key_mm->vaddr = qhp->wq.rq.queue;
			rq_key_mm->dma_addr = qhp->wq.rq.dma_addr;
			rq_key_mm->len = PAGE_ALIGN(qhp->wq.rq.memsize);
			insert_mmap(ucontext, rq_key_mm);
		}
		sq_db_key_mm->key = uresp.sq_db_gts_key;
		sq_db_key_mm->addr = (u64)(unsigned long)qhp->wq.sq.bar2_pa;
		sq_db_key_mm->vaddr = NULL;
		sq_db_key_mm->dma_addr = 0;
		sq_db_key_mm->len = PAGE_SIZE;
		insert_mmap(ucontext, sq_db_key_mm);
		if (!attrs->srq) {
			rq_db_key_mm->key = uresp.rq_db_gts_key;
			rq_db_key_mm->addr = (u64)(unsigned long)qhp->wq.rq.bar2_pa;
			rq_db_key_mm->len = PAGE_SIZE;
			rq_db_key_mm->vaddr = NULL;
			rq_db_key_mm->dma_addr = 0;
			insert_mmap(ucontext, rq_db_key_mm);
		}
		if (ma_sync_key_mm) {
			ma_sync_key_mm->key = uresp.ma_sync_key;
			ma_sync_key_mm->addr =
			       	(res->start + A_PCIE_MA_SYNC) & PAGE_MASK;
			ma_sync_key_mm->len = PAGE_SIZE;
			ma_sync_key_mm->vaddr = NULL;
			ma_sync_key_mm->dma_addr = 0;
			insert_mmap(ucontext, ma_sync_key_mm);
		}

		qhp->ucontext = ucontext;
	}
	if (!attrs->srq)
		qhp->wq.qp_errp = &qhp->wq.rq.queue[qhp->wq.rq.size].status.qp_err;
	else {
		qhp->wq.qp_errp = &qhp->wq.sq.queue[qhp->wq.sq.size].status.qp_err;
		qhp->wq.srqidxp = &qhp->wq.sq.queue[qhp->wq.sq.size].status.srqidx;
	}

	qhp->ibqp.qp_num = qhp->wq.sq.qid;
	if (unlikely(qhp->qp_type == IB_QPT_GSI)) {
		ret = create_gsi_filter(qhp->netdev, qhp, attrs->port_num - 1);
	}

	if (attrs->srq)
		qhp->srq = to_chrd_srq(attrs->srq);
	INIT_LIST_HEAD(&qhp->fcl.db_fc_entry);
	qhp->fcl.type = RC_QP;

	pr_debug("sq id %u size %u memsize %lu num_entries %u "
		 "rq id %u size %u memsize %lu num_entries %u sq_sig_all %u scqid %u\n",
		 qhp->wq.sq.qid, qhp->wq.sq.size, (unsigned long)qhp->wq.sq.memsize,
		 attrs->cap.max_send_wr, qhp->wq.rq.qid, qhp->wq.rq.size,
		 (unsigned long)qhp->wq.rq.memsize, attrs->cap.max_recv_wr,
		 qhp->sq_sig_all, schp->cq.cqid);

	return 0;
err_free_ma_sync_key:
	if (ma_sync_key_mm)
		kfree(ma_sync_key_mm);
err_free_rq_db_key:
	if (!attrs->srq)
		kfree(rq_db_key_mm);
err_free_sq_db_key:
	kfree(sq_db_key_mm);
err_free_rq_key:
	if (!attrs->srq)
		kfree(rq_key_mm);
err_free_sq_key:
	kfree(sq_key_mm);
err_remove_handle:
	xa_erase_irq(&rhp->qps, qhp->wq.sq.qid);
err_destroy_qp:
	free_rc_queues(&rhp->rdev, &qhp->wq,
		   ucontext ? &ucontext->uctx : &rhp->rdev.uctx, !attrs->srq);
err_free_wr_wait:
	chrd_put_wr_wait(qhp->wr_waitp);
	return ret;
}

static int create_raw_qp(struct ib_qp *qp, struct ib_qp_init_attr *attrs,
			 struct ib_udata *udata)
{
	struct chrd_mm_entry *fl_db_key_mm = NULL, *iq_db_key_mm = NULL;
	struct chrd_mm_entry *txq_key_mm = NULL, *txq_db_key_mm = NULL;
	struct chrd_mm_entry *kdb_key_mm = NULL, *ocq_key_mm = NULL;
	struct chrd_mm_entry *fl_key_mm = NULL, *iq_key_mm = NULL;
	struct chrd_raw_qp *rqp = to_chrd_raw_qp(qp);
	struct cxgb4_uld_txq_info txq_info = { 0 };
	struct chrd_create_raw_qp_resp uresp;
	struct chrd_create_raw_qp_req ureq;
	struct chrd_ucontext *ucontext;
	int sqsize, flsize, iqsize;
	struct ib_pd *pd = qp->pd;
	struct resource *res;
	struct chrd_dev *rhp;
	struct chrd_cq *schp;
	struct chrd_cq *rchp;
	struct chrd_pd *php;
	static int warned;
	int ret;

	pr_debug("ib_pd %p\n", pd);

	if (!(pd->uobject))
		return EINVAL;

	if (!allow_nonroot_rawqps && !capable(CAP_NET_RAW))
		return -EPERM;

	php = to_chrd_pd(pd);
	rhp = php->rhp;

	res = cxgb4_bar_resource(rhp->rdev.lldi.ports[0], 0);
	if (!res)
		return -EOPNOTSUPP;

	if (udata->inlen != sizeof ureq ||
	    udata->outlen < sizeof uresp) {
		if (!warned) {
			warned = 1;
			pr_warn("WARNING: downlevel libcxgb4. "
				"WD queues cannot be supported. Please update "
				"libcxgb4.\n");
		}
		return -EINVAL;
	} 

	ret = ib_copy_from_udata(&ureq, udata, sizeof ureq);
	if (ret)
		return -EFAULT;

	if (ureq.port == 0 || ureq.port > rhp->rdev.lldi.nports)
		return -EINVAL;
	if (ureq.nfids == 0)
		return -EINVAL;
	ureq.port--;
	schp = get_chp(rhp, ((struct chrd_cq *)attrs->send_cq)->cq.cqid);
	rchp = get_chp(rhp, ((struct chrd_cq *)attrs->recv_cq)->cq.cqid);
	if (!schp || !rchp)
		return -EINVAL;

	if (attrs->cap.max_inline_data > T4_MAX_TXQ_INLINE)
		return -EINVAL;

	if (attrs->cap.max_send_wr > rhp->rdev.hw_queue.t4_max_sq_size)
		return -E2BIG;
	sqsize = attrs->cap.max_send_wr + 1;
	if (sqsize < 8)
		sqsize = 8;

	if (attrs->cap.max_recv_wr > rhp->rdev.hw_queue.t4_max_sq_size)
		return -E2BIG;
	if (attrs->srq) {
		flsize = 0;
		iqsize = 0;
	} else {
		flsize = attrs->cap.max_recv_wr + 1;
		if (flsize < 8)
			flsize = 8;
		iqsize = rchp->cq.size + 1;
	}

	ucontext = rdma_udata_to_drv_context(udata, struct chrd_ucontext,
					     ibucontext);

	rqp->rcq = rchp;
	rqp->scq = schp;
	rqp->fl.size = flsize;
	rqp->fl.packed = !!(ureq.flags & FL_PACKED_MODE);
	rqp->fl.cong_drop = !!(ureq.flags & FL_CONG_DROP_MODE);
	rqp->iq.size = iqsize;
	rqp->txq.size = sqsize;
	rqp->netdev = rhp->rdev.lldi.ports[ureq.port];
	rqp->vlan_pri = ureq.vlan_pri;
	rqp->nfids = ureq.nfids;
	rqp->rhp = rhp;

	txq_info.uld_index = cxgb4_port_idx(rqp->netdev) *
			     rhp->rdev.lldi.ntxq / rhp->rdev.lldi.nchan;
	ret = cxgb4_uld_txq_alloc(rqp->netdev, CXGB4_ULD_TYPE_RDMA, &txq_info);
	if (ret < 0)
		return ret;
	rqp->txq_idx = txq_info.lld_index;

	rqp->iq.memsize = PAGE_ALIGN(rqp->iq.size * T4_IQE_LEN);
	rqp->fl.memsize = PAGE_ALIGN(rqp->fl.size * sizeof(__be64) +
				     rhp->rdev.hw_queue.t4_stat_len);
	rqp->txq.memsize = PAGE_ALIGN(rqp->txq.size * sizeof *rqp->txq.desc +
				      rhp->rdev.hw_queue.t4_stat_len +
				      16*sizeof(__be64));
	rqp->state = CHRD_QP_STATE_IDLE;
	mutex_init(&rqp->mutex);
	init_waitqueue_head(&rqp->wait);
	atomic_set(&rqp->refcnt, 1);

	if (!attrs->srq) {
		ret = alloc_raw_rxq(rhp, rqp);
		if (ret)
			goto err1;
	}
	ret = alloc_raw_txq(rhp, rqp);
	if (ret)
		goto err2;

	rqp->fid = get_fid(rhp, rqp->nfids);
	if (rqp->fid < 0) {
		pr_err("%s no fids available\n", __func__);
		ret = -ENOMEM;
		goto err2a;
	}

	attrs->cap.max_recv_wr = rqp->fl.size ? rqp->fl.size - 1 : 0;
	attrs->cap.max_send_wr = rqp->txq.size - 1;
	attrs->cap.max_inline_data = T4_MAX_SEND_INLINE;

	if (!attrs->srq) {
		ret = xa_insert_irq(&rhp->rawiqs, rqp->iq.cntxt_id, &rqp->fcl, GFP_KERNEL);
		if (ret)
			goto err3;
		fl_key_mm = kmalloc(sizeof *fl_key_mm, GFP_KERNEL);
		if (!fl_key_mm) {
			ret = -ENOMEM;
			goto err4;
		}
		iq_key_mm = kmalloc(sizeof *iq_key_mm, GFP_KERNEL);
		if (!iq_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
	} else {
		fl_key_mm = iq_key_mm = NULL;
	}
	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		kdb_key_mm = kmalloc(sizeof *kdb_key_mm, GFP_KERNEL);
		if (!kdb_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
	}
	txq_key_mm = kmalloc(sizeof *txq_key_mm, GFP_KERNEL);
	if (!txq_key_mm) {
		ret = -ENOMEM;
		goto err5;
	}
	memset(&uresp, 0, sizeof uresp);
	uresp.flags = 0;
	if (rqp->txq.flags & T4_SQ_ONCHIP) {
		ocq_key_mm = kmalloc(sizeof *ocq_key_mm, GFP_KERNEL);
		if (!ocq_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
		uresp.flags = CHRD_QPF_ONCHIP;
	} else if (!is_t4(rhp->rdev.lldi.adapter_type)) {
		txq_db_key_mm = kmalloc(sizeof *txq_db_key_mm, GFP_KERNEL);
		if (!txq_db_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
		fl_db_key_mm = kmalloc(sizeof *fl_db_key_mm, GFP_KERNEL);
		if (!fl_db_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
		iq_db_key_mm = kmalloc(sizeof *iq_db_key_mm, GFP_KERNEL);
		if (!iq_db_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
	}
	uresp.fl_id = rqp->fl.cntxt_id;
	uresp.iq_id = rqp->iq.cntxt_id;
	uresp.txq_id = rqp->txq.cntxt_id;
	uresp.fl_size = rqp->fl.size;
	uresp.iq_size = rqp->iq.size;
	uresp.txq_size = rqp->txq.size;
	uresp.fl_memsize = rqp->fl.memsize;
	uresp.iq_memsize = rqp->iq.memsize;
	uresp.txq_memsize = rqp->txq.memsize;
	uresp.tx_chan = cxgb4_port_tx_chan(rqp->netdev);
	uresp.pf = rhp->rdev.lldi.pf;
	uresp.fid = rqp->fid;
	spin_lock(&ucontext->mmap_lock);
	if (rqp->txq.flags & T4_SQ_ONCHIP) {
		uresp.ma_sync_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	} else if (!is_t4(rhp->rdev.lldi.adapter_type)) {
		uresp.txq_bar2_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.fl_bar2_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.iq_bar2_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	}
	if (!attrs->srq) {
		uresp.fl_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.iq_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	}
	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		uresp.db_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	}
	uresp.txq_key = ucontext->key;
	ucontext->key += PAGE_SIZE;
	spin_unlock(&ucontext->mmap_lock);
	ret = ib_copy_to_udata(udata, &uresp, sizeof uresp);
	if (ret)
		goto err5;
	if (!attrs->srq) {
		fl_key_mm->key = uresp.fl_key;
		fl_key_mm->addr = rqp->fl.phys_addr;
		fl_key_mm->len = uresp.fl_memsize;
		fl_key_mm->vaddr = rqp->fl.desc;
		fl_key_mm->dma_addr = rqp->fl.dma_addr;
		insert_mmap(ucontext, fl_key_mm);
		iq_key_mm->key = uresp.iq_key;
		iq_key_mm->addr = rqp->iq.phys_addr;
		iq_key_mm->len = uresp.iq_memsize;
		iq_key_mm->vaddr = rqp->iq.desc;
		iq_key_mm->dma_addr = rqp->iq.dma_addr;
		insert_mmap(ucontext, iq_key_mm);
	}
	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		kdb_key_mm->key = uresp.db_key;
		kdb_key_mm->addr =
			(res->start + MYPF_REG(A_SGE_PF_KDOORBELL)) & PAGE_MASK;
		kdb_key_mm->len = PAGE_SIZE;
		kdb_key_mm->vaddr = NULL;
		kdb_key_mm->dma_addr = 0;
		insert_mmap(ucontext, kdb_key_mm);
	}
	txq_key_mm->key = uresp.txq_key;
	txq_key_mm->addr = rqp->txq.phys_addr;
	txq_key_mm->len = uresp.txq_memsize;
	txq_key_mm->vaddr = rqp->txq.desc;
	txq_key_mm->dma_addr = rqp->txq.dma_addr;
	insert_mmap(ucontext, txq_key_mm);
	if (rqp->txq.flags & T4_SQ_ONCHIP) {
		ocq_key_mm->key = uresp.ma_sync_key;
		ocq_key_mm->addr = (res->start + A_PCIE_MA_SYNC) & PAGE_MASK;
		ocq_key_mm->len = PAGE_SIZE;
		ocq_key_mm->vaddr = NULL;
		ocq_key_mm->dma_addr = 0;
		insert_mmap(ucontext, ocq_key_mm);
	} else if (!is_t4(rhp->rdev.lldi.adapter_type)) {
		u32 bar2_qid;
		u64 bar2_pa;
		void __iomem *va;

		va = chrd_bar2_addrs(&rhp->rdev, rqp->txq.cntxt_id,
				     CXGB4_BAR2_QTYPE_EGRESS,
				     &bar2_qid, &bar2_pa);
		if (!va)
			goto err6;
		txq_db_key_mm->key = uresp.txq_bar2_key;
		txq_db_key_mm->addr = bar2_pa;
		txq_db_key_mm->len = PAGE_SIZE;
		txq_db_key_mm->vaddr = NULL;
		txq_db_key_mm->dma_addr = 0;
		insert_mmap(ucontext, txq_db_key_mm);

		va = chrd_bar2_addrs(&rhp->rdev, rqp->fl.cntxt_id,
				     CXGB4_BAR2_QTYPE_EGRESS,
				     &bar2_qid, &bar2_pa);
		if (!va)
			goto err7;
		fl_db_key_mm->key = uresp.fl_bar2_key;
		fl_db_key_mm->addr = bar2_pa;
		fl_db_key_mm->len = PAGE_SIZE;
		fl_db_key_mm->vaddr = NULL;
		fl_db_key_mm->dma_addr = 0;
		insert_mmap(ucontext, fl_db_key_mm);

		va = chrd_bar2_addrs(&rhp->rdev, rqp->iq.cntxt_id,
				     CXGB4_BAR2_QTYPE_EGRESS,
				     &bar2_qid, &bar2_pa);
		if (!va)
			goto err8;
		iq_db_key_mm->key = uresp.iq_bar2_key;
		iq_db_key_mm->addr = bar2_pa;
		iq_db_key_mm->len = PAGE_SIZE;
		iq_db_key_mm->vaddr = NULL;
		iq_db_key_mm->dma_addr = 0;
		insert_mmap(ucontext, iq_db_key_mm);
	}
	rqp->ibqp.qp_num = rqp->txq.cntxt_id;

	ret = xa_insert_irq(&rhp->rawqps, rqp->txq.cntxt_id, rqp, GFP_KERNEL);
	if (ret)
		goto err8;
	ret = xa_insert_irq(&rhp->fids, rqp->fid, rchp, GFP_KERNEL);
	if (ret)
		goto err9;

	INIT_LIST_HEAD(&rqp->fcl.db_fc_entry);
	rqp->fcl.type = RAW_QP;

	pr_debug("txq id %u size %u memsize %u num_entries %u "
		 "fl id %u size %u memsize %u num_entries %u "
		 "iq id %u size %u memsize %u num_entries %u\n",
		 rqp->txq.cntxt_id, rqp->txq.size, rqp->txq.memsize,
		 attrs->cap.max_send_wr, rqp->fl.cntxt_id, rqp->fl.size,
		 rqp->fl.memsize, attrs->cap.max_recv_wr, rqp->iq.cntxt_id,
		 rqp->iq.size, rqp->iq.memsize, rqp->iq.size - 1);

	return 0;
err9:
	xa_erase_irq(&rhp->rawqps, rqp->txq.cntxt_id);
err8:
	if (!is_t4(rhp->rdev.lldi.adapter_type))
		remove_mmap(ucontext, fl_db_key_mm->key, fl_db_key_mm->len);
err7:
	if (!is_t4(rhp->rdev.lldi.adapter_type))
		remove_mmap(ucontext, txq_db_key_mm->key, txq_db_key_mm->len);
err6:
	if (rqp->txq.flags & T4_SQ_ONCHIP) {
		remove_mmap(ucontext, ocq_key_mm->key, ocq_key_mm->len);
	}
	remove_mmap(ucontext, txq_key_mm->key, txq_key_mm->len);
	if (is_t4(rhp->rdev.lldi.adapter_type))
		remove_mmap(ucontext, kdb_key_mm->key, kdb_key_mm->len);
	if (!attrs->srq) {
		remove_mmap(ucontext, iq_key_mm->key, iq_key_mm->len);
		remove_mmap(ucontext, fl_key_mm->key, fl_key_mm->len);
	}
err5:
	if (iq_db_key_mm)
		kfree(iq_db_key_mm);
	if (fl_db_key_mm)
		kfree(fl_db_key_mm);
	if (txq_db_key_mm)
		kfree(txq_db_key_mm);
	if (ocq_key_mm)
		kfree(ocq_key_mm);
	if (txq_key_mm)
		kfree(txq_key_mm);
	if (kdb_key_mm)
		kfree(kdb_key_mm);
	if (iq_key_mm)
		kfree(iq_key_mm);
	if (fl_key_mm)
		kfree(fl_key_mm);
err4:
	if (!attrs->srq)
		xa_erase_irq(&rhp->rawiqs, rqp->iq.cntxt_id);
err3:
	put_fid(rqp);
err2a:
	free_raw_txq(rhp, rqp);
err2:
	if (!attrs->srq)
		free_raw_rxq(rhp, rqp);
err1:
	memset(&txq_info, 0, sizeof(txq_info));
	txq_info.lld_index = rqp->txq_idx;
	cxgb4_uld_txq_free(rqp->netdev, CXGB4_ULD_TYPE_RDMA, &txq_info);
	return ret;
}

int chrd_create_qp(struct ib_qp *qp, struct ib_qp_init_attr *attrs,
		   struct ib_udata *udata)
{
	struct chrd_dev *rhp;
	struct chrd_pd *php;
	int ret;

	php = to_chrd_pd(qp->pd);
	rhp = php->rhp;
	pr_debug("ib_pd %p QP type %d\n", qp->pd, attrs->qp_type);

	switch (attrs->qp_type) {
	case IB_QPT_RC:
	case IB_QPT_GSI:
	case IB_QPT_UD:
		ret = create_rc_qp(qp, attrs, udata);
		break;
	case IB_QPT_RAW_ETH:
		if (!(qp->pd->uobject))
			return -EINVAL;
		ret = create_raw_qp(qp, attrs, udata);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

int chrd_iw_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		      int attr_mask, struct ib_udata *udata)
{
	enum chrd_qp_attr_mask mask = 0;
	struct chrd_common_qp_attributes attrs;
	int ret = 0;

	pr_debug("ib_qp 0x%llx\n", (unsigned long long)ibqp);

	/* iwarp does not support the RTR state */
	if ((attr_mask & IB_QP_STATE) && (attr->qp_state == IB_QPS_RTR))
		attr_mask &= ~IB_QP_STATE;

	/* Make sure we still have something left to do */
	if (!attr_mask)
		return 0;

	memset(&attrs, 0, sizeof attrs);

	attrs.next_state = chrd_convert_state(attr->qp_state);
	attrs.enable_rdma_read = (attr->qp_access_flags &
			       IB_ACCESS_REMOTE_READ) ?  1 : 0;
	attrs.enable_rdma_write = (attr->qp_access_flags &
				IB_ACCESS_REMOTE_WRITE) ? 1 : 0;
	attrs.enable_bind = (attr->qp_access_flags & IB_ACCESS_MW_BIND) ? 1 : 0;

	mask |= (attr_mask & IB_QP_STATE) ? CHRD_QP_ATTR_NEXT_STATE : 0;
	mask |= (attr_mask & IB_QP_ACCESS_FLAGS) ?
			(CHRD_QP_ATTR_ENABLE_RDMA_READ |
			 CHRD_QP_ATTR_ENABLE_RDMA_WRITE |
			 CHRD_QP_ATTR_ENABLE_RDMA_BIND) : 0;

	/*
	 * Use SQ_PSN and RQ_PSN to pass in IDX_INC values for 
	 * ringing the queue db when we're in DB_FULL mode.
	 * Only allow this on T4 devices.
	 */
	attrs.sq_db_inc = attr->sq_psn;
	attrs.rq_db_inc = attr->rq_psn;
	mask |= (attr_mask & IB_QP_SQ_PSN) ? CHRD_QP_ATTR_SQ_DB : 0;
	mask |= (attr_mask & IB_QP_RQ_PSN) ? CHRD_QP_ATTR_RQ_DB : 0;
	if (!is_t4(to_chrd_qp(ibqp)->rhp->rdev.lldi.adapter_type) &&
	    (mask & (CHRD_QP_ATTR_SQ_DB|CHRD_QP_ATTR_RQ_DB)))
		return -EINVAL;

	switch (ibqp->qp_type) {
	case IB_QPT_RC:
		ret = chrd_modify_iw_rc_qp(to_chrd_qp(ibqp), mask, &attrs, 0);
		break;
	case IB_QPT_RAW_ETH:
		ret = modify_raw_qp(to_chrd_raw_qp(ibqp), mask, &attrs);
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", ibqp->qp_type);
	}
	return ret;
}

int chrd_roce_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		      int attr_mask, struct ib_udata *udata)
{
	int ret = 0;

	pr_debug("ib_qp 0x%llx\n", (unsigned long long)ibqp);

	if (!attr_mask)
		return 0;

	switch (ibqp->qp_type) {
	case IB_QPT_GSI:
	case IB_QPT_RC:
	case IB_QPT_UD:
		ret = chrd_modify_roce_qp(to_chrd_qp(ibqp), attr_mask, attr, 0);
		break;
	case IB_QPT_XRC_INI:
	case IB_QPT_XRC_TGT:
		WARN_ONCE(1, "XRC qp type %u\n", ibqp->qp_type);
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", ibqp->qp_type);
	}

	return ret;
}

static int modify_raw_srq(struct ib_srq *ib_srq, struct ib_srq_attr *attr,
			  enum ib_srq_attr_mask srq_attr_mask,
			  struct ib_udata *udata)
{
	u16 idx_inc;
	int ret;

	idx_inc = attr->max_sge >> 16;
	ret = ring_kernel_srq_db(to_chrd_raw_srq(ib_srq), idx_inc);

	return ret;
}

void chrd_dispatch_srq_limit_reached_event(struct chrd_srq *srq)
{
	struct ib_event event = {0};

	event.device = &srq->rhp->ibdev;
	event.element.srq = &srq->ibsrq;
	event.event = IB_EVENT_SRQ_LIMIT_REACHED;
	ib_dispatch_event(&event);
}

static int modify_srq(struct ib_srq *ib_srq, struct ib_srq_attr *attr,
		      enum ib_srq_attr_mask srq_attr_mask,
		      struct ib_udata *udata)
{
	struct chrd_srq *srq = to_chrd_srq(ib_srq);
	int ret = 0;

	/*
	 * XXX 0 mask == a SW interrupt for srq_limit reached...
	 */
	if (udata && !srq_attr_mask) {
		chrd_dispatch_srq_limit_reached_event(srq);
		goto out;
	}

	/* no support for this yet */
	if (srq_attr_mask & IB_SRQ_MAX_WR) {
		ret = -ENOSYS;
		goto out;
	}

	if (!udata && (srq_attr_mask & IB_SRQ_LIMIT)) {
		srq->armed = true;
		srq->srq_limit = attr->srq_limit;
	}
out:
	return ret;
}

int chrd_modify_srq(struct ib_srq *ib_srq, struct ib_srq_attr *attr,
		    enum ib_srq_attr_mask srq_attr_mask,
		    struct ib_udata *udata)
{
	struct chrd_srq *srq = to_chrd_srq(ib_srq);

	if (srq->fcl.type == RAW_SRQ)
		return modify_raw_srq(ib_srq, attr, srq_attr_mask, udata);
	return modify_srq(ib_srq, attr, srq_attr_mask, udata);
}

struct ib_qp *chrd_iw_get_qp(struct ib_device *dev, int qpn)
{
	pr_debug("ib_dev %p qpn 0x%x\n", dev, qpn);
	return (struct ib_qp *)get_qhp(to_chrd_dev(dev), qpn);
}

int chrd_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		     int attr_mask, struct ib_qp_init_attr *init_attr)
{
	struct chrd_qp *qhp = to_chrd_qp(ibqp);

	memset(attr, 0, sizeof *attr);
	memset(init_attr, 0, sizeof *init_attr);
	if (rdma_protocol_roce(ibqp->device, 1)) {
		attr->qp_state = v2_to_ib_qp_state(qhp->attr.state);
		pr_debug("ibqp 0x%llx attr->qp_state %d\n",
			 (unsigned long long)ibqp, attr->qp_state);
	} else {
		attr->qp_state = to_ib_qp_state(qhp->attr.state);
		pr_debug("ibqp 0x%llx attr->qp_state %d\n",
			 (unsigned long long)ibqp, attr->qp_state);
	}
	init_attr->cap.max_send_wr = qhp->attr.sq_num_entries;
	init_attr->cap.max_recv_wr = qhp->attr.rq_num_entries;
	init_attr->cap.max_send_sge = qhp->attr.sq_max_sges;
	init_attr->cap.max_recv_sge = qhp->attr.rq_max_sges;
	init_attr->cap.max_inline_data = T4_MAX_SEND_INLINE;
	init_attr->sq_sig_type = qhp->sq_sig_all ? IB_SIGNAL_ALL_WR : 0;
	return 0;
}

static void destroy_raw_srq(struct ib_srq *ib_srq)
{
	struct chrd_dev *rhp;
	struct chrd_raw_srq *srq;

	srq = to_chrd_raw_srq(ib_srq);
	rhp = srq->dev;

	pr_debug("iqid %d\n", srq->iq.cntxt_id);

	xa_erase_irq(&rhp->rawiqs, srq->iq.cntxt_id);
	spin_lock_irq(&rhp->lock);
	if (!list_empty(&srq->fcl.db_fc_entry))
		list_del_init(&srq->fcl.db_fc_entry);
	spin_unlock_irq(&rhp->lock);
	free_raw_srq(rhp, srq);
}

static void destroy_srq(struct ib_srq *ib_srq, struct ib_udata *udata)
{
	struct chrd_dev *rhp;
	struct chrd_srq *srq;
	struct chrd_ucontext *ucontext;

	srq = to_chrd_srq(ib_srq);
	rhp = srq->rhp;

	pr_debug("id %d\n", srq->wq.qid);

	ucontext = rdma_udata_to_drv_context(udata, struct chrd_ucontext,
					     ibucontext);
	free_srq_queue(srq, ucontext ? &ucontext->uctx : &rhp->rdev.uctx,
		       srq->wr_waitp);
	cxgb4_uld_free_srq_idx(rhp->rdev.rdma_res, srq->idx);
	chrd_put_wr_wait(srq->wr_waitp);
}

static int create_raw_srq(struct ib_srq *ib_srq,
			  struct ib_srq_init_attr *attrs,
			  struct ib_udata *udata)
{
	struct chrd_raw_srq *srq = to_chrd_raw_srq(ib_srq);
	struct ib_pd *pd = ib_srq->pd;
	struct chrd_dev *rhp;
	struct chrd_pd *php;
	struct chrd_create_raw_srq_req ureq;
	struct chrd_create_raw_srq_resp uresp;
	int flsize, iqsize;
	struct chrd_ucontext *ucontext;
	int ret;
	struct chrd_mm_entry *fl_key_mm, *iq_key_mm, *kdb_key_mm = NULL;
	struct chrd_mm_entry *fl_db_key_mm = NULL, *iq_db_key_mm = NULL;
	struct resource *res;

	pr_debug("ib_pd %p\n", pd);

	if (!(pd->uobject))
		return -EINVAL;

	if (!allow_nonroot_rawqps && !capable(CAP_NET_RAW))
		return -EPERM;

	php = to_chrd_pd(pd);
	rhp = php->rhp;

	res = cxgb4_bar_resource(rhp->rdev.lldi.ports[0], 0);
	if (!res)
		return -EOPNOTSUPP;

	ret = ib_copy_from_udata(&ureq, udata, sizeof ureq);
	if (ret)
		return -EFAULT;

	if (ureq.port == 0 || ureq.port > rhp->rdev.lldi.nports)
		return -EINVAL;

	ureq.port--;
	if (attrs->attr.max_wr > rhp->rdev.hw_queue.t4_max_sq_size)
		return -E2BIG;
	flsize = attrs->attr.max_wr + 1;

	iqsize = roundup(flsize * 4, 16);
	if (iqsize > rhp->rdev.hw_queue.t4_max_iq_size)
		iqsize = rhp->rdev.hw_queue.t4_max_iq_size;
	ucontext = rdma_udata_to_drv_context(udata, struct chrd_ucontext,
					     ibucontext);

	srq->fl.size = flsize;
	srq->iq.size = iqsize;
	srq->netdev = rhp->rdev.lldi.ports[ureq.port];
	srq->dev = rhp;
	srq->iq.memsize = PAGE_ALIGN(srq->iq.size * T4_IQE_LEN);
	srq->fl.memsize = PAGE_ALIGN(srq->fl.size * sizeof(__be64) +
				     rhp->rdev.hw_queue.t4_stat_len);
	srq->fl.packed = !!(ureq.flags & FL_PACKED_MODE);
	ret = alloc_raw_srq(rhp, srq);
	if (ret)
		goto err1;
	attrs->attr.max_wr = srq->fl.size - 1;
	attrs->attr.max_sge = 4;

	ret = xa_insert_irq(&rhp->rawiqs, srq->iq.cntxt_id, &srq->fcl, GFP_KERNEL);
	if (ret)
		goto err3;

	fl_key_mm = kmalloc(sizeof *fl_key_mm, GFP_KERNEL);
	if (!fl_key_mm) {
		ret = -ENOMEM;
		goto err4;
	}
	iq_key_mm = kmalloc(sizeof *iq_key_mm, GFP_KERNEL);
	if (!iq_key_mm) {
		ret = -ENOMEM;
		goto err5;
	}
	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		kdb_key_mm = kmalloc(sizeof *kdb_key_mm, GFP_KERNEL);
		if (!kdb_key_mm) {
			ret = -ENOMEM;
			goto err6;
		}
	} else {
		fl_db_key_mm = kmalloc(sizeof *fl_db_key_mm, GFP_KERNEL);
		if (!fl_db_key_mm) {
			ret = -ENOMEM;
			goto err7;
		}
		iq_db_key_mm = kmalloc(sizeof *iq_db_key_mm, GFP_KERNEL);
		if (!iq_db_key_mm) {
			ret = -ENOMEM;
			goto err8;
		}
	}

	memset(&uresp, 0, sizeof uresp);
	uresp.fl_id = srq->fl.cntxt_id;
	uresp.iq_id = srq->iq.cntxt_id;
	uresp.fl_size = srq->fl.size;
	uresp.iq_size = srq->iq.size;
	uresp.fl_memsize = srq->fl.memsize;
	uresp.iq_memsize = srq->iq.memsize;
	uresp.qid_mask = rhp->rdev.rdma_res->qpmask;

	spin_lock(&ucontext->mmap_lock);
	uresp.fl_key = ucontext->key;
	ucontext->key += PAGE_SIZE;
	uresp.iq_key = ucontext->key;
	ucontext->key += PAGE_SIZE;
	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		uresp.db_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	} else {
		uresp.fl_bar2_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.iq_bar2_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	}
	spin_unlock(&ucontext->mmap_lock);

	ret = ib_copy_to_udata(udata, &uresp, sizeof uresp);
	if (ret)
		goto err9;

	fl_key_mm->key = uresp.fl_key;
	fl_key_mm->addr = srq->fl.phys_addr;
	fl_key_mm->len = uresp.fl_memsize;
	fl_key_mm->vaddr = srq->fl.desc;
	fl_key_mm->dma_addr = srq->fl.dma_addr;
	insert_mmap(ucontext, fl_key_mm);
	iq_key_mm->key = uresp.iq_key;
	iq_key_mm->addr = srq->iq.phys_addr;
	iq_key_mm->len = uresp.iq_memsize;
	iq_key_mm->vaddr = srq->iq.desc;
	iq_key_mm->dma_addr = srq->iq.dma_addr;
	insert_mmap(ucontext, iq_key_mm);

	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		kdb_key_mm->key = uresp.db_key;
		kdb_key_mm->addr =
			(res->start + MYPF_REG(A_SGE_PF_KDOORBELL)) & PAGE_MASK;
		kdb_key_mm->len = PAGE_SIZE;
		kdb_key_mm->vaddr = NULL;
		kdb_key_mm->dma_addr = 0;
		insert_mmap(ucontext, kdb_key_mm);
	} else {
		u32 bar2_qid;
		u64 bar2_pa;
		void __iomem *va;

		va = chrd_bar2_addrs(&rhp->rdev, srq->fl.cntxt_id,
				     CXGB4_BAR2_QTYPE_EGRESS,
				     &bar2_qid, &bar2_pa);
		if (!va)
			goto err10;
		fl_db_key_mm->key = uresp.fl_bar2_key;
		fl_db_key_mm->addr = bar2_pa;
		fl_db_key_mm->len = PAGE_SIZE;
		fl_db_key_mm->vaddr = NULL;
		fl_db_key_mm->dma_addr = 0;
		insert_mmap(ucontext, fl_db_key_mm);

		va = chrd_bar2_addrs(&rhp->rdev, srq->iq.cntxt_id,
				     CXGB4_BAR2_QTYPE_EGRESS,
				     &bar2_qid, &bar2_pa);
		if (!va)
			goto err11;
		iq_db_key_mm->key = uresp.iq_bar2_key;
		iq_db_key_mm->addr = bar2_pa;
		iq_db_key_mm->len = PAGE_SIZE;
		iq_db_key_mm->vaddr = NULL;
		iq_db_key_mm->dma_addr = 0;
		insert_mmap(ucontext, iq_db_key_mm);
	}
	INIT_LIST_HEAD(&srq->fcl.db_fc_entry);
	srq->fcl.type = RAW_SRQ;
	pr_debug("fl id %u size %u memsize %u num_entries %u "
		 "iq id %u size %u memsize %u num_entries %u\n",
		 srq->fl.cntxt_id, srq->fl.size, srq->fl.memsize,
		 attrs->attr.max_wr, srq->iq.cntxt_id, srq->iq.size,
		 srq->iq.memsize, srq->iq.size - 1);
	return 0;
err11:
	remove_mmap(ucontext, fl_db_key_mm->key, fl_db_key_mm->len);
err10:
	remove_mmap(ucontext, iq_key_mm->key, iq_key_mm->len);
	remove_mmap(ucontext, fl_key_mm->key, fl_key_mm->len);
err9:
	if (iq_db_key_mm)
		kfree(iq_db_key_mm);
err8:
	if (fl_db_key_mm)
		kfree(fl_db_key_mm);
err7:
	if (kdb_key_mm)
		kfree(kdb_key_mm);
err6:
	if (iq_key_mm)
		kfree(iq_key_mm);
err5:
	if (fl_key_mm)
		kfree(fl_key_mm);
err4:
	xa_erase_irq(&rhp->rawiqs, srq->iq.cntxt_id);
err3:
	free_raw_srq(rhp, srq);
err1:
	return ret;
}

static int create_srq(struct ib_srq *ib_srq, struct ib_srq_init_attr *attrs,
		      struct ib_udata *udata)
{
	struct ib_pd *pd = ib_srq->pd;
	struct chrd_dev *rhp;
	struct chrd_srq *srq = to_chrd_srq(ib_srq);
	struct chrd_pd *php;
	struct chrd_create_srq_resp uresp;
	struct chrd_ucontext *ucontext;
	struct chrd_mm_entry *srq_key_mm, *srq_db_key_mm;
	int rqsize;
	int ret;
	int wr_len;
	unsigned int chip_ver;
	pr_debug("ib_pd %p\n", pd);

	php = to_chrd_pd(pd);
	rhp = php->rhp;

	if (!rhp->rdev.lldi.vr->srq.size)
		return -EINVAL;
	if (attrs->attr.max_wr > rhp->rdev.hw_queue.t4_max_rq_size)
		return -E2BIG;
	if (attrs->attr.max_sge > T4_MAX_RECV_SGE)
		return -E2BIG;

	/*
	 * SRQ RQT and RQ must be a power of 2 and at least 16 deep.
	 */
	rqsize = attrs->attr.max_wr + 1;
	rqsize = roundup_pow_of_two(max_t(u16, rqsize, 16));

	ucontext = rdma_udata_to_drv_context(udata, struct chrd_ucontext,
					     ibucontext);

	srq->wr_waitp = chrd_alloc_wr_wait(GFP_KERNEL);
	if (!srq->wr_waitp)
		return -ENOMEM;

	srq->idx = cxgb4_uld_alloc_srq_idx(rhp->rdev.rdma_res);
	if (srq->idx < 0) {
		ret = -ENOMEM;
		goto err_free_wr_wait;
	}

	wr_len = sizeof(struct fw_ri_res_wr) + sizeof(struct fw_ri_res);
	srq->destroy_skb = alloc_skb(wr_len, GFP_KERNEL);
	if (!srq->destroy_skb) {
		ret = -ENOMEM;
		goto err_free_srq_idx;
	}

	srq->rhp = rhp;
	srq->pdid = php->pdid;

	srq->wq.size = rqsize;
	srq->wq.memsize =
		(rqsize + rhp->rdev.hw_queue.t4_eq_status_entries) *
		sizeof(*srq->wq.queue);
	if (ucontext)
		srq->wq.memsize = roundup(srq->wq.memsize, PAGE_SIZE);

	ret = alloc_srq_queue(srq, ucontext ? &ucontext->uctx :
			&rhp->rdev.uctx, srq->wr_waitp);
	if (ret)
		goto err_free_skb;
	attrs->attr.max_wr = rqsize - 1;

	chip_ver = CHELSIO_CHIP_VERSION(rhp->rdev.lldi.adapter_type);
	if (chip_ver >= CHELSIO_T7)
		srq->flags = T4_SRQ_LIMIT_SUPPORT;

	if (udata) {
		srq_key_mm = kmalloc(sizeof(*srq_key_mm), GFP_KERNEL);
		if (!srq_key_mm) {
			ret = -ENOMEM;
			goto err_free_queue;
		}
		srq_db_key_mm = kmalloc(sizeof(*srq_db_key_mm), GFP_KERNEL);
		if (!srq_db_key_mm) {
			ret = -ENOMEM;
			goto err_free_srq_key_mm;
		}
		memset(&uresp, 0, sizeof(uresp));
		uresp.flags = srq->flags;
		uresp.qid_mask = rhp->rdev.rdma_res->qpmask;
		uresp.srqid = srq->wq.qid;
		uresp.srq_size = srq->wq.size;
		uresp.srq_memsize = srq->wq.memsize;
		uresp.rqt_abs_idx = srq->wq.rqt_abs_idx;
		spin_lock(&ucontext->mmap_lock);
		uresp.srq_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.srq_db_gts_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		spin_unlock(&ucontext->mmap_lock);
		ret = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (ret)
			goto err_free_srq_db_key_mm;
		srq_key_mm->key = uresp.srq_key;
		srq_key_mm->addr = virt_to_phys(srq->wq.queue);
		srq_key_mm->len = PAGE_ALIGN(srq->wq.memsize);
		srq_key_mm->vaddr = srq->wq.queue;
		srq_key_mm->dma_addr = srq->wq.dma_addr;
		insert_mmap(ucontext, srq_key_mm);
		srq_db_key_mm->key = uresp.srq_db_gts_key;
		srq_db_key_mm->addr = (u64)(unsigned long)srq->wq.bar2_pa;
		srq_db_key_mm->len = PAGE_SIZE;
		srq_db_key_mm->vaddr = NULL;
		srq_db_key_mm->dma_addr = 0;
		insert_mmap(ucontext, srq_db_key_mm);
	}

	pr_debug("%s srq qid %u idx %u size %u memsize %lu num_entries %u\n",
		 __func__, srq->wq.qid, srq->idx, srq->wq.size,
		 (unsigned long)srq->wq.memsize, attrs->attr.max_wr);

	spin_lock_init(&srq->lock);
	return 0;

err_free_srq_db_key_mm:
	kfree(srq_db_key_mm);
err_free_srq_key_mm:
	kfree(srq_key_mm);
err_free_queue:
	free_srq_queue(srq, ucontext ? &ucontext->uctx : &rhp->rdev.uctx,
		       srq->wr_waitp);
err_free_skb:
	kfree_skb(srq->destroy_skb);
err_free_srq_idx:
	cxgb4_uld_free_srq_idx(rhp->rdev.rdma_res, srq->idx);
err_free_wr_wait:
	chrd_put_wr_wait(srq->wr_waitp);
	return ret;
}

int chrd_create_srq(struct ib_srq *ib_srq, struct ib_srq_init_attr *attrs,
			       struct ib_udata *udata)
{
	/*
	 * XXX attrs->attr.srq_limit[31:31] == 1 indicates a raw SRQ!
	 */
	if (((attrs->attr.srq_limit >> 31) & 1) == 1)
		return create_raw_srq(ib_srq, attrs, udata);
	return create_srq(ib_srq, attrs, udata);
}

int chrd_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata)
{
	struct chrd_srq *srq = to_chrd_srq(ibsrq);

	if (srq->fcl.type == RAW_SRQ)
		destroy_raw_srq(ibsrq);
	else
		destroy_srq(ibsrq, udata);

	return 0;
}
