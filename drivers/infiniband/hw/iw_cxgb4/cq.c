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

#include "iw_cxgb4.h"
#include <rdma/ib_user_verbs.h>
#include <rdma/uverbs_ioctl.h>

static void destroy_cq(struct chrd_rdev *rdev, struct t4_cq *cq,
		       struct cxgb4_dev_ucontext *uctx, struct sk_buff *skb,
		       struct chrd_wr_wait *wr_waitp)
{
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
	res->u.cq.restype = FW_RI_RES_TYPE_CQ;
	res->u.cq.op = FW_RI_RES_OP_RESET;
	res->u.cq.iqid = cpu_to_be32(cq->cqid);

	chrd_init_wr_wait(wr_waitp);
	chrd_ref_send_wait(rdev, skb, wr_waitp, 0, 0, __func__);

	kfree(cq->sw_queue);
	dma_free_coherent(rdev->lldi.dev,
			  cq->memsize, cq->queue,
			  dma_unmap_addr(cq, mapping));
	cxgb4_uld_put_cqid(uctx, cq->cqid);
}

static int create_cq(struct chrd_rdev *rdev, struct t4_cq *cq,
		     struct cxgb4_dev_ucontext *uctx,
		     struct chrd_wr_wait *wr_waitp)
{
	struct fw_ri_res_wr *res_wr;
	struct fw_ri_res *res;
	int wr_len;
	int user = (uctx != &rdev->uctx);
	int ret;
	struct sk_buff *skb;

	cq->cqid = cxgb4_uld_get_cqid(rdev->rdma_res, uctx);
	if (!cq->cqid) {
		ret = -ENOMEM;
		goto err1;
	}

	if (!user) {
		cq->sw_queue = kzalloc(cq->memsize, GFP_KERNEL);
		if (!cq->sw_queue) {
			ret = -ENOMEM;
			goto err2;
		}
	}
	cq->queue = dma_alloc_coherent(rdev->lldi.dev, cq->memsize,
				       &cq->dma_addr, GFP_KERNEL);
	if (!cq->queue) {
		ret = -ENOMEM;
		goto err3;
	}
	dma_unmap_addr_set(cq, mapping, cq->dma_addr);

	/* build fw_ri_res_wr */
	wr_len = sizeof *res_wr + sizeof *res;

	skb = alloc_skb(wr_len, GFP_KERNEL | __GFP_NOFAIL);
	if (!skb) {
		ret = -ENOMEM;
		goto err4;
	}
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
	res->u.cq.restype = FW_RI_RES_TYPE_CQ;
	res->u.cq.op = FW_RI_RES_OP_WRITE;
	res->u.cq.iqid = cpu_to_be32(cq->cqid);
	res->u.cq.iqandst_to_iqandstindex = cpu_to_be32(
			V_FW_RI_RES_WR_IQANUS(0) |
			V_FW_RI_RES_WR_IQANUD(1) |
			F_FW_RI_RES_WR_IQANDST |
			V_FW_RI_RES_WR_IQANDSTINDEX(rdev->lldi.ciq_ids[cq->vector]));
	res->u.cq.iqdroprss_to_iqesize = cpu_to_be16(
			V_FW_RI_RES_WR_IQPCIECH(2) |
			V_FW_RI_RES_WR_IQINTCNTTHRESH(0) |
			F_FW_RI_RES_WR_IQO |
			V_FW_RI_RES_WR_IQESIZE(ilog2(sizeof *cq->queue) - 4));
	res->u.cq.iqsize = cpu_to_be16(cq->size);
	res->u.cq.iqaddr = cpu_to_be64(cq->dma_addr);

	chrd_init_wr_wait(wr_waitp);

	ret = chrd_ref_send_wait(rdev, skb, wr_waitp, 0, 0, __func__);
	if (ret)
		goto err4;

	cq->gen = 1;
 	cq->gts = rdev->lldi.gts_reg;
	cq->rdev = rdev;

	cq->bar2_va = chrd_bar2_addrs(rdev, cq->cqid, CXGB4_BAR2_QTYPE_INGRESS,
				      &cq->bar2_qid,
				      user ? &cq->bar2_pa : NULL);
	if (user && !cq->bar2_pa) {
		pr_warn("%s: cqid %u not in BAR2 range\n",
			rdev->lldi.name, cq->cqid);
		ret = -EINVAL;
		goto err4;
	}
	return 0;
err4:
	dma_free_coherent(rdev->lldi.dev, cq->memsize, cq->queue,
			  dma_unmap_addr(cq, mapping));
err3:
	kfree(cq->sw_queue);
err2:
	cxgb4_uld_put_cqid(uctx, cq->cqid);
err1:
	return ret;
}

static void insert_recv_cqe(struct chrd_qp *qhp, struct t4_cq *cq, u32 srqidx)
{
	struct t4_cqe cqe;
	struct t4_wq *wq = &qhp->wq;

	pr_debug("wq %p cq %p sw_cidx %u sw_pidx %u\n",
		 wq, cq, cq->sw_cidx, cq->sw_pidx);
	memset(&cqe, 0, sizeof(cqe));
	if (rdma_protocol_roce(qhp->ibqp.device, 1)) {
		cqe.rss.opcode = CPL_ROCE_CQE;
		cqe.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
					 V_CQE_TYPE(0) |
					 V_CQE_SWCQE(1) |
					 V_CQE_QPID(wq->sq.qid));
		cqe.u.v2_com.v2_header = cpu_to_be32(V_CQE_V2_OPCODE(FW_RI_SEND));
	} else {
		cqe.rss.opcode = CPL_RDMA_CQE;
		cqe.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
					 V_CQE_OPCODE(FW_RI_SEND) |
					 V_CQE_TYPE(0) |
					 V_CQE_SWCQE(1) |
					 V_CQE_QPID(wq->sq.qid));
	}
	cqe.bits_type_ts = cpu_to_be64(V_CQE_GENBIT((u64)cq->gen));
	if (srqidx)
		cqe.u.srcqe.abs_rqe_idx = cpu_to_be32(srqidx);
	cq->sw_queue[cq->sw_pidx] = cqe;
	t4_swcq_produce(cq);
}

int chrd_flush_rq(struct chrd_qp *qhp, struct t4_cq *cq, int count)
{
	int flushed = 0;
	struct t4_wq *wq = &qhp->wq;
	int in_use = wq->rq.in_use - count;

	pr_debug("wq %p cq %p rq.in_use %u skip count %u\n",
		 wq, cq, wq->rq.in_use, count);
	while (in_use--) {
		insert_recv_cqe(qhp, cq, 0);
		flushed++;
	}
	return flushed;
}

static void insert_sq_cqe(struct chrd_qp *qhp, struct t4_cq *cq,
			  struct t4_swsqe *swcqe)
{
	struct t4_cqe cqe;
	struct t4_wq *wq = &qhp->wq;

	pr_debug("wq %p cq %p sw_cidx %u sw_pidx %u\n",
		 wq, cq, cq->sw_cidx, cq->sw_pidx);
	memset(&cqe, 0, sizeof(cqe));
	if (rdma_protocol_roce(qhp->ibqp.device, 1)) {
		cqe.rss.opcode = CPL_ROCE_CQE;
		cqe.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
					 V_CQE_TYPE(1) |
					 V_CQE_SWCQE(1) |
					 V_CQE_QPID(wq->sq.qid));
		cqe.u.v2_com.v2_header = cpu_to_be32(V_CQE_V2_OPCODE(swcqe->opcode));
	} else {
		cqe.rss.opcode = CPL_RDMA_CQE;
		cqe.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
					 V_CQE_OPCODE(swcqe->opcode) |
					 V_CQE_TYPE(1) |
					 V_CQE_SWCQE(1) |
					 V_CQE_QPID(wq->sq.qid));
	}
	CQE_WRID_SQ_IDX(&cqe) = swcqe->idx;
	cqe.bits_type_ts = cpu_to_be64(V_CQE_GENBIT((u64)cq->gen));
	cq->sw_queue[cq->sw_pidx] = cqe;
	t4_swcq_produce(cq);
}

static void advance_oldest_read(struct t4_wq *wq);

int chrd_flush_sq(struct chrd_qp *qhp)
{
	int flushed = 0;
	struct t4_wq *wq = &qhp->wq;
	struct chrd_cq *chp = to_chrd_cq(qhp->ibqp.send_cq);
	struct t4_cq *cq = &chp->cq;
	int idx;
	struct t4_swsqe *swsqe;

	if (wq->sq.flush_cidx == -1)
		wq->sq.flush_cidx = wq->sq.cidx;
	idx = wq->sq.flush_cidx;
	while (idx != wq->sq.pidx) {
		swsqe = &wq->sq.sw_sq[idx];
		swsqe->flushed = 1;
		insert_sq_cqe(qhp, cq, swsqe);
		if (wq->sq.oldest_read == swsqe) {
			advance_oldest_read(wq);
		}
		flushed++;
		if (++idx == wq->sq.size)
			idx = 0;
	}
	wq->sq.flush_cidx += flushed;
	if (wq->sq.flush_cidx >= wq->sq.size)
        	wq->sq.flush_cidx -= wq->sq.size;
	return flushed;
}

static void flush_completed_wrs(struct t4_wq *wq, struct t4_cq *cq)
{
	struct t4_swsqe *swsqe;
	int cidx;

	if (wq->sq.flush_cidx == -1)
	        wq->sq.flush_cidx = wq->sq.cidx;
    	cidx = wq->sq.flush_cidx;
		
	while (cidx != wq->sq.pidx) {
		swsqe = &wq->sq.sw_sq[cidx];
		if (!swsqe->signaled) {
			pr_debug("sq pidx %u swcq sq idx %u cq idx %u\n",
				 wq->sq.pidx, cidx, cq->sw_pidx);
			if (++cidx == wq->sq.size)
				cidx = 0;
		} else if (swsqe->complete) {
			/*
			 * Insert this completed cqe into the swcq.
			 */
			pr_debug("moving cqe into sq pidx %u swcq sq idx %u cq idx %u Signaled %d\n",
				 wq->sq.pidx, cidx, cq->sw_pidx, swsqe->signaled);
			swsqe->cqe.header |= htonl(V_CQE_SWCQE(1));
			cq->sw_queue[cq->sw_pidx] = swsqe->cqe;
			t4_swcq_produce(cq);
			swsqe->flushed = 1;
			if (++cidx == wq->sq.size)
				cidx = 0;
			wq->sq.flush_cidx = cidx;
		} else {
			pr_debug("WARNING: SIGNALLED! sq pidx %u swcq sq idx %u cq idx %u Signaled %d\n",
				 wq->sq.pidx, cidx, cq->sw_pidx, swsqe->signaled);
			break;
		}
	}
}

static void create_read_req_cqe(struct t4_wq *wq, struct t4_cqe *hw_cqe,
		struct t4_cqe *read_cqe)
{
	read_cqe->rss = hw_cqe->rss;
	read_cqe->u.scqe.cidx = wq->sq.oldest_read->idx;
	read_cqe->len = ntohl(wq->sq.oldest_read->read_len);
	read_cqe->header = htonl(V_CQE_QPID(CQE_QPID(hw_cqe)) |
			V_CQE_SWCQE(SW_CQE(hw_cqe)) |
			V_CQE_OPCODE(FW_RI_READ_REQ) |
			V_CQE_TYPE(1));
	read_cqe->bits_type_ts = hw_cqe->bits_type_ts;
}

static void create_v2_read_req_cqe(struct t4_wq *wq, struct t4_cqe *hw_cqe,
		struct t4_cqe *read_cqe)
{
	read_cqe->rss = hw_cqe->rss;
	read_cqe->u.scqe.cidx = wq->sq.oldest_read->idx;
	read_cqe->len = ntohl(wq->sq.oldest_read->read_len);
	read_cqe->header = htonl(V_CQE_QPID(CQE_QPID(hw_cqe)) |
			V_CQE_SWCQE(SW_CQE(hw_cqe)) |
			//V_CQE_V2_OPCODE(FW_RI_READ_REQ) |			/*Todo: Check the Commented Code */
			V_CQE_TYPE(1));
	read_cqe->u.v2_com.v2_header = htonl(V_CQE_V2_OPCODE(FW_RI_READ_REQ));
	read_cqe->bits_type_ts = hw_cqe->bits_type_ts;
}

static void advance_oldest_read(struct t4_wq *wq)
{

	u32 rptr = wq->sq.oldest_read - wq->sq.sw_sq + 1;

	if (rptr == wq->sq.size)
		rptr = 0;
	while (rptr != wq->sq.pidx) {
		wq->sq.oldest_read = &wq->sq.sw_sq[rptr];

		if (wq->sq.oldest_read->opcode == FW_RI_READ_REQ)
			return;
		if (++rptr == wq->sq.size)
			rptr = 0;
	}
	wq->sq.oldest_read = NULL;
}

/*
 * Move all CQEs from the HWCQ into the SWCQ.
 * Deal with out-of-order and/or completions that complete
 * prior unsignalled WRs.
 */
void chrd_flush_hw_cq(struct chrd_cq *chp, struct chrd_qp *flush_qhp)
{
	struct t4_cqe *hw_cqe, *swcqe, read_cqe;
	struct chrd_qp *qhp;
	struct t4_swsqe *swsqe;
	u32 cqe2qpid;
	enum qp_transport_type prot;
	int ret;
	u8 cqe_opc;

	pr_debug(" cqid 0x%x\n", chp->cq.cqid);
	if (rdma_protocol_roce(chp->ibcq.device, 1))
		prot = CHRD_TRANSPORT_ROCEV2;
	else
		prot = CHRD_TRANSPORT_IWARP;

	ret = t4_next_hw_cqe(&chp->cq, &hw_cqe);

	/*
	 * This logic is similar to poll_cq(), but not quite the same
	 * unfortunately.  Need to move pertinent HW CQEs to the SW CQ but
	 * also do any translation magic that poll_cq() normally does.
	 */
	while (!ret) {
		cqe2qpid = CQE_QPID(hw_cqe);
		qhp = get_qhp(chp->rhp, cqe2qpid);

		/*
		 * drop CQEs with no associated QP
		 */
		if (qhp == NULL)
			goto next_cqe;

		if (flush_qhp != qhp) {
			spin_lock(&qhp->lock);

			if (qhp->wq.flushed == 1)
				goto next_cqe;
		}

		cqe_opc = prot ? CQE_V2_OPCODE(hw_cqe) : CQE_OPCODE(hw_cqe);
		if (cqe_opc == FW_RI_TERMINATE)
			goto next_cqe;

		if (cqe_opc == FW_RI_READ_RESP) {

			/*
			 * If we have reached here because of async
			 * event or other error, and have egress error
			 * then drop
			 */
			if (CQE_TYPE(hw_cqe) == 1) {
				goto next_cqe;
			}

			/*
			 * drop peer2peer RTR reads.
			 */
			if (CQE_WRID_STAG(hw_cqe) == 1)
				goto next_cqe;

			/*
			 * Eat completions for unsignaled read WRs.
			 */
			if (!qhp->wq.sq.oldest_read->signaled) {
				advance_oldest_read(&qhp->wq);
				goto next_cqe;
			}

			/*
			 * Don't write to the HWCQ, create a new read req CQE
			 * in local memory and move it into the swcq.
			 */
			if (prot)
				create_v2_read_req_cqe(&qhp->wq, hw_cqe, &read_cqe);
			else
				create_read_req_cqe(&qhp->wq, hw_cqe, &read_cqe);

			hw_cqe = &read_cqe;
			advance_oldest_read(&qhp->wq);
		}

		/* if its a SQ completion, then do the magic to move all the
		 * unsignaled and now in-order completions into the swcq.
		 */
		if (SQ_TYPE(hw_cqe)) {
			swsqe = &qhp->wq.sq.sw_sq[CQE_WRID_SQ_IDX(hw_cqe)];
			swsqe->cqe = *hw_cqe;
			swsqe->complete = 1;
			flush_completed_wrs(&qhp->wq, &chp->cq);
		} else {
			swcqe = &chp->cq.sw_queue[chp->cq.sw_pidx];
			*swcqe = *hw_cqe;
			swcqe->header |= cpu_to_be32(V_CQE_SWCQE(1));
			t4_swcq_produce(&chp->cq);
		}
next_cqe:
		t4_hwcq_consume(&chp->cq);
		ret = t4_next_hw_cqe(&chp->cq, &hw_cqe);
		if (qhp && flush_qhp != qhp)
			spin_unlock(&qhp->lock);
	}
}

static int cqe_completes_wr(struct t4_cqe *cqe, struct t4_wq *wq)
{
	if (DRAIN_CQE(cqe)) {
		WARN_ONCE(1, "Unexpected DRAIN CQE qp id %u!\n", wq->sq.qid);
		return 0;
	}

	if (CQE_OPCODE(cqe) == FW_RI_TERMINATE)
		return 0;

	if ((CQE_OPCODE(cqe) == FW_RI_RDMA_WRITE) && RQ_TYPE(cqe))
		return 0;

	if ((CQE_OPCODE(cqe) == FW_RI_READ_RESP) && SQ_TYPE(cqe))
		return 0;

	if (CQE_SEND_OPCODE(cqe) && RQ_TYPE(cqe) && t4_rq_empty(wq))
		return 0;
	return 1;
}

void chrd_count_rcqes(struct t4_cq *cq, struct t4_wq *wq, int *count)
{
	struct t4_cqe *cqe;
	u32 ptr;

	*count = 0;
	pr_debug("count zero %d\n", *count);
	ptr = cq->sw_cidx;
	while (ptr != cq->sw_pidx) {
		cqe = &cq->sw_queue[ptr];
		if (RQ_TYPE(cqe) && (CQE_OPCODE(cqe) != FW_RI_READ_RESP) &&
		    (CQE_QPID(cqe) == wq->sq.qid) && cqe_completes_wr(cqe, wq))
			(*count)++;
		if (++ptr == cq->size)
			ptr = 0;
	}
	pr_debug("cq %p count %d\n", cq, *count);
}

static void post_pending_srq_wrs(struct t4_srq *srq)
{
	struct t4_srq_pending_wr *pwr;
	u16 idx = 0;

	while (srq->pending_in_use) {
		pwr = &srq->pending_wrs[srq->pending_cidx];
		srq->sw_rq[srq->pidx].wr_id = pwr->wr_id;
		srq->sw_rq[srq->pidx].valid = 1;

		pr_debug("posting pending cidx %u pidx %u wq_pidx %u "
			 "in_use %u rq_size %u wr_id %llx\n",
			 srq->cidx, srq->pidx, srq->wq_pidx, srq->in_use,
			 srq->size, (unsigned long long)pwr->wr_id);

		chrd_copy_wr_to_srq(srq, &pwr->wqe, pwr->len16);
		t4_srq_consume_pending_wr(srq);
		t4_srq_produce(srq, pwr->len16);
		idx += DIV_ROUND_UP(pwr->len16*16, T4_EQ_ENTRY_SIZE);
	}

	if (idx) {
		t4_ring_srq_db(srq, idx, pwr->len16, &pwr->wqe);
		srq->queue[srq->size].status.host_wq_pidx =
			srq->wq_pidx;
	}
}

static u64 reap_srq_cqe(struct t4_cqe *hw_cqe, struct t4_srq *srq)
{
	int rel_idx = CQE_ABS_RQE_IDX(hw_cqe) - srq->rqt_abs_idx;
	u64 wr_id;

	srq->sw_rq[rel_idx].valid = 0;
	wr_id = srq->sw_rq[rel_idx].wr_id;

	if (rel_idx == srq->cidx) {
		pr_debug("in order cqe rel_idx %u cidx %u pidx %u wq_pidx %u "
			 "in_use %u rq_size %u wr_id %llx\n",
			 rel_idx, srq->cidx, srq->pidx, srq->wq_pidx,
			 srq->in_use, srq->size,
			 (unsigned long long)srq->sw_rq[rel_idx].wr_id);
		t4_srq_consume(srq);
		while (srq->ooo_count && !srq->sw_rq[srq->cidx].valid) {
			pr_debug("eat ooo cidx %u pidx %u wq_pidx %u "
				 "in_use %u rq_size %u ooo_count %u wr_id %llx\n",
				 srq->cidx, srq->pidx, srq->wq_pidx,
				 srq->in_use, srq->size, srq->ooo_count,
				 (unsigned long long)srq->sw_rq[srq->cidx].wr_id);
			t4_srq_consume_ooo(srq);
		}
		if (srq->ooo_count == 0 && srq->pending_in_use)
			post_pending_srq_wrs(srq);
	} else {
		pr_debug("ooo cqe rel_idx %u cidx %u pidx %u wq_pidx %u "
			 "in_use %u rq_size %u ooo_count %u wr_id %llx\n",
			 rel_idx, srq->cidx, srq->pidx, srq->wq_pidx,
			 srq->in_use, srq->size, srq->ooo_count,
			 (unsigned long long)srq->sw_rq[rel_idx].wr_id);
		t4_srq_produce_ooo(srq);
	}
	return wr_id;
}

/*
 * poll_cq
 *
 * Caller must:
 *     check the validity of the first CQE,
 *     supply the wq assicated with the qpid.
 *
 * credit: cq credit to return to sge.
 * cqe_flushed: 1 iff the CQE is flushed.
 * cqe: copy of the polled CQE.
 *
 * return value:
 *    0		    CQE returned ok.
 *    -EAGAIN       CQE skipped, try again.
 *    -EOVERFLOW    CQ overflow detected.
 */
static int poll_iw_cq(struct t4_wq *wq, struct t4_cq *cq, struct t4_cqe *cqe,
		   u8 *cqe_flushed, u64 *cookie, u32 *credit,
		   struct t4_srq *srq)
{
	int ret = 0;
	struct t4_cqe *hw_cqe, read_cqe = {0};

	*cqe_flushed = 0;
	*credit = 0;
	ret = t4_next_cqe(cq, &hw_cqe);
	if (ret)
		return ret;
	/*
	 * skip cqe's not affiliated with a QP.
	 */
	if (wq == NULL) {
		ret = -EAGAIN;
		goto skip_cqe;
	}

	/*
	* skip hw cqe's if the wq is flushed.
	*/
	if (wq->flushed && !SW_CQE(hw_cqe)) {
		ret = -EAGAIN;
		goto skip_cqe;
	}

	/*
	* skip TERMINATE cqes...
	*/
	if (CQE_OPCODE(hw_cqe) == FW_RI_TERMINATE) {
		ret = -EAGAIN;
		goto skip_cqe;
	}

	/*
	 * Special cqe for drain WR completions...
	 */
	if (DRAIN_CQE(hw_cqe)) {
		*cookie = CQE_DRAIN_COOKIE(hw_cqe);
		*cqe = *hw_cqe;
		goto skip_cqe;
	}

	/*
	 * Gotta tweak READ completions:
	 *	1) the cqe doesn't contain the sq_wptr from the wr.
	 *	2) opcode not reflected from the wr.
	 *	3) read_len not reflected from the wr.
	 *	4) T4 HW (for now) inserts target read response failures which
	 * 	   need to be skipped.
	 */
	if (CQE_OPCODE(hw_cqe) == FW_RI_READ_RESP) {

		/*
		 * If we have reached here because of async
		 * event or other error, and have egress error
		 * then drop
		 */
		if (CQE_TYPE(hw_cqe) == 1) {
			if (CQE_STATUS(hw_cqe))
				t4_set_wq_in_error(wq, 0);
			ret = -EAGAIN;
			goto skip_cqe;
		}

		/*
		 * If this is an unsolicited read response, then the read
		 * was generated by the kernel driver as part of peer-2-peer
		 * connection setup.  So ignore the completion.
		 */
		if (CQE_WRID_STAG(hw_cqe) == 1) {
			if (CQE_STATUS(hw_cqe))
				t4_set_wq_in_error(wq, 0);
			ret = -EAGAIN;
			goto skip_cqe;
		}

		/*
		 * Eat completions for unsignaled read WRs.
		 */
		if (!wq->sq.oldest_read->signaled) {
			advance_oldest_read(wq);
			ret = -EAGAIN;
			goto skip_cqe;
		}

		/*
		 * Don't write to the HWCQ, so create a new read req CQE
		 * in local memory.
		 */
		create_read_req_cqe(wq, hw_cqe, &read_cqe);
		hw_cqe = &read_cqe;
		advance_oldest_read(wq);
	}

	if (CQE_STATUS(hw_cqe) || t4_wq_in_error(wq)) {
		*cqe_flushed = (CQE_STATUS(hw_cqe) == T4_ERR_SWFLUSH);
		t4_set_wq_in_error(wq, 0);
	}

	/*
	 * RECV completion.
	 */
	if (RQ_TYPE(hw_cqe)) {

		/*
		 * HW only validates 4 bits of MSN.  So we must validate that
		 * the MSN in the SEND is the next expected MSN.  If its not,
		 * then we complete this with T4_ERR_MSN and mark the wq in
		 * error.
		 */
		if (unlikely(!CQE_STATUS(hw_cqe) &&
			     CQE_WRID_MSN(hw_cqe) != wq->rq.msn)) {
			t4_set_wq_in_error(wq, 0);
			hw_cqe->header |= cpu_to_be32(V_CQE_STATUS(T4_ERR_MSN));
		}
		goto proc_cqe;
	}

	/*
	 * If we get here its a send completion.
	 *
	 * Handle out of order completion. These get stuffed
	 * in the SW SQ. Then the SW SQ is walked to move any
	 * now in-order completions into the SW CQ.  This handles
	 * 2 cases:
	 *	1) reaping unsignaled WRs when the first subsequent
	 *	   signaled WR is completed.
	 *	2) out of order read completions.
	 */
	if (!SW_CQE(hw_cqe) && (CQE_WRID_SQ_IDX(hw_cqe) != wq->sq.cidx)) {
		struct t4_swsqe *swsqe;

		pr_debug("out of order completion going in sw_sq at idx %u, cidx %u\n",
			 CQE_WRID_SQ_IDX(hw_cqe), wq->sq.cidx);
		swsqe = &wq->sq.sw_sq[CQE_WRID_SQ_IDX(hw_cqe)];
		swsqe->cqe = *hw_cqe;
		swsqe->complete = 1;
		ret = -EAGAIN;
		goto flush_wq;
	}

proc_cqe:
	*cqe = *hw_cqe;

	/*
	 * Reap the associated WR(s) that are freed up with this
	 * completion.
	 */
	if (SQ_TYPE(hw_cqe)) {
		int idx = CQE_WRID_SQ_IDX(hw_cqe);

		/*
		* Account for any unsignaled completions completed by
		* this signaled completion.  In this case, cidx points
		* to the first unsignaled one, and idx points to the
		* signaled one.  So adjust in_use based on this delta.
		* if this is not completing any unsigned wrs, then the
		* delta will be 0. Handle wrapping also!
		*/
		if (idx < wq->sq.cidx)
			wq->sq.in_use -= wq->sq.size + idx - wq->sq.cidx;
		else
			wq->sq.in_use -= idx - wq->sq.cidx;

		wq->sq.cidx = (uint16_t)idx;
		pr_debug("completing sq idx %u\n", wq->sq.cidx);
		*cookie = wq->sq.sw_sq[wq->sq.cidx].wr_id;
		if (chrd_wr_log)
			chrd_log_wr_stats(wq, hw_cqe);
		t4_sq_consume(wq);
	} else {
		if (!srq) {
			pr_debug("completing rq idx %u\n", wq->rq.cidx);
			*cookie = wq->rq.sw_rq[wq->rq.cidx].wr_id;
			if (chrd_wr_log)
				chrd_log_wr_stats(wq, hw_cqe);
			t4_rq_consume(wq);
		} else
			*cookie = reap_srq_cqe(hw_cqe, srq);
		wq->rq.msn++;
		goto skip_cqe;
	}

flush_wq:
	/*
	 * Flush any completed cqes that are now in-order.
	 */
	flush_completed_wrs(wq, cq);

skip_cqe:
	if (SW_CQE(hw_cqe)) {
		pr_debug("cq %p cqid 0x%x skip sw cqe cidx %u sw_in_use %u\n",
			 cq, cq->cqid, cq->sw_cidx, cq->sw_in_use);
		t4_swcq_consume(cq);
	} else {
		pr_debug("cq %p cqid 0x%x skip hw cqe cidx %u sw_in_use %u\n",
			 cq, cq->cqid, cq->cidx, cq->sw_in_use);
		t4_hwcq_consume(cq);
	}
	return ret;
}

/*
 * poll_cq
 *
 * Caller must:
 *     check the validity of the first CQE,
 *     supply the wq assicated with the qpid.
 *
 * credit: cq credit to return to sge.
 * cqe_flushed: 1 iff the CQE is flushed.
 * cqe: copy of the polled CQE.
 *
 * return value:
 *    0		    CQE returned ok.
 *    -EAGAIN       CQE skipped, try again.
 *    -EOVERFLOW    CQ overflow detected.
 */
static int poll_roce_cq(struct t4_wq *wq, struct t4_cq *cq, struct t4_cqe *cqe,
		   u8 *cqe_flushed, u64 *cookie, u32 *credit,
		   struct t4_srq *srq)
{
	struct t4_cqe *hw_cqe, read_cqe = {0};
	struct t4_swsqe *swsqe;
	int ret = 0;
	u8 cqe_opc;

	*cqe_flushed = 0;
	*credit = 0;
	ret = t4_next_cqe(cq, &hw_cqe);
	if (ret)
		return ret;

	/*
	 * skip cqe's not affiliated with a QP.
	 */
	if (wq == NULL) {
		ret = -EAGAIN;
		goto skip_cqe;
	}

	/*
	* skip hw cqe's if the wq is flushed.
	*/
	if (wq->flushed && !SW_CQE(hw_cqe)) {
		ret = -EAGAIN;
		goto skip_cqe;
	}

	/*
	 * Special cqe for drain WR completions...
	 */
	if (DRAIN_CQE(hw_cqe)) {
		*cookie = CQE_DRAIN_COOKIE(hw_cqe);
		*cqe = *hw_cqe;
		goto skip_cqe;
	}
	/* If egress CQE, set the opcode as FW doesn't set it */
	if (CQE_TYPE(hw_cqe) == 1) {
		hw_cqe->u.v2_com.v2_header &= cpu_to_be32(~V_CQE_V2_OPCODE(M_CQE_V2_OPCODE));
		/* FW doesn't send opcode so handle it in SW */
		hw_cqe->u.v2_com.v2_header |= cpu_to_be32(V_CQE_V2_OPCODE(wq->sq.sw_sq[
							  CQE_WRID_SQ_IDX(hw_cqe)].opcode));
	/* If inress CQE, set the SW opcode derrived from HW opcode */
	} else {
		if (CQE_V2_OPCODE(hw_cqe) < 0x18) {
			if (!SW_CQE(hw_cqe)) {
				cqe_opc = CQE_V2_OPCODE(hw_cqe);
				hw_cqe->u.v2_com.v2_header &= cpu_to_be32(~V_CQE_V2_OPCODE(
									  M_CQE_V2_OPCODE));
				hw_cqe->u.v2_com.v2_header |= cpu_to_be32(V_CQE_V2_OPCODE(
									  v2_ib_opc_to_fw_opc(
									  cqe_opc)));
			}
		} else {
			pr_err("Unexpected ingress opcode: opcode %u v2_opcode %u\n",
				  CQE_OPCODE(hw_cqe), CQE_V2_OPCODE(hw_cqe));
			BUG_ON(1);
		}
	}
	/*
	* skip TERMINATE cqes...
	*/
	if (CQE_V2_OPCODE(hw_cqe) == FW_RI_TERMINATE) {
		ret = -EAGAIN;
		goto skip_cqe;
	}

	/*
	 * Gotta tweak READ completions:
	 *	1) the cqe doesn't contain the sq_wptr from the wr.
	 *	2) opcode not reflected from the wr.
	 *	3) read_len not reflected from the wr.
	 *	4) T4 HW (for now) inserts target read response failures which
	 * 	   need to be skipped.
	 */
	if (CQE_V2_OPCODE(hw_cqe) == FW_RI_READ_RESP) {

		/*
		 * If we have reached here because of async
		 * event or other error, and have egress error
		 * then drop
		 */
		BUG_ON(1);
		if (CQE_TYPE(hw_cqe) == 1) {
			if (CQE_STATUS(hw_cqe))
				t4_set_wq_in_error(wq, 0);
			ret = -EAGAIN;
			goto skip_cqe;
		}

		/*
		 * If this is an unsolicited read response, then the read
		 * was generated by the kernel driver as part of peer-2-peer
		 * connection setup.  So ignore the completion.
		 */
		if (CQE_WRID_STAG(hw_cqe) == 1) {
			if (CQE_STATUS(hw_cqe))
				t4_set_wq_in_error(wq, 0);
			ret = -EAGAIN;
			goto skip_cqe;
		}

		/*
		 * Eat completions for unsignaled read WRs.
		 */
		if (wq->sq.oldest_read) {
			pr_debug("Oldest Read 0x%llx\n", (unsigned long long)wq->sq.oldest_read);
			if (!wq->sq.oldest_read->signaled) {
				advance_oldest_read(wq);
				ret = -EAGAIN;
				goto skip_cqe;
			}
	
			/*
			 * Don't write to the HWCQ, so create a new read req CQE
			 * in local memory.
			 */
			create_v2_read_req_cqe(wq, hw_cqe, &read_cqe);
			hw_cqe = &read_cqe;
			advance_oldest_read(wq);
			pr_debug("Oldest Read 0x%llx\n", (unsigned long long)wq->sq.oldest_read);
			pr_debug("CQE OVF %u qpid 0x%0x genbit %u type %u status 0x%0x"
				 " opcode 0x%0x len 0x%0x wrid_hi_stag 0x%x wrid_low_msn 0x%x"
				 " cidx 0x%04x sw opc 0x%x cq 0x%llx v2_header 0x%x\n",
				 CQE_OVFBIT(hw_cqe), CQE_QPID(hw_cqe),
				 CQE_GENBIT(hw_cqe), CQE_TYPE(hw_cqe), CQE_STATUS(hw_cqe),
				 CQE_V2_OPCODE(hw_cqe), CQE_LEN(hw_cqe), CQE_WRID_HI(hw_cqe),
				 CQE_WRID_LOW(hw_cqe), CQE_WRID_SQ_IDX(hw_cqe),
				 wq->sq.sw_sq[CQE_WRID_SQ_IDX(hw_cqe)].opcode,
				 (unsigned long long)cq, hw_cqe->u.v2_com.v2_header);
		} else {
			mdelay(100000); // delay processing for fw dump collection
			BUG_ON(1);
		}
	}

	if (CQE_STATUS(hw_cqe) || t4_wq_in_error(wq)) {
		*cqe_flushed = (CQE_STATUS(hw_cqe) == T4_ERR_SWFLUSH);
		t4_set_wq_in_error(wq, 0);
	}

	/*
	 * RECV completion.
	 */
	if (RQ_TYPE(hw_cqe)) {

		/*
		 * HW only validates 4 bits of MSN.  So we must validate that
		 * the MSN in the SEND is the next expected MSN.  If its not,
		 * then we complete this with T4_ERR_MSN and mark the wq in
		 * error.
		 */
#if 0 // untill msn is fixed in fw/hw
		if (unlikely(!CQE_STATUS(hw_cqe) &&
			     CQE_WRID_MSN(hw_cqe) != wq->rq.msn)) {
			pr_err("Poll failure!\n");
			pr_err(" MSN %u msn %u\n", CQE_WRID_MSN(hw_cqe), wq->rq.msn);
			t4_set_wq_in_error(wq, 0);
			hw_cqe->header |= cpu_to_be32(V_CQE_STATUS(T4_ERR_MSN));
		}
#endif
		goto proc_cqe;
	}

	swsqe = &wq->sq.sw_sq[CQE_WRID_SQ_IDX(hw_cqe)];
	if (!swsqe->signaled) {
		pr_err("%s:%d WARNING: UNSIGNALLED COMPLETION @ %u!!\n", __func__, __LINE__, CQE_WRID_SQ_IDX(hw_cqe));
		ret = -EAGAIN;
		goto skip_cqe;
	}

	/*
	 * If we get here its a send completion.
	 *
	 * Handle out of order completion. These get stuffed
	 * in the SW SQ. Then the SW SQ is walked to move any
	 * now in-order completions into the SW CQ.  This handles
	 * 2 cases:
	 *	1) reaping unsignaled WRs when the first subsequent
	 *	   signaled WR is completed.
	 *	2) out of order read completions.
	 */
	if (!SW_CQE(hw_cqe) && (CQE_WRID_SQ_IDX(hw_cqe) != wq->sq.cidx)) {
		struct t4_swsqe *swsqe;

		pr_debug("out of order completion going in sw_sq at idx %u, cidx %u\n",
			 CQE_WRID_SQ_IDX(hw_cqe), wq->sq.cidx);
		swsqe = &wq->sq.sw_sq[CQE_WRID_SQ_IDX(hw_cqe)];
		swsqe->cqe = *hw_cqe;
		swsqe->complete = 1;
		ret = -EAGAIN;
		goto flush_wq;
	}

proc_cqe:
	*cqe = *hw_cqe;

	/*
	 * Reap the associated WR(s) that are freed up with this
	 * completion.
	 */
	if (SQ_TYPE(hw_cqe)) {
		int idx = CQE_WRID_SQ_IDX(hw_cqe);

		/*
		* Account for any unsignaled completions completed by
		* this signaled completion.  In this case, cidx points
		* to the first unsignaled one, and idx points to the
		* signaled one.  So adjust in_use based on this delta.
		* if this is not completing any unsigned wrs, then the
		* delta will be 0. Handle wrapping also!
		*/
		if (idx < wq->sq.cidx)
			wq->sq.in_use -= wq->sq.size + idx - wq->sq.cidx;
		else
			wq->sq.in_use -= idx - wq->sq.cidx;

		wq->sq.cidx = (uint16_t)idx;
		pr_debug("completing sq idx %u sq inuse %u\n", wq->sq.cidx, wq->sq.in_use);
		*cookie = wq->sq.sw_sq[wq->sq.cidx].wr_id;
		if (chrd_wr_log)
			chrd_log_wr_stats(wq, hw_cqe);
		t4_sq_consume(wq);
	} else {
		if (!srq) {
			pr_debug("completing rq idx %u\n", wq->rq.cidx);
			*cookie = wq->rq.sw_rq[wq->rq.cidx].wr_id;
			if (chrd_wr_log)
				chrd_log_wr_stats(wq, hw_cqe);
			t4_rq_consume(wq);
		} else
			*cookie = reap_srq_cqe(hw_cqe, srq);
		wq->rq.msn++;
		goto skip_cqe;
	}

flush_wq:
	/*
	 * Flush any completed cqes that are now in-order.
	 */
	flush_completed_wrs(wq, cq);

skip_cqe:
	if (SW_CQE(hw_cqe)) {
		pr_debug("sw cq 0x%llx cqid 0x%x skip sw cqe cidx %u sw_in_use %u\n",
			 (unsigned long long)cq, cq->cqid, cq->sw_cidx, cq->sw_in_use);
		t4_swcq_consume(cq);
	} else {
		pr_debug("hw cq 0x%llx cqid 0x%x skip sw cqe cidx %u sw_in_use %u\n",
			 (unsigned long long)cq, cq->cqid, cq->sw_cidx, cq->sw_in_use);
		t4_hwcq_consume(cq);
	}
	return ret;
}

/*
 * Get one cq entry from chrd and map it to openib.
 *
 * Returns:
 *	0			cqe returned
 *	-ENODATA		EMPTY;
 *	-EAGAIN			caller must try again
 *	any other -errno	fatal error
 */
static int chrd_poll_cq_one(struct chrd_cq *chp, struct ib_wc *wc,
			    enum qp_transport_type prot)
{
	struct chrd_qp *qhp = NULL;
	struct t4_cqe cqe, *rd_cqe;
	struct t4_wq *wq;
	u32 credit = 0;
	u8 cqe_flushed, cqe_opc;
	u64 smac;
	u32 cqe2qpid;
	u64 cookie = 0;
	int ret;
	struct chrd_srq *srq = NULL;

	ret = t4_next_cqe(&chp->cq, &rd_cqe);
	pr_debug("next cqe ret %d\n", ret);

	if (ret)
		return ret;

	cqe2qpid = CQE_QPID(rd_cqe);
	pr_debug("cqe qpid %d\n", cqe2qpid);
	qhp = get_qhp(chp->rhp, cqe2qpid);
	if (!qhp)
		wq = NULL;
	else {
		spin_lock(&qhp->lock);
		wq = &(qhp->wq);
		srq = qhp->srq;
		if (srq)
			spin_lock(&srq->lock);
	}

	if (prot)
		ret = poll_roce_cq(wq, &(chp->cq), &cqe, &cqe_flushed, &cookie, &credit,
				   srq ? &srq->wq : NULL);
	else
		ret = poll_iw_cq(wq, &(chp->cq), &cqe, &cqe_flushed, &cookie, &credit,
			      srq ? &srq->wq : NULL);
	if (ret) {
		pr_debug("ret %d\n", ret);
		goto out;
	}

	memset(wc, 0, sizeof(struct ib_wc));
	wc->wr_id = cookie;
	wc->qp = &qhp->ibqp;
	wc->vendor_err = CQE_STATUS(&cqe);
	wc->wc_flags = 0;
	/*
	 * Simulate a SRQ_LIMIT_REACHED HW notification if required.
	 */
	if (srq && !(srq->flags & T4_SRQ_LIMIT_SUPPORT) && srq->armed &&
	    srq->wq.in_use < srq->srq_limit)
		chrd_dispatch_srq_limit_reached_event(srq);

	if (prot)
		cqe_opc = CQE_V2_OPCODE(&cqe);
	else
		cqe_opc = CQE_OPCODE(&cqe);
	pr_debug("wc 0x%llx qpid 0x%x type %d opcode %d status 0x%x len %u wrid hi 0x%x "
		 "lo 0x%x cookie 0x%llx\n", (unsigned long long)wc, CQE_QPID(&cqe),
		 CQE_TYPE(&cqe), cqe_opc, CQE_STATUS(&cqe), CQE_LEN(&cqe),
		 CQE_WRID_HI(&cqe), CQE_WRID_LOW(&cqe), (unsigned long long)cookie);

	if (CQE_TYPE(&cqe) == 0) {
		if (!CQE_STATUS(&cqe))
			wc->byte_len = CQE_LEN(&cqe);
		else
			wc->byte_len = 0;

		switch (cqe_opc) {
		case FW_RI_SEND:
			pr_debug("Check!\n");
			wc->opcode = IB_WC_RECV;
			if (prot) {
				wc->src_qp = 1; /*ToDO: change harcoded value to the one from cqe*/
				wc->slid = 0;
			
				wc->network_hdr_type = (be64_to_cpu(cqe.v2_ext_hi)>>8 & 1) ? RDMA_NETWORK_IPV6 :
				                           RDMA_NETWORK_IPV4;
				smac = be64_to_cpu(cqe.v2_ext_lo);
				ether_addr_copy(wc->smac, (u8 *)&smac);
				wc->vlan_id = CQE_V2_VLAN(&cqe);
				if (wc->vlan_id == 0)
					wc->vlan_id = 0xffff;
				wc->wc_flags |= IB_WC_GRH |
						IB_WC_WITH_NETWORK_HDR_TYPE |
						IB_WC_WITH_SMAC|IB_WC_WITH_VLAN;
				pr_debug("smac 0x%llX\n", smac);
			}
			break;
		case FW_RI_SEND_WITH_INV:
		case FW_RI_SEND_WITH_SE_INV:
			wc->opcode = IB_WC_RECV;
			wc->ex.invalidate_rkey = CQE_WRID_STAG(&cqe);
			wc->wc_flags |= IB_WC_WITH_INVALIDATE;
			chrd_invalidate_mr(qhp->rhp, wc->ex.invalidate_rkey);
			break;
		case FW_RI_WRITE_IMMEDIATE:
			wc->opcode = IB_WC_RECV_RDMA_WITH_IMM;
			wc->ex.imm_data = CQE_IMM_DATA(&cqe);
			wc->wc_flags |= IB_WC_WITH_IMM;
			break;
		default:
			pr_err("%s-%d: Unexpected opcode %d "
			       "in the CQE received for QPID=0x%0x\n",
			       __func__, __LINE__, cqe_opc, CQE_QPID(&cqe));
			ret = -EINVAL;
			goto out;
		}
	} else {
		switch (cqe_opc) {
		case FW_RI_WRITE_IMMEDIATE:
		case FW_RI_RDMA_WRITE:
			wc->opcode = IB_WC_RDMA_WRITE;
			break;
		case FW_RI_READ_REQ:
			wc->opcode = IB_WC_RDMA_READ;
			wc->byte_len = CQE_LEN(&cqe);
			break;
		case FW_RI_SEND_WITH_INV:
		case FW_RI_SEND_WITH_SE_INV:
			wc->opcode = IB_WC_SEND;
			wc->wc_flags |= IB_WC_WITH_INVALIDATE;
			break;
		case FW_RI_SEND:
		case FW_RI_SEND_WITH_SE:
			wc->opcode = IB_WC_SEND;
			//wc->byte_len = 256;// Hack: add byte len
			break;
		case FW_RI_LOCAL_INV:
			wc->opcode = IB_WC_LOCAL_INV;
			break;
		case FW_RI_FAST_REGISTER:
			wc->opcode = IB_WC_REG_MR;

			/* Invalidate the MR if the fastreg failed */
			if (CQE_STATUS(&cqe) != T4_ERR_SUCCESS)
				chrd_invalidate_mr(qhp->rhp,
						   CQE_WRID_FR_STAG(&cqe));
			break;
		default:
			pr_err("%s-%d: Unexpected opcode %d "
			       "in the CQE received for QPID=0x%0x\n",
			       __func__, __LINE__, cqe_opc, CQE_QPID(&cqe));
			ret = -EINVAL;
			goto out;
		}
	}

	if (cqe_flushed)
		wc->status = IB_WC_WR_FLUSH_ERR;
	else {

		switch (CQE_STATUS(&cqe)) {
		case T4_ERR_SUCCESS:
			wc->status = IB_WC_SUCCESS;
			break;
		case T4_ERR_STAG:
			wc->status = IB_WC_LOC_ACCESS_ERR;
			break;
		case T4_ERR_PDID:
			wc->status = IB_WC_LOC_PROT_ERR;
			break;
		case T4_ERR_QPID:
		case T4_ERR_ACCESS:
			wc->status = IB_WC_LOC_ACCESS_ERR;
			break;
		case T4_ERR_WRAP:
			wc->status = IB_WC_GENERAL_ERR;
			break;
		case T4_ERR_BOUND:
			wc->status = IB_WC_LOC_LEN_ERR;
			break;
		case T4_ERR_INVALIDATE_SHARED_MR:
		case T4_ERR_INVALIDATE_MR_WITH_MW_BOUND:
			wc->status = IB_WC_MW_BIND_ERR;
			break;
		case T4_ERR_CRC:
		case T4_ERR_MARKER:
		case T4_ERR_PDU_LEN_ERR:
		case T4_ERR_OUT_OF_RQE:
		case T4_ERR_DDP_VERSION:
		case T4_ERR_RDMA_VERSION:
		case T4_ERR_DDP_QUEUE_NUM:
		case T4_ERR_MSN:
		case T4_ERR_TBIT:
		case T4_ERR_MO:
		case T4_ERR_MSN_RANGE:
		case T4_ERR_IRD_OVERFLOW:
		case T4_ERR_OPCODE:
		case T4_ERR_INTERNAL_ERR:
			wc->status = IB_WC_FATAL_ERR;
			break;
		case T4_ERR_SWFLUSH:
			wc->status = IB_WC_WR_FLUSH_ERR;
			break;
		default:
			pr_err("Unexpected cqe_status 0x%x for QPID=0x%0x\n",
			       CQE_STATUS(&cqe), CQE_QPID(&cqe));
			wc->status = IB_WC_FATAL_ERR;
		}
	}
out:
	if (wq) {
		if (srq)
			spin_unlock(&srq->lock);
		spin_unlock(&qhp->lock);
	}
	return ret;
}

int chrd_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	struct chrd_cq *chp;
	enum qp_transport_type prot;
	unsigned long flags;
	int npolled, j;
	int err = 0;
	struct ib_wc *twc = wc;

	if (rdma_protocol_roce(ibcq->device, 1))
		prot = CHRD_TRANSPORT_ROCEV2;
	else
		prot = CHRD_TRANSPORT_IWARP;

	chp = to_chrd_cq(ibcq);
	pr_debug("chp %p\n", chp);

	spin_lock_irqsave(&chp->lock, flags);
	for (npolled = 0; npolled < num_entries; ++npolled) {
		do {
			err = chrd_poll_cq_one(chp, wc + npolled, prot);
		} while (err == -EAGAIN);
		if (err)
			break;
	}
	if (npolled) {
	for (j = 0; j < npolled; j++) {
		pr_debug("npolled %d j %d status %d opcode %d wr_id 0x%llx "
			 "byte_len %u src_qp %u slid %u wc_flags %d "
			 "pkey_index %u sl %u dlid_path_bits %u "
			 "port_num %u smac %x%x%x%x%x%x"
			 "vlan_id %u network_hdr_type %u\n",
			 npolled, j, twc->status, twc->opcode, twc->wr_id,
			 twc->byte_len, twc->src_qp, twc->slid, twc->wc_flags,
			 twc->pkey_index, twc->sl, twc->dlid_path_bits, twc->port_num,
			 twc->smac[0], twc->smac[1], twc->smac[2], twc->smac[3],
			 twc->smac[4], twc->smac[5], twc->vlan_id, twc->network_hdr_type);
		twc = twc + 1;
		}
	}
	spin_unlock_irqrestore(&chp->lock, flags);
	return !err || err == -ENODATA ? npolled : err;
}

int chrd_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata)
{
	struct chrd_cq *chp;
	struct chrd_ucontext *ucontext;

	pr_debug("ib_cq %p\n", ib_cq);
	chp = to_chrd_cq(ib_cq);

	xa_erase_irq(&chp->rhp->cqs, chp->cq.cqid);
	atomic_dec(&chp->refcnt);
	wait_event(chp->wait, !atomic_read(&chp->refcnt));

	ucontext = rdma_udata_to_drv_context(udata, struct chrd_ucontext,
					     ibucontext);
	destroy_cq(&chp->rhp->rdev, &chp->cq,
		   ucontext ? &ucontext->uctx : &chp->cq.rdev->uctx,
		   chp->destroy_skb, chp->wr_waitp);
	chrd_put_wr_wait(chp->wr_waitp);

	return 0;
}

int chrd_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
		   struct uverbs_attr_bundle *attrs)
{
	struct ib_udata *udata = &attrs->driver_udata;
	struct ib_device *ibdev = ibcq->device;
	int entries = attr->cqe;
	int vector = attr->comp_vector;
	struct chrd_dev *rhp = to_chrd_dev(ibcq->device);
	struct chrd_cq *chp = to_chrd_cq(ibcq);
	struct chrd_create_cq_resp uresp;
	int ret, wr_len;
	size_t memsize, hwentries;
	struct chrd_mm_entry *mm, *mm2;
	struct chrd_ucontext *ucontext = rdma_udata_to_drv_context(
		udata, struct chrd_ucontext, ibucontext);

	pr_debug("ib_dev %p entries %d\n", ibdev, entries);
	if (attr->flags)
		return -EINVAL;

	if (vector >= rhp->rdev.lldi.nciq)
		return -EINVAL;

	chp->wr_waitp = chrd_alloc_wr_wait(GFP_KERNEL);
	if (!chp->wr_waitp) {
		ret = -ENOMEM;
		goto err_free_chp;
	}
	chrd_init_wr_wait(chp->wr_waitp);

	wr_len = sizeof(struct fw_ri_res_wr) + sizeof(struct fw_ri_res);
	chp->destroy_skb = alloc_skb(wr_len, GFP_KERNEL);
	if (!chp->destroy_skb) {
		ret = -ENOMEM;
		goto err_free_wr_wait;
	}

	/* account for the status page. */
	entries++;

	/* IQ needs one extra entry to differentiate full vs empty. */
	entries++;

	/*
	 * entries must be multiple of 16 for HW.
	 */
	entries = roundup(entries, 16);

	/*
	 * Make actual HW queue 2x to avoid cdix_inc overflows.
	 */
	hwentries = min(entries * 2, rhp->rdev.hw_queue.t4_max_iq_size);

	/*
	 * Make HW queue at least 64 entries so GTS updates aren't too
	 * frequent.
	 */
	if (hwentries < 64)
		hwentries = 64;

	memsize = hwentries * sizeof(*chp->cq.queue);

	/*
	 * memsize must be a multiple of the page size if its a user cq.
	 */
	if (udata)
		memsize = roundup(memsize, PAGE_SIZE);

	chp->cq.size = hwentries;
	chp->cq.memsize = memsize;
	chp->cq.vector = vector;

	ret = create_cq(&rhp->rdev, &chp->cq,
			ucontext ? &ucontext->uctx : &rhp->rdev.uctx,
			chp->wr_waitp);
	if (ret)
		goto err_free_skb;

	chp->rhp = rhp;
	chp->cq.size--;				/* status page */
	chp->ibcq.cqe = entries - 2;
	spin_lock_init(&chp->lock);
	spin_lock_init(&chp->comp_handler_lock);
	atomic_set(&chp->refcnt, 1);
	init_waitqueue_head(&chp->wait);
	ret = xa_insert_irq(&rhp->cqs, chp->cq.cqid, chp, GFP_KERNEL);
	if (ret)
		goto err_destroy_cq;

	if (ucontext) {
		ret = -ENOMEM;
		mm = kmalloc(sizeof(*mm), GFP_KERNEL);
		if (!mm)
			goto err_remove_handle;
		mm2 = kmalloc(sizeof(*mm2), GFP_KERNEL);
		if (!mm2)
			goto err_free_mm;

		memset(&uresp, 0, sizeof(uresp));
		uresp.qid_mask = rhp->rdev.rdma_res->cqmask;
		uresp.cqid = chp->cq.cqid;
		uresp.size = chp->cq.size;
		uresp.memsize = chp->cq.memsize;
		spin_lock(&ucontext->mmap_lock);
		uresp.key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.gts_key = ucontext->key;
		ucontext->key += PAGE_SIZE;

		spin_unlock(&ucontext->mmap_lock);
		ret = ib_copy_to_udata(udata, &uresp,
				       sizeof(uresp));
		if (ret)
			goto err_free_mm2;

		mm->key = uresp.key;
		mm->addr = virt_to_phys(chp->cq.queue);
		mm->vaddr = chp->cq.queue;
		mm->dma_addr = chp->cq.dma_addr;
		mm->len = chp->cq.memsize;
		insert_mmap(ucontext, mm);

		mm2->key = uresp.gts_key;
		mm2->addr = chp->cq.bar2_pa;
		mm2->len = PAGE_SIZE;
		mm2->vaddr = NULL;
		mm2->dma_addr = 0;
		insert_mmap(ucontext, mm2);
	}

	pr_debug("cqid 0x%0x chp 0x%llx size %u memsize %zu, dma_addr %pad vector %u\n",
		 chp->cq.cqid, (unsigned long long)chp, chp->cq.size, chp->cq.memsize,
		 &chp->cq.dma_addr, vector);
	return 0;
err_free_mm2:
	kfree(mm2);
err_free_mm:
	kfree(mm);
err_remove_handle:
	xa_erase_irq(&rhp->cqs, chp->cq.cqid);
err_destroy_cq:
	destroy_cq(&chp->rhp->rdev, &chp->cq,
		   ucontext ? &ucontext->uctx : &rhp->rdev.uctx,
		   chp->destroy_skb, chp->wr_waitp);
err_free_skb:
	kfree_skb(chp->destroy_skb);
err_free_wr_wait:
	chrd_put_wr_wait(chp->wr_waitp);
err_free_chp:
	return ret;
}

int chrd_resize_cq(struct ib_cq *cq, int cqe, struct ib_udata *udata)
{
	return -ENOSYS;
}

int chrd_arm_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct chrd_cq *chp;
	int ret = 0;
	unsigned long flag;

	chp = to_chrd_cq(ibcq);
	spin_lock_irqsave(&chp->lock, flag);
	t4_arm_cq(&chp->cq,
		  (flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED);
	if (flags & IB_CQ_REPORT_MISSED_EVENTS)
		ret = t4_cq_notempty(&chp->cq);
	spin_unlock_irqrestore(&chp->lock, flag);
	return ret;
}

void chrd_flush_srqidx(struct chrd_qp *qhp, u32 srqidx)
{
	struct chrd_cq *rchp = to_chrd_cq(qhp->ibqp.recv_cq);
	unsigned long flag;

	/* locking heirarchy: cq lock first, then qp lock. */
	spin_lock_irqsave(&rchp->lock, flag);
	spin_lock(&qhp->lock);

	/* create a SRQ RECV CQE for srqidx */
	insert_recv_cqe(qhp, &rchp->cq, srqidx);

	spin_unlock(&qhp->lock);
	spin_unlock_irqrestore(&rchp->lock, flag);
}
