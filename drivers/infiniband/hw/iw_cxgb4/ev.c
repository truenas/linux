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
#include <linux/kconfig.h>
#include <linux/slab.h>
#include <linux/mman.h>
#include <net/sock.h>

#include "iw_cxgb4.h"

static void print_tpte(struct chrd_dev *dev, u32 stag)
{
	int ret;
	struct fw_ri_tpte tpte;
	
	ret = cxgb4_read_tpte(dev->rdev.lldi.ports[0], stag,
			      (__be32 *)&tpte);
	if (ret) {
		pr_err("%s cxgb4_read_tpte err %d\n", __func__,
		       ret);
		return; 
	}
	pr_err("stag idx 0x%x valid %d key 0x%x state %d pdid %d "
	       "perm 0x%x ps %d len 0x%llx va 0x%llx\n",
	       stag & 0xffffff00,
	       G_FW_RI_TPTE_VALID(ntohl(tpte.valid_to_pdid)),
	       G_FW_RI_TPTE_STAGKEY(ntohl(tpte.valid_to_pdid)),
	       G_FW_RI_TPTE_STAGSTATE(ntohl(tpte.valid_to_pdid)),
	       G_FW_RI_TPTE_PDID(ntohl(tpte.valid_to_pdid)),
	       G_FW_RI_TPTE_PERM(ntohl(tpte.locread_to_qpid)),
	       G_FW_RI_TPTE_PS(ntohl(tpte.locread_to_qpid)),
	       ((u64)ntohl(tpte.len_hi) << 32) | ntohl(tpte.len_lo),
	       ((u64)ntohl(tpte.va_hi) << 32) | ntohl(tpte.va_lo_fbo));
}

static void dump_err_cqe(struct chrd_dev *dev, struct t4_cqe *err_cqe)
{
	__be64 *p = (void *)err_cqe;
	
	pr_err("AE qpid %d opcode %d status 0x%x "
	       "type %d len 0x%x wrid.hi 0x%x wrid.lo 0x%x\n",
	       CQE_QPID(err_cqe), CQE_OPCODE(err_cqe),
	       CQE_STATUS(err_cqe), CQE_TYPE(err_cqe), ntohl(err_cqe->len),
	       CQE_WRID_HI(err_cqe), CQE_WRID_LOW(err_cqe));

	pr_err("%016llx %016llx %016llx %016llx\n",
	       be64_to_cpu(p[0]), be64_to_cpu(p[1]), be64_to_cpu(p[2]),
	       be64_to_cpu(p[3]));

	/*
	 * Ingress WRITE and READ_RESP errors provide
	 * the offending stag, so parse and log it.
	 */
	if (RQ_TYPE(err_cqe) && (CQE_OPCODE(err_cqe) == FW_RI_RDMA_WRITE ||
				 CQE_OPCODE(err_cqe) == FW_RI_READ_RESP))
		print_tpte(dev, CQE_WRID_STAG(err_cqe));

}

static void post_qp_event(struct chrd_dev *dev, struct chrd_cq *chp,
			  struct chrd_qp *qhp,
			  struct t4_cqe *err_cqe,
			  enum ib_event_type ib_event)
{
	struct ib_event event;
	struct chrd_common_qp_attributes attrs;
	unsigned long flag;

	dump_err_cqe(dev, err_cqe);

	if (qhp->attr.state == CHRD_QP_STATE_RTS) {
		attrs.next_state = CHRD_QP_STATE_TERMINATE;
	//	chrd_modify_iw_rc_qp(qhp, CHRD_QP_ATTR_NEXT_STATE, &attrs, 0);		/*Todo: Check the Commented Code */
	}

	event.event = ib_event;
	event.device = chp->ibcq.device;
	if (ib_event == IB_EVENT_CQ_ERR)
		event.element.cq = &chp->ibcq;
	else
		event.element.qp = &qhp->ibqp;
	if (qhp->ibqp.event_handler)
		(*qhp->ibqp.event_handler)(&event, qhp->ibqp.qp_context);

	if (t4_clear_cq_armed(&chp->cq, qhp->ibqp.uobject)) {
		spin_lock_irqsave(&chp->comp_handler_lock, flag);
		(*chp->ibcq.comp_handler)(&chp->ibcq, chp->ibcq.cq_context);
		spin_unlock_irqrestore(&chp->comp_handler_lock, flag);
	}
}

void chrd_ev_dispatch(struct chrd_dev *dev, struct t4_cqe *err_cqe)
{
	struct chrd_cq *chp;
	struct chrd_qp *qhp;
	u32 cqid;

	xa_lock_irq(&dev->qps);
	qhp = xa_load(&dev->qps, CQE_QPID(err_cqe));
	if (!qhp) {
		pr_err("BAD AE qpid 0x%x opcode %d status 0x%x type %d wrid.hi 0x%x wrid.lo 0x%x\n",
		       CQE_QPID(err_cqe),
		       CQE_OPCODE(err_cqe), CQE_STATUS(err_cqe),
		       CQE_TYPE(err_cqe), CQE_WRID_HI(err_cqe),
		       CQE_WRID_LOW(err_cqe));
		xa_unlock_irq(&dev->qps);
		goto out;
	}

	if (SQ_TYPE(err_cqe))
		cqid = qhp->attr.scq;
	else
		cqid = qhp->attr.rcq;
	chp = get_chp(dev, cqid);
	if (!chp) {
		pr_err("BAD AE cqid 0x%x qpid 0x%x opcode %d status 0x%x type %d wrid.hi 0x%x wrid.lo 0x%x\n",
		       cqid, CQE_QPID(err_cqe),
		       CQE_OPCODE(err_cqe), CQE_STATUS(err_cqe),
		       CQE_TYPE(err_cqe), CQE_WRID_HI(err_cqe),
		       CQE_WRID_LOW(err_cqe));
		xa_unlock_irq(&dev->qps);
		goto out;
	}

	chrd_iw_qp_add_ref(&qhp->ibqp);
	atomic_inc(&chp->refcnt);
	xa_unlock_irq(&dev->qps);

	/* Bad incoming write */
	if (RQ_TYPE(err_cqe) &&
	    (CQE_OPCODE(err_cqe) == FW_RI_RDMA_WRITE)) {
		post_qp_event(dev, chp, qhp, err_cqe, IB_EVENT_QP_REQ_ERR);
		goto done;
	}

	switch (CQE_STATUS(err_cqe)) {

	/* Completion Events */
	case T4_ERR_SUCCESS:
		pr_err("AE with status 0!\n");
		break;

	case T4_ERR_STAG:
	case T4_ERR_PDID:
	case T4_ERR_QPID:
	case T4_ERR_ACCESS:
	case T4_ERR_WRAP:
	case T4_ERR_BOUND:
	case T4_ERR_INVALIDATE_SHARED_MR:
	case T4_ERR_INVALIDATE_MR_WITH_MW_BOUND:
		post_qp_event(dev, chp, qhp, err_cqe, IB_EVENT_QP_ACCESS_ERR);
		break;

	/* Device Fatal Errors */
	case T4_ERR_ECC:
	case T4_ERR_ECC_PSTAG:
	case T4_ERR_INTERNAL_ERR:
		post_qp_event(dev, chp, qhp, err_cqe, IB_EVENT_DEVICE_FATAL);
		break;

	/* QP Fatal Errors */
	case T4_ERR_OUT_OF_RQE:
	case T4_ERR_PBL_ADDR_BOUND:
	case T4_ERR_CRC:
	case T4_ERR_MARKER:
	case T4_ERR_PDU_LEN_ERR:
	case T4_ERR_DDP_VERSION:
	case T4_ERR_RDMA_VERSION:
	case T4_ERR_OPCODE:
	case T4_ERR_DDP_QUEUE_NUM:
	case T4_ERR_MSN:
	case T4_ERR_TBIT:
	case T4_ERR_MO:
	case T4_ERR_MSN_GAP:
	case T4_ERR_MSN_RANGE:
	case T4_ERR_RQE_ADDR_BOUND:
	case T4_ERR_IRD_OVERFLOW:
		post_qp_event(dev, chp, qhp, err_cqe, IB_EVENT_QP_FATAL);
		break;

	default:
		pr_err("Unknown T4 status 0x%x QPID 0x%x\n",
		       CQE_STATUS(err_cqe), qhp->wq.sq.qid);
		post_qp_event(dev, chp, qhp, err_cqe, IB_EVENT_QP_FATAL);
		break;
	}
done:
	if (atomic_dec_and_test(&chp->refcnt))
		wake_up(&chp->wait);
	chrd_iw_qp_rem_ref(&qhp->ibqp);
out:
	return;
}

static enum obj_type get_raw_qpsrq(struct chrd_dev *dev, u32 qid,
				   struct chrd_raw_qp **rqp,
				   struct chrd_raw_srq **srq)
{
	enum obj_type ret = UNKNOWN;
	struct db_fcl *f = xa_load(&dev->rawiqs, qid);
	if (f) {
		ret = f->type;
		if (ret == RAW_QP)
			*rqp = fcl_to_chrd_raw_qp(f);
		else {
			*srq = fcl_to_chrd_raw_srq(f);
		}
	}
	return ret;
}

int chrd_ev_handler(struct chrd_dev *dev, u32 qid, u32 pidx)
{
	struct chrd_cq *chp;
	struct chrd_raw_qp *rqp = NULL;
	struct chrd_raw_srq *srq;
	enum obj_type type;
	unsigned long flag;

	/*
	 * RDMA CQ Event
	 */
	xa_lock_irqsave(&dev->cqs, flag);
	chp = xa_load(&dev->cqs, qid);
	if (chp) {
		atomic_inc(&chp->refcnt);
		xa_unlock_irqrestore(&dev->cqs, flag);
		t4_clear_cq_armed(&chp->cq, chp->ibcq.uobject);
		spin_lock_irqsave(&chp->comp_handler_lock, flag);
		(*chp->ibcq.comp_handler)(&chp->ibcq, chp->ibcq.cq_context);
		spin_unlock_irqrestore(&chp->comp_handler_lock, flag);
		if (atomic_dec_and_test(&chp->refcnt))
			wake_up(&chp->wait);
		return 0;
	}
	xa_unlock_irqrestore(&dev->cqs, flag);

	/*
	 * WD IQ Event
	 */
	type = get_raw_qpsrq(dev, qid, &rqp, &srq);
	switch (type) {
	case RAW_QP:
		t4_clear_iq_armed(&rqp->iq);
		(*rqp->rcq->ibcq.comp_handler)(&rqp->rcq->ibcq,
					       rqp->rcq->ibcq.cq_context);
		break;
	case RAW_SRQ: {
		struct rss_header *rss;
		u32 fidx;
		
		/*
		 * The indirect interrupt IQE includes the IQID and PIDX of the
		 * target IQ that received the pkt.  From the rss flit of the
		 * target IQ IQE we get the filter TID used to place the pkt.
		 * The filter TID is mapped back to a CQ that receives the 
		 * completion event. Whew...
		 */
		rss = (void *)srq->iq.desc + pidx * T4_IQE_LEN;
		fidx = be32_to_cpu(rss->hash_val) -
		       dev->rdev.lldi.uld_tids.ftids.start +
		       dev->rdev.lldi.uld_tids.hpftids.size;
		chp = fidx2cq(dev, fidx);
		if (chp) {
			t4_clear_iq_armed(&srq->iq);
			(*chp->ibcq.comp_handler)(&chp->ibcq,
						  chp->ibcq.cq_context);
		} else
			pr_err("%s cannot find endpoint for fidx "
			       "%u iqid %u!\n", __func__, fidx, qid);
		break;
	}
	default:
		pr_err("%s unknown iqid %d queue type %d\n",
		       __func__, qid, (int)type);
		
	}
	return 0;
}
