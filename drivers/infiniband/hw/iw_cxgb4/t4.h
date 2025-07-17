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
#ifndef __T4_H__
#define __T4_H__

#include "t4_regs.h"
#include "t4_regs_values.h"
#include "t4_tcb.h"
#include "t4_msg.h"
#include "t4fw_interface.h"

#define T4_MAX_MR_SIZE (~0ULL)
#define T4_PAGESIZE_MASK 0xffff000  /* 4KB-128MB */
#define T4_STAG_UNSET 0xffffffff
#define T4_FW_MAJ 0

struct t4_status_page {
	__be32 rsvd1;	/* flit 0 - hw owns */
	__be16 rsvd2;
	__be16 qid;
	__be16 cidx;
	__be16 pidx;
	u8 qp_err;	/* flit 1 - sw owns */
	u8 db_off;
	u8 cq_armed;
	u8 pad;
	u16 host_wq_pidx;
	u16 host_cidx;
	u16 host_pidx;
	u16 pad2;
	u32 srqidx;
};

#define T4_RQT_ENTRY_SHIFT 6
#define T4_EQ_ENTRY_SIZE 64

#define T4_SQ_NUM_SLOTS 5
#define T4_SQ_NUM_BYTES (T4_EQ_ENTRY_SIZE * T4_SQ_NUM_SLOTS)
#define T4_MAX_SEND_SGE ((T4_SQ_NUM_BYTES - sizeof(struct fw_ri_send_wr) - \
			sizeof(struct fw_ri_isgl)) / sizeof(struct fw_ri_sge))
#define T4_MAX_SEND_INLINE ((T4_SQ_NUM_BYTES - sizeof(struct fw_ri_send_wr) - \
			sizeof(struct fw_ri_immd)))
#define T4_MAX_WRITE_INLINE ((T4_SQ_NUM_BYTES - \
			sizeof(struct fw_ri_rdma_write_wr) - \
			sizeof(struct fw_ri_immd)))
#define T4_MAX_WRITE_SGE ((T4_SQ_NUM_BYTES - \
			sizeof(struct fw_ri_rdma_write_wr) - \
			sizeof(struct fw_ri_isgl)) / sizeof(struct fw_ri_sge))
#define T4_MAX_FR_IMMD ((T4_SQ_NUM_BYTES - sizeof(struct fw_ri_fr_nsmr_wr) - \
			sizeof(struct fw_ri_immd)) & ~31UL)
#define T4_MAX_FR_IMMD_DEPTH (T4_MAX_FR_IMMD / sizeof(u64))
#define T4_MAX_FR_DSGL 1024
#define T4_MAX_FR_DSGL_DEPTH (T4_MAX_FR_DSGL / sizeof(u64))
#define T4_MAX_FR_FW_DSGL 4096
#define T4_MAX_FR_FW_DSGL_DEPTH (T4_MAX_FR_FW_DSGL / sizeof(u64))

#define T4_RQ_NUM_SLOTS 2
#define T4_RQ_NUM_BYTES (T4_EQ_ENTRY_SIZE * T4_RQ_NUM_SLOTS)
#define T4_MAX_RECV_SGE 4
#define T7_MAX_RD_SGE 4
#define GSI_MAX_RECV_SGE 1
#define ISER_SQ_SIZE 523

#define T4_WRITE_CMPL_MAX_SGL 4

union t4_wr {
	struct fw_ri_res_wr res;
	struct fw_ri_wr ri;
	struct fw_ri_rdma_write_wr write;
	struct fw_ri_v2_rdma_write_wr v2_write;
	struct fw_ri_send_wr send;
	struct fw_ri_v2_send_wr v2_send;
	struct fw_ri_v2_ud_send_wr v2_ud_send;
	struct fw_ri_rdma_read_wr read;
	struct fw_ri_v2_rdma_read_wr v2_read;
	struct fw_ri_v2_atomic_wr v2_atomic;
	struct fw_ri_bind_mw_wr bind;
	struct fw_ri_v2_bind_mw_wr v2_bind;
	struct fw_ri_fr_nsmr_wr fr;
	struct fw_ri_v2_fr_nsmr_wr v2_fr;
	struct fw_ri_fr_nsmr_tpte_wr fr_tpte;
	struct fw_ri_inv_lstag_wr inv;
	struct fw_ri_rdma_write_cmpl_wr write_cmpl;
	struct t4_status_page status;
	__be64 flits[T4_EQ_ENTRY_SIZE / sizeof(__be64) * T4_SQ_NUM_SLOTS];
};

union t4_recv_wr {
	struct fw_ri_recv_wr recv;
	struct t4_status_page status;
	__be64 flits[T4_EQ_ENTRY_SIZE / sizeof(__be64) * T4_RQ_NUM_SLOTS];
};

static inline void init_wr_hdr(union t4_wr *wqe, u16 wrid,
			       enum fw_wr_opcodes opcode, u8 flags, u8 len16)
{
	wqe->send.opcode = (u8)opcode;
	wqe->send.flags = flags;
	wqe->send.wrid = wrid;
	wqe->send.r1[0] = 0;
	wqe->send.r1[1] = 0;
	wqe->send.r1[2] = 0;
	wqe->send.len16 = len16;
}

/* CQE/AE status codes */
#define T4_ERR_SUCCESS                     0x0
#define T4_ERR_STAG                        0x1	/* STAG invalid: either the */
						/* STAG is offlimt, being 0, */
						/* or STAG_key mismatch */
#define T4_ERR_PDID                        0x2	/* PDID mismatch */
#define T4_ERR_QPID                        0x3	/* QPID mismatch */
#define T4_ERR_ACCESS                      0x4	/* Invalid access right */
#define T4_ERR_WRAP                        0x5	/* Wrap error */
#define T4_ERR_BOUND                       0x6	/* base and bounds voilation */
#define T4_ERR_INVALIDATE_SHARED_MR        0x7	/* attempt to invalidate a  */
						/* shared memory region */
#define T4_ERR_INVALIDATE_MR_WITH_MW_BOUND 0x8	/* attempt to invalidate a  */
						/* shared memory region */
#define T4_ERR_ECC                         0x9	/* ECC error detected */
#define T4_ERR_ECC_PSTAG                   0xA	/* ECC error detected when  */
						/* reading PSTAG for a MW  */
						/* Invalidate */
#define T4_ERR_PBL_ADDR_BOUND              0xB	/* pbl addr out of bounds:  */
						/* software error */
#define T4_ERR_SWFLUSH			   0xC	/* SW FLUSHED */
#define T4_ERR_CRC                         0x10 /* CRC error */
#define T4_ERR_MARKER                      0x11 /* Marker error */
#define T4_ERR_PDU_LEN_ERR                 0x12 /* invalid PDU length */
#define T4_ERR_OUT_OF_RQE                  0x13 /* out of RQE */
#define T4_ERR_DDP_VERSION                 0x14 /* wrong DDP version */
#define T4_ERR_RDMA_VERSION                0x15 /* wrong RDMA version */
#define T4_ERR_OPCODE                      0x16 /* invalid rdma opcode */
#define T4_ERR_DDP_QUEUE_NUM               0x17 /* invalid ddp queue number */
#define T4_ERR_MSN                         0x18 /* MSN error */
#define T4_ERR_TBIT                        0x19 /* tag bit not set correctly */
#define T4_ERR_MO                          0x1A /* MO not 0 for TERMINATE  */
						/* or READ_REQ */
#define T4_ERR_MSN_GAP                     0x1B
#define T4_ERR_MSN_RANGE                   0x1C
#define T4_ERR_IRD_OVERFLOW                0x1D
#define T4_ERR_RQE_ADDR_BOUND              0x1E /* RQE addr out of bounds:  */
						/* software error */
#define T4_ERR_INTERNAL_ERR                0x1F /* internal error (opcode  */
						/* mismatch) */
/*
 * CQE defs
 */

/*
 * 64B CQE entries.
 */
struct t4_cqe {
	struct rss_header rss;
	__be32 header;
	__be32 len;
	union {
		struct {
			__be32 stag;
			__be32 msn;
		} rcqe;
		struct {
			u32 stag;
			u16 nada2;
			u16 cidx;
		} scqe;
		struct {
			__be32 wrid_hi;
			__be32 wrid_low;
		} gen;
		struct {
			__be32 stag;
			__be32 msn;
			__be32 reserved;
			__be32 abs_rqe_idx;
		} srcqe;
		u64 drain_cookie;
		struct {
			__be32 mo;
			__be32 msn;
			__u64 imm_data;
		} imm_data_rcqe;
		struct {
			__be32 stag;
			__be32 msn;
			__be32 v2_header;
			__be32 abs_rqe_idx;
		} v2_com;
		//Todo : fix this later ASAP, by correctly pointing to immdata for rocev2
	} u;
	__be64 v2_ext_hi;
	__be64 v2_ext_lo;
	__be64 reserved;
	__be64 bits_type_ts;
};

/* macros for flit 0 of the cqe */

#define S_CQE_QPID        12
#define M_CQE_QPID        0xFFFFF
#define G_CQE_QPID(x)     ((((x) >> S_CQE_QPID)) & M_CQE_QPID)
#define V_CQE_QPID(x)	  ((x)<<S_CQE_QPID)

#define S_CQE_SWCQE       11
#define M_CQE_SWCQE       0x1
#define G_CQE_SWCQE(x)    ((((x) >> S_CQE_SWCQE)) & M_CQE_SWCQE)
#define V_CQE_SWCQE(x)	  ((x)<<S_CQE_SWCQE)

#define S_CQE_DRAIN       10
#define M_CQE_DRAIN       0x1
#define G_CQE_DRAIN(x)    ((((x) >> S_CQE_DRAIN)) & M_CQE_DRAIN)
#define V_CQE_DRAIN(x)	  ((x)<<S_CQE_DRAIN)

#define S_CQE_STATUS      5
#define M_CQE_STATUS      0x1F
#define G_CQE_STATUS(x)   ((((x) >> S_CQE_STATUS)) & M_CQE_STATUS)
#define V_CQE_STATUS(x)   ((x)<<S_CQE_STATUS)

#define S_CQE_TYPE        4
#define M_CQE_TYPE        0x1
#define G_CQE_TYPE(x)     ((((x) >> S_CQE_TYPE)) & M_CQE_TYPE)
#define V_CQE_TYPE(x)     ((x)<<S_CQE_TYPE)

#define S_CQE_OPCODE      0
#define M_CQE_OPCODE      0xF
#define G_CQE_OPCODE(x)   ((((x) >> S_CQE_OPCODE)) & M_CQE_OPCODE)
#define V_CQE_OPCODE(x)   ((x)<<S_CQE_OPCODE)

#define SW_CQE(x)         (G_CQE_SWCQE(be32_to_cpu((x)->header)))
#define DRAIN_CQE(x)      (G_CQE_DRAIN(be32_to_cpu((x)->header)))
#define CQE_QPID(x)       (G_CQE_QPID(be32_to_cpu((x)->header)))
#define CQE_TYPE(x)       (G_CQE_TYPE(be32_to_cpu((x)->header)))
#define SQ_TYPE(x)	  (CQE_TYPE((x)))
#define RQ_TYPE(x)	  (!CQE_TYPE((x)))
#define CQE_STATUS(x)     (G_CQE_STATUS(be32_to_cpu((x)->header)))
#define CQE_OPCODE(x)     (G_CQE_OPCODE(be32_to_cpu((x)->header)))

#define S_CQE_V2_OPCODE      24
#define M_CQE_V2_OPCODE      0x7F
#define G_CQE_V2_OPCODE(x)   ((((x) >> S_CQE_V2_OPCODE)) & M_CQE_V2_OPCODE)
#define V_CQE_V2_OPCODE(x)   ((x)<<S_CQE_V2_OPCODE)
#define CQE_V2_OPCODE(x)     (G_CQE_V2_OPCODE(be32_to_cpu((x)->u.v2_com.v2_header)))

#define S_CQE_V2_VLAN      48
#define M_CQE_V2_VLAN      0xFFFF
#define G_CQE_V2_VLAN(x)   ((((x) >> S_CQE_V2_VLAN)) & M_CQE_V2_VLAN)
#define CQE_V2_VLAN(x)     (G_CQE_V2_VLAN(be64_to_cpu((x)->v2_ext_hi)))

#define CQE_SEND_OPCODE(x)( \
	(G_CQE_OPCODE(be32_to_cpu((x)->header)) == FW_RI_SEND) || \
	(G_CQE_OPCODE(be32_to_cpu((x)->header)) == FW_RI_SEND_WITH_SE) || \
	(G_CQE_OPCODE(be32_to_cpu((x)->header)) == FW_RI_SEND_WITH_INV) || \
	(G_CQE_OPCODE(be32_to_cpu((x)->header)) == FW_RI_SEND_WITH_SE_INV))

#define CQE_LEN(x)        (be32_to_cpu((x)->len))

/* used for RQ completion processing */
#define CQE_WRID_STAG(x)  (be32_to_cpu((x)->u.rcqe.stag))
#define CQE_WRID_MSN(x)   (be32_to_cpu((x)->u.rcqe.msn))
#define CQE_ABS_RQE_IDX(x) (be32_to_cpu((x)->u.srcqe.abs_rqe_idx))
#define CQE_IMM_DATA(x)   ((x)->u.imm_data_rcqe.imm_data)

/* used for SQ completion processing */
#define CQE_WRID_SQ_IDX(x)	((x)->u.scqe.cidx)
#define CQE_WRID_FR_STAG(x)     (be32_to_cpu((x)->u.scqe.stag))

/* generic accessor macros */
#define CQE_WRID_HI(x)		(be32_to_cpu((x)->u.gen.wrid_hi))
#define CQE_WRID_LOW(x)		(be32_to_cpu((x)->u.gen.wrid_low))
#define CQE_DRAIN_COOKIE(x)	(x)->u.drain_cookie;

/* macros for flit 3 of the cqe */
#define S_CQE_GENBIT	63
#define M_CQE_GENBIT	0x1
#define G_CQE_GENBIT(x)	(((x) >> S_CQE_GENBIT) & M_CQE_GENBIT)
#define V_CQE_GENBIT(x) ((x)<<S_CQE_GENBIT)

#define S_CQE_OVFBIT	62
#define M_CQE_OVFBIT	0x1
#define G_CQE_OVFBIT(x)	((((x) >> S_CQE_OVFBIT)) & M_CQE_OVFBIT)

#define S_CQE_IQTYPE	60
#define M_CQE_IQTYPE	0x3
#define G_CQE_IQTYPE(x)	((((x) >> S_CQE_IQTYPE)) & M_CQE_IQTYPE)

#define M_CQE_TS	0x0fffffffffffffffULL
#define G_CQE_TS(x)	((x) & M_CQE_TS)

#define CQE_OVFBIT(x)	((unsigned)G_CQE_OVFBIT(be64_to_cpu((x)->bits_type_ts)))
#define CQE_GENBIT(x)	((unsigned)G_CQE_GENBIT(be64_to_cpu((x)->bits_type_ts)))
#define CQE_TS(x)	(G_CQE_TS(be64_to_cpu((x)->bits_type_ts)))

struct t4_swsqe {
	u64			wr_id;
	struct t4_cqe		cqe;
	int			read_len;
	int			opcode;
	int			complete;
	int			signaled;
	u16			idx;
	int                     flushed;
	ktime_t                 host_time;
	u64			sge_ts;
};

static inline pgprot_t t4_pgprot_wc(pgprot_t prot)
{
#if defined(__i386__) || defined(__x86_64__) || defined(CONFIG_PPC64)
        return pgprot_writecombine(prot);
#else
        return pgprot_noncached(prot);
#endif
}

enum {
	T4_SQ_ONCHIP = (1<<0),
};

struct t4_sq {
	union t4_wr *queue;
	dma_addr_t dma_addr;
	unsigned long phys_addr;
	DEFINE_DMA_UNMAP_ADDR(mapping);
	struct t4_swsqe *sw_sq;
	struct t4_swsqe *oldest_read;
	void __iomem *bar2_va;
	u64 bar2_pa;
	size_t memsize;
	u32 bar2_qid;
	u32 qid;
	u16 in_use;
	u16 size;
	u16 cidx;
	u16 pidx;
	u16 wq_pidx;
	u16 wq_pidx_inc;
	u16 flags;
	short flush_cidx;
};

struct t4_swrqe {
	u64 wr_id;
	ktime_t host_time;
	u64 sge_ts;
	struct ib_sge sg_list[GSI_MAX_RECV_SGE];
	int valid;
};

struct t4_rq {
	union  t4_recv_wr *queue;
	dma_addr_t dma_addr;
	DEFINE_DMA_UNMAP_ADDR(mapping);
	struct t4_swrqe *sw_rq;
	void __iomem *bar2_va;
	u64 bar2_pa;
	size_t memsize;
	u32 bar2_qid;
	u32 qid;
	u32 msn;
	u32 rqt_hwaddr;
	u16 rqt_size;
	u16 in_use;
	u16 size;
	u16 cidx;
	u16 pidx;
	u16 wq_pidx;
	u16 wq_pidx_inc;
};

struct t4_wq {
	struct t4_sq sq;
	struct t4_rq rq;
	void __iomem *db;
	struct chrd_rdev *rdev;
	int flushed;
	u8 *qp_errp;
	u32 *srqidxp;
};

struct t4_srq_pending_wr {
	u64 wr_id;
	union t4_recv_wr wqe;
	u8 len16;
};

struct t4_srq {
	union  t4_recv_wr *queue;
	dma_addr_t dma_addr;
	DEFINE_DMA_UNMAP_ADDR(mapping);
	struct t4_swrqe *sw_rq;
	void __iomem *bar2_va;
	u64 bar2_pa;
	size_t memsize;
	u32 bar2_qid;
	u32 qid;
	u32 msn;
	u32 rqt_hwaddr;
	u32 rqt_abs_idx;
	u16 rqt_size;
	u16 in_use;
	u16 size;
	u16 cidx;
	u16 pidx;
	u16 wq_pidx;
	u16 wq_pidx_inc;
	struct t4_srq_pending_wr *pending_wrs;
	u16 pending_cidx;
	u16 pending_pidx;
	u16 pending_in_use;
	u16 ooo_count;
};

static inline u32 t4_srq_avail(struct t4_srq *srq)
{
	return srq->size - 1 - srq->in_use;
}

static inline int t4_srq_empty(struct t4_srq *srq)
{
	return srq->in_use == 0;
}

static inline int t4_srq_cidx_at_end(struct t4_srq *srq)
{
	if (srq->cidx < srq->pidx)
		return srq->cidx == (srq->pidx - 1);
	else
		return srq->cidx == (srq->size - 1) && srq->pidx == 0;
}

static inline int t4_srq_wrs_pending(struct t4_srq *srq)
{
	return srq->pending_cidx != srq->pending_pidx;
}

static inline void t4_srq_produce(struct t4_srq *srq, u8 len16)
{
	srq->in_use++;
	if (++srq->pidx == srq->size)
		srq->pidx = 0;
	srq->wq_pidx += DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);
	if (srq->wq_pidx >= srq->size * T4_RQ_NUM_SLOTS)
		srq->wq_pidx %= srq->size * T4_RQ_NUM_SLOTS;
	srq->queue[srq->size].status.host_pidx = srq->pidx;
}

static inline void t4_srq_produce_pending_wr(struct t4_srq *srq)
{
	srq->pending_in_use++;
	srq->in_use++;
	if (++srq->pending_pidx == srq->size)
		srq->pending_pidx = 0;
}

static inline void t4_srq_consume_pending_wr(struct t4_srq *srq)
{
	srq->pending_in_use--;
	srq->in_use--;
	if (++srq->pending_cidx == srq->size)
		srq->pending_cidx = 0;
}

static inline void t4_srq_produce_ooo(struct t4_srq *srq)
{
	srq->in_use--;
	srq->ooo_count++;
}

static inline void t4_srq_consume_ooo(struct t4_srq *srq)
{
	srq->cidx++;
	if (srq->cidx == srq->size)
		srq->cidx  = 0;
	srq->queue[srq->size].status.host_cidx = srq->cidx;
	srq->ooo_count--;
}

static inline void t4_srq_consume(struct t4_srq *srq)
{
	srq->in_use--;
	if (++srq->cidx == srq->size)
		srq->cidx = 0;
	srq->queue[srq->size].status.host_cidx = srq->cidx;
}

static inline int t4_rqes_posted(struct t4_wq *wq)
{
	return wq->rq.in_use;
}

static inline int t4_rq_empty(struct t4_wq *wq)
{
	return wq->rq.in_use == 0;
}

static inline int t4_rq_full(struct t4_wq *wq)
{
	return wq->rq.in_use == (wq->rq.size - 1);
}

static inline u32 t4_rq_avail(struct t4_wq *wq)
{
	return wq->rq.size - 1 - wq->rq.in_use;
}

static inline void t4_sw_rq_produce(struct t4_wq *wq)
{
	wq->rq.in_use++;
	if (++wq->rq.pidx == wq->rq.size)
		wq->rq.pidx = 0;
}

static inline void t4_rq_produce(struct t4_wq *wq, u8 len16)
{
	t4_sw_rq_produce(wq);
	wq->rq.wq_pidx += DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);
	if (wq->rq.wq_pidx >= wq->rq.size * T4_RQ_NUM_SLOTS)
		wq->rq.wq_pidx %= wq->rq.size * T4_RQ_NUM_SLOTS;
}

static inline void t4_rq_consume(struct t4_wq *wq)
{
	wq->rq.in_use--;
	if (++wq->rq.cidx == wq->rq.size)
		wq->rq.cidx = 0;
}

static inline u16 t4_rq_host_wq_pidx(struct t4_wq *wq)
{
	return wq->rq.queue[wq->rq.size].status.host_wq_pidx;
}

static inline u16 t4_rq_wq_size(struct t4_wq *wq)
{
		return wq->rq.size * T4_RQ_NUM_SLOTS;
}

static inline int t4_sq_onchip(struct t4_sq *sq)
{
	return sq->flags & T4_SQ_ONCHIP;
}

static inline int t4_sq_empty(struct t4_wq *wq)
{
	return wq->sq.in_use == 0;
}

static inline int t4_sq_full(struct t4_wq *wq)
{
	return wq->sq.in_use == (wq->sq.size - 1);
}

static inline u32 t4_sq_avail(struct t4_wq *wq)
{
	return wq->sq.size - 1 - wq->sq.in_use;
}

static inline void t4_sq_produce(struct t4_wq *wq, u8 len16)
{
	wq->sq.in_use++;
	if (++wq->sq.pidx == wq->sq.size)
		wq->sq.pidx = 0;
	wq->sq.wq_pidx += DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);
	if (wq->sq.wq_pidx >= wq->sq.size * T4_SQ_NUM_SLOTS)
		wq->sq.wq_pidx %= wq->sq.size * T4_SQ_NUM_SLOTS;
}

static inline void t4_sq_consume(struct t4_wq *wq)
{
	if (wq->sq.cidx == wq->sq.flush_cidx)
		wq->sq.flush_cidx = -1;
	wq->sq.in_use--;
	if (++wq->sq.cidx == wq->sq.size)
		wq->sq.cidx = 0;
}

static inline u16 t4_sq_host_wq_pidx(struct t4_wq *wq)
{
	return wq->sq.queue[wq->sq.size].status.host_wq_pidx;
}

static inline u16 t4_sq_wq_size(struct t4_wq *wq)
{
		return wq->sq.size * T4_SQ_NUM_SLOTS;
}

/* This function copies 64 byte coalesced work request to
 * memory mapped BAR2 space. For coalesced WR SGE fetches
 * data from the FIFO instead of from Host.
 */
static inline void pio_copy(u64 __iomem *dst, u64 *src)
{
	int count = 8;

	while (count) {
		__raw_writeq((__force u64)cpu_to_le64(*src), dst);
		src++;
		dst++;
		count--;
	}
}
extern int t5_en_wc;

static inline void t4_ring_srq_db(struct t4_srq *srq, u16 inc, u8 len16,
				 union t4_recv_wr *wqe)
{
	wmb();
	if (t5_en_wc && inc == 1 && srq->bar2_qid == 0 && wqe) {
		pr_debug("WC srq->pidx = %d; len16=%d\n", srq->pidx, len16);
		pio_copy((u64 __iomem *)
			 (srq->bar2_va + SGE_UDB_WCDOORBELL),
			 (void *)wqe);
	} else {
		pr_debug("DB srq->pidx = %d; len16=%d\n", srq->pidx, len16);
		__raw_writel((__force u32)cpu_to_le32(V_PIDX_T5(inc) | V_QID(srq->bar2_qid)),
			     srq->bar2_va + SGE_UDB_KDOORBELL);
	}
	wmb();
	return;
}

static inline void t4_ring_sq_db(struct t4_wq *wq, u16 inc,
				 union t4_wr *wqe)
{
	wmb();
	if (wq->sq.bar2_va) {
		if (t5_en_wc && inc == 1 && wq->sq.bar2_qid == 0 && wqe) {
			pr_debug("WC wq->sq.pidx = %d\n", wq->sq.pidx);
			pio_copy((u64 __iomem *)
				 (wq->sq.bar2_va + SGE_UDB_WCDOORBELL),
				 (u64 *)wqe);
		} else {
			pr_debug("DB wq->sq.pidx = %d\n", wq->sq.pidx);
			__raw_writel((__force u32)cpu_to_le32(V_PIDX_T5(inc) | V_QID(wq->sq.bar2_qid)),
				     wq->sq.bar2_va + SGE_UDB_KDOORBELL);
		}
		wmb();
		return;
	}
	writel(V_QID(wq->sq.qid) | V_PIDX(inc), wq->db);
}

static inline void t4_ring_rq_db(struct t4_wq *wq, u16 inc,
				 union t4_recv_wr *wqe)
{
	wmb();
	if (wq->rq.bar2_va) {
		if (t5_en_wc && inc == 1 && wq->rq.bar2_qid == 0 && wqe) {
			pr_debug("WC wq->rq.pidx = %d\n", wq->rq.pidx);
			pio_copy((u64 __iomem *)
				 (wq->rq.bar2_va + SGE_UDB_WCDOORBELL),
				 (void *)wqe);
		} else {
			pr_debug("DB wq->rq.pidx = %d\n", wq->rq.pidx);
			__raw_writel((__force u32)cpu_to_le32(V_PIDX_T5(inc) | V_QID(wq->rq.bar2_qid)),
				     wq->rq.bar2_va + SGE_UDB_KDOORBELL);
		}
		wmb();
		return;
	}
	writel(V_QID(wq->rq.qid) | V_PIDX(inc), wq->db);
}

static inline int t4_wq_in_error(struct t4_wq *wq)
{
	return *wq->qp_errp;
}

static inline void t4_set_wq_in_error(struct t4_wq *wq, u32 srqidx)
{
	if (srqidx)
		*wq->srqidxp = srqidx;
	*wq->qp_errp = 1;
}

static inline void t4_disable_wq_db(struct t4_wq *wq)
{
	wq->rq.queue[wq->rq.size].status.db_off = 1;
}

static inline void t4_enable_wq_db(struct t4_wq *wq)
{
	wq->rq.queue[wq->rq.size].status.db_off = 0;
}

static inline int t4_wq_db_enabled(struct t4_wq *wq)
{
	return !wq->rq.queue[wq->rq.size].status.db_off;
}

enum t4_cq_flags {
	CQ_ARMED	= 1,
};

struct t4_cq {
	struct t4_cqe *queue;
	dma_addr_t dma_addr;
	DEFINE_DMA_UNMAP_ADDR(mapping);
	struct t4_cqe *sw_queue;
	void __iomem *gts;
	void __iomem *bar2_va;
	u64 bar2_pa;
	u32 bar2_qid;
	struct chrd_rdev *rdev;
	size_t memsize;
	__be64 bits_type_ts;
	u32 cqid;
	u32 qid_mask;
	int vector;
	u16 size; /* including status page */
	u16 cidx;
	u16 sw_pidx;
	u16 sw_cidx;
	u16 sw_in_use;
	u16 cidx_inc;
	u8 gen;
	u8 error;
	unsigned long flags;
};

static inline void write_gts(struct t4_cq *cq, u32 val)
{
	if (cq->bar2_va)
		writel(val | V_INGRESSQID(cq->bar2_qid),
		       cq->bar2_va + SGE_UDB_GTS);
	else
		writel(val | V_INGRESSQID(cq->cqid), cq->gts);
}

static inline int t4_arm_cq(struct t4_cq *cq, int se)
{
	u32 val;

	set_bit(CQ_ARMED, &cq->flags);
	while (cq->cidx_inc > M_CIDXINC) {
		val = V_SEINTARM(0) | V_CIDXINC(M_CIDXINC) | V_TIMERREG(7);
		write_gts(cq, val);
		cq->cidx_inc -= M_CIDXINC;
	}
	val = V_SEINTARM(se) | V_CIDXINC(cq->cidx_inc) | V_TIMERREG(6);
	write_gts(cq, val);
	cq->cidx_inc = 0;
	return 0;
}

static inline void t4_swcq_produce(struct t4_cq *cq)
{
	cq->sw_in_use++;
	pr_debug("Check!\n");
	if (cq->sw_in_use == cq->size) {
		pr_warn("%s cxgb4 sw cq overflow cqid %u\n", __func__, cq->cqid);
		cq->error = 1;
		cq->sw_in_use--;
		return;
	}
	if (++cq->sw_pidx == cq->size)
		cq->sw_pidx = 0;
}

static inline void t4_swcq_consume(struct t4_cq *cq)
{
	cq->sw_in_use--;
	pr_debug("Check!\n");
	if (++cq->sw_cidx == cq->size)
		cq->sw_cidx = 0;
}

static inline void t4_hwcq_consume(struct t4_cq *cq)
{
	cq->bits_type_ts = cq->queue[cq->cidx].bits_type_ts;
	if (++cq->cidx_inc == (cq->size >> 4) || cq->cidx_inc == M_CIDXINC) {
		u32 val;

		val = V_SEINTARM(0) | V_CIDXINC(cq->cidx_inc) | V_TIMERREG(7);
		write_gts(cq, val);
		cq->cidx_inc = 0;
	}
	if (++cq->cidx == cq->size) {
		cq->cidx = 0;
		cq->gen ^= 1;
	}
}

static inline int t4_valid_cqe(struct t4_cq *cq, struct t4_cqe *cqe)
{
	return (CQE_GENBIT(cqe) == cq->gen);
}

static inline int t4_cq_notempty(struct t4_cq *cq)
{
	return cq->sw_in_use || t4_valid_cqe(cq, &cq->queue[cq->cidx]);
}

static inline int t4_next_hw_cqe(struct t4_cq *cq, struct t4_cqe **cqe)
{
	int ret;
	u16 prev_cidx;

	if (cq->cidx == 0)
		prev_cidx = cq->size - 1;
	else
		prev_cidx = cq->cidx - 1;

	if (cq->queue[prev_cidx].bits_type_ts != cq->bits_type_ts) {
		ret = -EOVERFLOW;
		cq->error = 1;
		pr_err("cq overflow cqid %u\n", cq->cqid);
	} else if (t4_valid_cqe(cq, &cq->queue[cq->cidx])) {
		rmb();
		*cqe = &cq->queue[cq->cidx];
		ret = 0;
	} else
		ret = -ENODATA;
	return ret;
}

static inline struct t4_cqe *t4_next_sw_cqe(struct t4_cq *cq)
{
	if (cq->sw_in_use == cq->size) {
		pr_warn("%s cxgb4 sw cq overflow cqid %u\n", __func__, cq->cqid);
		cq->error = 1;
		return NULL;
	}
	if (cq->sw_in_use)
		return &cq->sw_queue[cq->sw_cidx];
	return NULL;
}

static inline int t4_next_cqe(struct t4_cq *cq, struct t4_cqe **cqe)
{
	int ret = 0;

	if (cq->error) {
		ret = -ENODATA;
	} else if (cq->sw_in_use) {
		pr_debug("sw_in_use %d\n", cq->sw_in_use);
		//BUG_ON(1); // disable for iwarp
		*cqe = &cq->sw_queue[cq->sw_cidx];
	} else {
		ret = t4_next_hw_cqe(cq, cqe);
		pr_debug("ret %d\n", ret);
	}
	return ret;
}

static inline int t4_cq_in_error(struct t4_cq *cq)
{
	return ((struct t4_status_page *)&cq->queue[cq->size])->qp_err;
}

static inline void t4_set_cq_in_error(struct t4_cq *cq)
{
	((struct t4_status_page *)&cq->queue[cq->size])->qp_err = 1;
}

static inline int t4_clear_cq_armed(struct t4_cq *cq, bool user)
{
	if (unlikely(user))
		((struct t4_status_page *)&cq->queue[cq->size])->cq_armed = 0;
	else
		return test_and_clear_bit(CQ_ARMED, &cq->flags);

	return 0;
}

struct fl_sw_desc {
	void *buf;
	dma_addr_t dma_addr;
};

struct t4_fl {
	unsigned int avail;
	unsigned int pend_cred;
	unsigned int cidx;
	unsigned int pidx;
	unsigned int cntxt_id;
	unsigned int size;
	unsigned int memsize;
	struct fl_sw_desc *sdesc;
	__be64 *desc;
	dma_addr_t dma_addr;
	unsigned long phys_addr;
	void __iomem *db;
	u8 packed;
	u8 cong_drop;
	u16 pidx_inc;
};

static inline void t4_disable_fl_db(struct t4_fl *f)
{
	((struct t4_status_page *)&f->desc[f->size])->db_off = 1;
}

static inline void t4_enable_fl_db(struct t4_fl *f)
{
	((struct t4_status_page *)&f->desc[f->size])->db_off = 0;
}

static inline u16 t4_fl_host_wq_pidx(struct t4_fl *f)
{
	return ((struct t4_status_page *)&f->desc[f->size])->host_wq_pidx;
}

static inline u16 t4_fl_wq_size(struct t4_fl *f)
{
	return f->size;
}

#define T4_IQE_LEN 64

struct t4_iq {
	unsigned int cntxt_id;
	__be64 *desc;
	unsigned long phys_addr;
	dma_addr_t dma_addr;
	unsigned int size;
	unsigned int memsize;
};

static inline void t4_clear_iq_armed(struct t4_iq *iq)
{
	((struct t4_status_page *)
		((u8 *)iq->desc + iq->size * T4_IQE_LEN))->cq_armed = 0;
}

#define T4_TXQ_NUM_SLOTS 4
#define T4_TXQ_NUM_BYTES (T4_EQ_ENTRY_SIZE * T4_TXQ_NUM_SLOTS)
#define T4_MAX_TXQ_INLINE ((T4_TXQ_NUM_BYTES - \
			   sizeof(struct cpl_tx_pkt) - \
			   sizeof(struct fw_eth_tx_pkt_wr)))

struct t4_eth_tx_desc {
	__be64 flits[T4_EQ_ENTRY_SIZE / sizeof(__be64) *T4_TXQ_NUM_SLOTS];
};

struct t4_eth_txq {
	unsigned int size;
	unsigned int memsize;
	unsigned int cntxt_id;
	struct t4_eth_tx_desc *desc;
	dma_addr_t dma_addr;
	unsigned long phys_addr;
	unsigned int flags;
	u16 pidx_inc;
};

static inline u16 t4_txq_host_wq_pidx(struct t4_eth_txq *t)
{
	return ((struct t4_status_page *)&t->desc[t->size])->host_wq_pidx;
}

static inline u16 t4_txq_wq_size(struct t4_eth_txq *t)
{
	return t->size * T4_TXQ_NUM_SLOTS;
}

struct t4_dev_status_page
{
	u8 db_off;
	u8 wc_supported;
	u8 write_cmpl_supported;
	u8 pad2;
	u32 fid_base;
	u64 qp_start;
	u64 qp_size;
	u64 cq_start;
	u64 cq_size;
};
#endif
