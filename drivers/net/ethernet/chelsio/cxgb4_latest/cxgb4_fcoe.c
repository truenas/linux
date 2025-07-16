/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2011-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifdef CONFIG_PO_FCOE

#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/gfp.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/fc/fc_fs.h>
#include <scsi/fc/fc_fcoe.h>
#include <scsi/libfc.h>
#include <scsi/libfcoe.h>

#include "t4_hw.h"
#include "common.h"
#include "t4_regs.h"
#include "t4_regs_values.h"
#include "t4_msg.h"
#include "t4fw_interface.h"

bool cxgb_fcoe_sof_eof_supported(struct adapter *adap, struct sk_buff *skb)
{
	struct fcoe_hdr *fcoeh = (struct fcoe_hdr *)skb_network_header(skb);
	u8 sof = fcoeh->fcoe_sof;
	u8 eof = 0;

	if ((sof != FC_SOF_I3) && (sof != FC_SOF_N3)) {
		dev_err(adap->pdev_dev, "Unsupported SOF 0x%x\n", sof);
		return 0;
	}

	skb_copy_bits(skb, skb->len - 4, &eof, 1);

	if ((eof != FC_EOF_N) && (eof != FC_EOF_T)) {
		dev_err(adap->pdev_dev, "Unsupported EOF 0x%x\n", eof);
		return 0;
	}

	return 1;
}

static inline struct cxgb_fcoe_ddp *
cxgb_fcoe_lookup_ddp(struct port_info *pi, unsigned int tid)
{
	struct adapter *adap = pi->adapter;
	struct cxgb_fcoe *fcoe = &pi->fcoe;
	struct cxgb_fcoe_ddp *ddp;
	u16 xid;

	if (tid >= adap->tidinfo.tids.size) {
		dev_err(adap->pdev_dev, "tid %x out of bounds\n", tid);
		return NULL;
	}

	xid = adap->uld.tid2xid[tid];

	if (xid >= CXGB_FCOE_MAX_XCHGS_PORT) {
		dev_err(adap->pdev_dev, "xid %x out of bounds, tid:%x\n",
			xid, tid);
		return NULL;
	}

	ddp = &fcoe->ddp[xid];

	if ((fcoe->flags & CXGB_FCOE_ENABLED) && (ddp->tid == tid) && ddp->sgl)
		return ddp;

	return NULL;
}

static inline struct sk_buff *
cxgb_fcoe_init_skb(struct adapter *adapter, u16 xid, struct port_info *pi,
		   struct cxgb_fcoe_ddp *ddp, struct cpl_fcoe_hdr *cfcoe_hdr,
		   struct sge_eth_rxq *rxq)
{
	struct sk_buff *skb;
	struct ethhdr *eh;
	struct fcoe_crc_eof *cp;
	struct fc_frame_header *fh;
	unsigned int hlen;		/* fcoe header length */
	unsigned int tlen;		/* fcoe trailer length */
	unsigned int elen;		/* eth header excluding vlan */
	unsigned int fclen;		/* fc header len */
	u8 rctl;
	struct fcoe_hdr *hp;

	elen = sizeof(struct ethhdr);
	hlen = sizeof(struct fcoe_hdr);
	fclen = sizeof(struct fc_frame_header);
	tlen = sizeof(struct fcoe_crc_eof);

	skb = dev_alloc_skb(elen + hlen + fclen + tlen);
	if (!skb)
		return NULL;

	rctl = G_FCOE_FCHDR_RCTL(be32_to_cpu(cfcoe_hdr->rctl_fctl));

	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = htons(ETH_P_FCOE);
	skb->dev = adapter->port[pi->port_id];

	eh = (struct ethhdr *)skb_put(skb, elen);
	memcpy(eh->h_source, ddp->h_dest, ETH_ALEN);
	memcpy(eh->h_dest, ddp->h_source, ETH_ALEN);
	eh->h_proto = htons(ETH_P_FCOE);

	hp = (struct fcoe_hdr *)skb_put(skb, hlen);
	memset(hp, 0, sizeof(*hp));
	if (FC_FCOE_VER)
		FC_FCOE_ENCAPS_VER(hp, FC_FCOE_VER);
	hp->fcoe_sof = cfcoe_hdr->sof;

	fh = (struct fc_frame_header *)skb_put(skb, fclen);
	fh->fh_r_ctl = rctl;
	memcpy(fh->fh_d_id, &ddp->h_source[3], 3);
	memcpy(fh->fh_s_id, ddp->d_id, 3);

	fh->fh_cs_ctl = cfcoe_hdr->cs_ctl;
	fh->fh_type = cfcoe_hdr->type;
	memcpy(fh->fh_f_ctl, ((char *)&cfcoe_hdr->rctl_fctl) + 1, 3);
	fh->fh_seq_id = cfcoe_hdr->seq_id;
	fh->fh_df_ctl = cfcoe_hdr->df_ctl;
	fh->fh_seq_cnt = cfcoe_hdr->seq_cnt;
	fh->fh_ox_id = cfcoe_hdr->oxid;
	fh->fh_rx_id = htons(xid);
	fh->fh_parm_offset = cfcoe_hdr->param;

	cp = (struct fcoe_crc_eof *)skb_put(skb, tlen);

	memset(cp, 0, sizeof(*cp));
	cp->fcoe_eof = cfcoe_hdr->eof;

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, sizeof(*eh));
	__skb_pull(skb, sizeof(*eh));
	skb_record_rx_queue(skb, rxq->rspq.idx);

	return skb;
}

static inline void
cxgb_fcoe_cpl_fcoe_hdr(struct port_info *pi, struct sge_rspq *q,
		       struct cpl_fcoe_hdr *cfcoe_hdr)
{
	struct adapter *adap = pi->adapter;
	struct sk_buff *skb;
	struct cxgb_fcoe_ddp *ddp;
	struct sge_eth_rxq *rxq = container_of(q, struct sge_eth_rxq, rspq);
	unsigned int tid = GET_TID(cfcoe_hdr);
	u32 fctl;

	ddp = cxgb_fcoe_lookup_ddp(pi, tid);
	if (!ddp)
		return;

	if (ddp->flags & CXGB_FCOE_DDP_ERROR)
		return;

	fctl = G_FCOE_FCHDR_FCTL(be32_to_cpu(cfcoe_hdr->rctl_fctl));

	ddp->ddp_len += ntohs(cfcoe_hdr->len);

	/* Send skb only on transfer of sequence initiative (last frame) */
	if ((fctl & (FC_FC_SEQ_INIT | FC_FC_END_SEQ)) !=
					(FC_FC_SEQ_INIT | FC_FC_END_SEQ))
		return;

	/* Synth a skb */
	skb = cxgb_fcoe_init_skb(adap, ddp->xid, pi, ddp, cfcoe_hdr, rxq);
	if (unlikely(!skb)) {
		ddp->flags |= CXGB_FCOE_DDP_ERROR;
		return;
	}

	if (ddp->vlan_tci)
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), ddp->vlan_tci);

	netif_receive_skb(skb);
}

static void cxgb_fcoe_cpl_rx_fcoe_ddp(struct port_info *pi,
				      struct cpl_rx_fcoe_ddp *cfcoe_ddp)
{
	struct adapter *adap = pi->adapter;
	struct cxgb_fcoe_ddp *ddp;
	unsigned int tid = GET_TID(cfcoe_ddp);

	ddp = cxgb_fcoe_lookup_ddp(pi, tid);
	if (!ddp)
		return;

	dev_warn(adap->pdev_dev, "DDP Error, xid:%x tid:%x report:%x"
		 " vld:%x\n", ddp->xid, tid,
		 be32_to_cpu(cfcoe_ddp->ddp_report),
		 be32_to_cpu(cfcoe_ddp->ddpvld));

	ddp->flags |= CXGB_FCOE_DDP_ERROR;
}

int cxgb_fcoe_rx_handler(struct sge_rspq *q, const __be64 *rsp)
{
	struct port_info *pi = netdev_priv(q->netdev);

	switch (*(u8 *)rsp) {
	case CPL_FCOE_HDR:
		cxgb_fcoe_cpl_fcoe_hdr(pi, q,
				       (struct cpl_fcoe_hdr *)&rsp[1]);
		break;
	case CPL_RX_FCOE_DDP:
		cxgb_fcoe_cpl_rx_fcoe_ddp(pi,
					  (struct cpl_rx_fcoe_ddp *)&rsp[1]);
		break;
	case CPL_FCOE_DATA:
		break;
	default:
		return 0;
	}

	return 1;
}

/**
 * cxgb_fcoe_alloc_ppods - Allocate page pods
 * @adap: adapter
 * @n: number of page pods to allocate
 *
 * Returns -1 on failure or the page pod tag
 */
static inline int
cxgb_fcoe_alloc_ppods(struct adapter *adap, unsigned int n)
{
	unsigned int i, j;

	if (unlikely(!adap->uld.ppod_map))
		return -1;

	spin_lock_bh(&adap->uld.ppod_map_lock);

	/*
	 * Look for n consecutive available page pods.
	 * Make sure to guard from scanning beyond the table.
	 */
	for (i = 0; i + n - 1 < adap->uld.vres.fcoe_nppods; ) {
		for (j = 0; j < n; ++j)		/* scan ppod_map[i..i+n-1] */
			if (adap->uld.ppod_map[i + j]) {
				i = i + j + 1;
				goto next;
			}

		memset(&adap->uld.ppod_map[i], 1, n);   /* allocate range */
		spin_unlock_bh(&adap->uld.ppod_map_lock);
		return i;
next:
		;
	}

	spin_unlock_bh(&adap->uld.ppod_map_lock);
	return -1;
}

void
cxgb_fcoe_free_ppods(struct adapter *adap, unsigned int tag, unsigned int n)
{
	spin_lock_bh(&adap->uld.ppod_map_lock);
	memset(&adap->uld.ppod_map[tag], 0, n);
	spin_unlock_bh(&adap->uld.ppod_map_lock);
}

static inline void cxgb_fcoe_clear_ddp(struct cxgb_fcoe_ddp *ddp)
{
	ddp->sgl = NULL;
	ddp->sgc = 0;
	ddp->first_pg_off = 0;
	ddp->nppods = 0;
	ddp->ppod_tag = 0;
	ddp->xfer_len = 0;
	ddp->ddp_len = 0;
	ddp->npages = 0;
	ddp->flags = 0;
}

void cxgb_fcoe_cpl_act_open_rpl(struct adapter *adap, unsigned int atid,
				unsigned int tid, unsigned int status)
{
	u16 xid = CXGB_FCOE_GET_XID(atid);
	u8 port_id = CXGB_FCOE_GET_PORTID(atid);
	struct port_info *pi = adap2pinfo(adap, port_id);
	struct cxgb_fcoe *fcoe = &pi->fcoe;
	struct cxgb_fcoe_ddp *ddp = &fcoe->ddp[xid];

	if ((status == CPL_ERR_NONE) &&
	    (tid < adap->tidinfo.tids.size)) {
		ddp->tid = tid;
		ddp->flags |= CXGB_FCOE_DDP_TID_VALID;
		adap->uld.tid2xid[tid] = xid;
	} else
		dev_err(adap->pdev_dev, "tid allocation failed xid 0x%x status 0x%x\n",
			xid, status);

	complete(fcoe->cmpl);
}

static int cxgb_fcoe_alloc_tid(struct port_info *pi, u16 xid)
{
	struct adapter *adap = pi->adapter;
	struct cxgb_fcoe *fcoe = &pi->fcoe;
	struct cxgb_fcoe_ddp *ddp = &fcoe->ddp[xid];
	struct tp_params *tp = &adap->params.tp;
	struct cpl_t5_act_open_req *req;
	struct sk_buff *skb;
	unsigned int qid_atid = xid;

	skb = alloc_skb(sizeof(*req), GFP_KERNEL);
	if (!skb)
		return 1;

	qid_atid |= BIT(CXGB_FCOE_ATID);
	qid_atid |= (pi->port_id << CXGB_FCOE_SHIFT_PORTID);
	qid_atid |= (adap->sge.fw_evtq.abs_id << 14);

	req = (struct cpl_t5_act_open_req *)__skb_put(skb, sizeof(*req));
	memset(req, 0, sizeof(*req));

	INIT_TP_WR(req, 0);
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_ACT_OPEN_REQ, qid_atid));

	req->peer_port = cpu_to_be16(xid);
	req->opt0 = cpu_to_be64(V_ULP_MODE(ULP_MODE_FCOE) |
			F_NON_OFFLOAD | F_NO_CONG | V_TX_CHAN(pi->tx_chan) |
			V_RCV_BUFSIZ(M_RCV_BUFSIZ) | V_L2T_IDX(0));

	req->params = cpu_to_be64(V_FILTER_TUPLE(
				(pi->port_id << tp->port_shift) |
				(1 << tp->fcoe_shift)) | F_AOPEN_FCOEMASK);

	if (t4_mgmt_tx(adap, skb) == NET_XMIT_DROP)
		return 1;

	wait_for_completion(fcoe->cmpl);

	reinit_completion(fcoe->cmpl);

	if (!(ddp->flags & CXGB_FCOE_DDP_TID_VALID))
		return 1;

	return 0;
}

static void cxgb_fcoe_free_tid(struct port_info *pi, u16 xid)
{
	struct adapter *adap = pi->adapter;
	struct cxgb_fcoe *fcoe = &pi->fcoe;
	struct cxgb_fcoe_ddp *ddp = &fcoe->ddp[xid];
	struct cpl_tid_release *req;
	struct sk_buff *skb;
	unsigned int len = ALIGN(sizeof(*req), 16);

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return;

	req = (struct cpl_tid_release *)__skb_put(skb, len);
	memset(req, 0, len);

	INIT_TP_WR(req, 0);
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_TID_RELEASE, ddp->tid));

	t4_mgmt_tx(adap, skb);
}

static void cxgb_fcoe_free_ddp(struct port_info *pi, u16 xid)
{
	struct cxgb_fcoe *fcoe = &pi->fcoe;
	struct cxgb_fcoe_ddp *ddp;
	u16 i;

	for (i = 0; i < xid; i++) {
		ddp = &fcoe->ddp[i];
		kfree(ddp->ppod_gl);
		cxgb_fcoe_free_tid(pi, i);
	}
}

/*
 * Return the # of page pods needed to accommodate a # of pages.
 */
static inline unsigned int pages2ppods(unsigned int pages)
{
	return (pages + PPOD_PAGES - 1) / PPOD_PAGES +
			CXGB_FCOE_NUM_SENTINEL_PPODS;
}

/**
 * cxgb_fcoe_ddp_setup - setup ddp in target mode
 * @netdev: net device
 * @xid: exchange id
 * @sgl: scatterlist
 * @sgc: number of scatterlist elements
 *
 * Returns 1 on success or 0 on failure.
 */
int cxgb_fcoe_ddp_setup(struct net_device *netdev, u16 xid,
			struct scatterlist *sgl, unsigned int sgc)
{
	struct port_info *pi;
	struct adapter *adap;
	struct cxgb_fcoe *fcoe;
	struct cxgb_fcoe_ddp *ddp;
	struct scatterlist *sg;
	unsigned int nsge, i, j, len, lastsize, nppods;
	static const unsigned int bufflen = PAGE_SIZE;
	unsigned int firstoff = 0;
	unsigned int thisoff = 0;
	unsigned int thislen = 0;
	unsigned int totlen = 0;
	int tag;
	dma_addr_t addr;

	if (!netdev || !sgl)
		return 0;

	pi = netdev_priv(netdev);
	adap = pi->adapter;
	fcoe = &pi->fcoe;

	if (!(fcoe->flags & CXGB_FCOE_ENABLED))
		return 0;

	if (xid >= CXGB_FCOE_MAX_XCHGS_PORT) {
		dev_warn(adap->pdev_dev, "xid=0x%x out-of-range\n", xid);
		return 0;
	}

	ddp = &fcoe->ddp[xid];
	if (ddp->sgl) {
		dev_err(adap->pdev_dev, "xid 0x%x w/ non-null sgl%p nents=%d\n",
			xid, ddp->sgl, ddp->sgc);
		return 0;
	}

	cxgb_fcoe_clear_ddp(ddp);

	nsge = dma_map_sg(adap->pdev_dev, sgl, sgc, DMA_FROM_DEVICE);
	if (nsge == 0) {
		dev_err(adap->pdev_dev, "xid 0x%x DMA map error\n", xid);
		return 0;
	}

	j = 0;
	for_each_sg(sgl, sg, nsge, i) {
		addr = sg_dma_address(sg);
		len = sg_dma_len(sg);
		totlen += len;
		while (len) {
			/* max number of pages allowed in one DDP transfer */
			if (j >= CXGB_FCOE_MAX_PAGE_CNT) {
				dev_err(adap->pdev_dev,
					"xid=%x:%d,%d,%d:addr=%llx "
					"not enough descriptors\n",
					xid, i, j, nsge, (u64)addr);
				goto out_noddp;
			}

			/* get the offset of length of current buffer */
			thisoff = addr & ((dma_addr_t)bufflen - 1);
			thislen = min((bufflen - thisoff), len);

			/*
			 * all but the 1st buffer (j == 0)
			 * must be aligned on bufflen
			 */
			if ((j != 0) && (thisoff))
				goto out_noddp;
			/*
			 * all but the last buffer
			 * ((i == (nsge - 1)) && (thislen == len))
			 * must end at bufflen
			 */
			if (((i != (nsge - 1)) || (thislen != len)) &&
			    ((thislen + thisoff) != bufflen))
				goto out_noddp;

			ddp->ppod_gl[j] = (dma_addr_t)(addr - thisoff);

			/* only the first buffer may have none-zero offset */
			if (j == 0)
				firstoff = thisoff;
			len -= thislen;
			addr += thislen;
			j++;
		}
	}
	/* only the last buffer may have non-full bufflen */
	lastsize = thisoff + thislen;

	nppods = pages2ppods(j);
	tag = cxgb_fcoe_alloc_ppods(adap, nppods);
	if (tag < 0) {
		dev_err(adap->pdev_dev, "Failed to allocate %d ppods"
					" xid:0x%x\n", nppods, xid);
		goto out_noddp;
	}

	/* Should be offset by TOE's ppods */
	tag += adap->uld.vres.toe_nppods;

	ddp->sgl = sgl;
	ddp->sgc = sgc;
	ddp->xfer_len = totlen;
	ddp->first_pg_off = firstoff;
	ddp->nppods = nppods;
	ddp->npages = j;
	ddp->ppod_tag = tag;

	return 1;

out_noddp:
	dma_unmap_sg(adap->pdev_dev, sgl, sgc, DMA_FROM_DEVICE);
	return 0;
}

/**
 * cxgb_fcoe_ddp_done - complete DDP
 * @netdev: net device
 * @xid: exchange id
 *
 * Returns length of data directly placed in bytes.
 */
int cxgb_fcoe_ddp_done(struct net_device *netdev, u16 xid)
{
	struct port_info *pi;
	struct adapter *adap;
	struct cxgb_fcoe *fcoe;
	struct cxgb_fcoe_ddp *ddp;
	int len = 0;

	if (!netdev)
		return 0;

	pi = netdev_priv(netdev);
	adap = pi->adapter;

	if (xid >= CXGB_FCOE_MAX_XCHGS_PORT) {
		dev_warn(adap->pdev_dev, "ddp_done: xid%x out-of-range\n", xid);
		return 0;
	}

	fcoe = &pi->fcoe;
	ddp = &fcoe->ddp[xid];
	if (!ddp->sgl) {
		dev_err(adap->pdev_dev, "ddp_done: xid %x with null sgl\n",
			xid);
		return 0;
	}

	if (!(ddp->flags & CXGB_FCOE_DDP_ERROR))
		len = ddp->ddp_len;

	cxgb_fcoe_free_ppods(adap, ddp->ppod_tag - adap->uld.vres.toe_nppods,
			     ddp->nppods);

	if (ddp->sgl)
		dma_unmap_sg(adap->pdev_dev, ddp->sgl, ddp->sgc, DMA_FROM_DEVICE);

	cxgb_fcoe_clear_ddp(ddp);

	return len;
}

/**
 * cxgb_fcoe_enable - enable FCoE offload features
 * @netdev: net device
 *
 * Returns 0 on success and -EINVAL on failure.
 */
int cxgb_fcoe_enable(struct net_device *netdev)
{
	struct port_info *pi = netdev_priv(netdev);
	struct adapter *adap = pi->adapter;
	struct tp_params *tp = &adap->params.tp;
	struct cxgb_fcoe *fcoe;
	struct cxgb_fcoe_ddp *ddp;
	struct completion cmpl;
	int rc = -EINVAL;
	u16 xid;

	if (is_t4(adap->params.chip))
		return rc;

	if (!(adap->flags & FULL_INIT_DONE))
		return rc;

	if ((tp->port_shift < 0) || (tp->fcoe_shift < 0))
		return rc;

	if (!adap->uld.ppod_map || !adap->uld.tid2xid) {
		dev_warn(adap->pdev_dev, "FCoE Offload resources "
			 " unavailable\n");
		return rc;
	}

	dev_info(adap->pdev_dev, "Enabling FCoE offload features\n");

	init_completion(&cmpl);

	fcoe = &pi->fcoe;
	fcoe->cmpl = &cmpl;
	memset(fcoe->ddp, 0, sizeof(*ddp) * CXGB_FCOE_MAX_XCHGS_PORT);

	for (xid = 0; xid < CXGB_FCOE_MAX_XCHGS_PORT; xid++) {
		ddp = &fcoe->ddp[xid];
		ddp->xid = xid;
		ddp->ppod_gl = kzalloc(CXGB_FCOE_MAX_PAGE_CNT *
							sizeof(dma_addr_t),
							GFP_KERNEL);
		if (!ddp->ppod_gl) {
			dev_warn(adap->pdev_dev, "Unable to allocate "
				 "pagepod gatherlists xid 0x%x\n", xid);
			cxgb_fcoe_free_ddp(pi, xid);
			return rc;
		}

		if (cxgb_fcoe_alloc_tid(pi, xid)) {
			dev_warn(adap->pdev_dev, "Unable to allocate "
				 "tid xid 0x%x\n", xid);
			kfree(ddp->ppod_gl);
			cxgb_fcoe_free_ddp(pi, xid);
			return rc;
		}
	}

	netdev->features |= NETIF_F_FCOE_CRC;
	netdev->vlan_features |= NETIF_F_FCOE_CRC;
	netdev->features |= NETIF_F_FCOE_MTU;
	netdev->vlan_features |= NETIF_F_FCOE_MTU;

	netdev->fcoe_ddp_xid = CXGB_FCOE_MAX_XCHGS_PORT - 1;

	netdev_features_change(netdev);

	fcoe->flags |= CXGB_FCOE_ENABLED;

	return 0;
}

/**
 * cxgb_fcoe_disable - disable FCoE offload
 * @netdev: net device
 *
 * Returns 0 on success or -EINVAL on error.
 */
int cxgb_fcoe_disable(struct net_device *netdev)
{
	struct port_info *pi;
	struct adapter *adap;
	struct cxgb_fcoe *fcoe;

	pi = netdev_priv(netdev);
	adap = pi->adapter;
	fcoe = &pi->fcoe;

	if (!(fcoe->flags & CXGB_FCOE_ENABLED))
		return -EINVAL;

	dev_info(adap->pdev_dev, "Disabling FCoE offload features\n");

	fcoe->flags &= ~CXGB_FCOE_ENABLED;

	netdev->features &= ~NETIF_F_FCOE_CRC;
	netdev->vlan_features &= ~NETIF_F_FCOE_CRC;
	netdev->features &= ~NETIF_F_FCOE_MTU;
	netdev->vlan_features &= ~NETIF_F_FCOE_MTU;
	netdev->fcoe_ddp_xid = 0;

	netdev_features_change(netdev);

	cxgb_fcoe_free_ddp(pi, CXGB_FCOE_MAX_XCHGS_PORT);

	return 0;
}

void cxgb_fcoe_init_ddp(struct adapter *adap)
{
	u32 tot_ppods = adap->uld.vres.ddp.size / CXGB_FCOE_PPOD_SIZE;
	u32 fcoe_ddp_size, fcoe_ddp_start;

	adap->uld.vres.fcoe_nppods = tot_ppods / 2;
	adap->uld.vres.toe_nppods = tot_ppods - adap->uld.vres.fcoe_nppods;

	adap->uld.vres.ddp.size = adap->uld.vres.toe_nppods *
				  CXGB_FCOE_PPOD_SIZE;
	fcoe_ddp_size = adap->uld.vres.fcoe_nppods * CXGB_FCOE_PPOD_SIZE;
	fcoe_ddp_start = adap->uld.vres.ddp.start + adap->uld.vres.ddp.size;

	dev_info(adap->pdev_dev, "TOE ddp start:0x%x size:%d nppods:%d\n",
		 adap->uld.vres.ddp.start, adap->uld.vres.ddp.size,
		 adap->uld.vres.toe_nppods);
	dev_info(adap->pdev_dev,
		 "FCoE ddp start:0x%x size:%d nppods:%d tids:%d\n",
		 fcoe_ddp_start, fcoe_ddp_size, adap->uld.vres.fcoe_nppods,
		 adap->tidinfo.tids.size);

	spin_lock_init(&adap->uld.ppod_map_lock);

	adap->uld.ppod_map = kzalloc(adap->uld.vres.fcoe_nppods, GFP_KERNEL);
	if (!adap->uld.ppod_map)
		return;

	adap->uld.tid2xid = kcalloc(adap->tidinfo.tids.size, sizeof(u16),
				    GFP_KERNEL);
	if (!adap->uld.tid2xid) {
		kfree(adap->uld.ppod_map);
		adap->uld.ppod_map = NULL;
	}
}

void cxgb_fcoe_exit_ddp(struct adapter *adap)
{
	kfree(adap->uld.ppod_map);
	kfree(adap->uld.tid2xid);
	adap->uld.ppod_map = NULL;
	adap->uld.tid2xid = NULL;
}

#endif /* CONFIG_PO_FCOE */
