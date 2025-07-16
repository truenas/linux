/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifdef INET_HASHFN
#include <net/inet_hashtables.h>
#endif

#include "common.h"
#include "t4_regs.h"
#include "t4_tcb.h"
#include "t4_msg.h"
#include "l2t.h"
#include "t4fw_interface.h"
#include "smt.h"
#include "clip_tbl.h"
#include "cxgb4_filter.h"
#include "t4_linux_fs.h"

unsigned int cxgb4_filter_num_tids(struct adapter *adap)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	return t->hpftids.size + t->ftids.size + t->hashtids.size +
	       t->hashcoll_tids.size;
}

static int cxgb4_filter_validate(struct net_device *dev,
				 struct ch_filter_specification *fs)
{
	struct adapter *adapter = netdev2adap(dev);
	u32 fconf, f_mask, iconf, chip_ver;
	bool unsupp;

	/* Check for unconfigured fields being used. */
	fconf = adapter->params.tp.vlan_pri_map;
	f_mask = adapter->params.tp.filter_mask;
	iconf = adapter->params.tp.ingress_config;
	chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);

#define S(_field) (fs->val._field || fs->mask._field)

	/* If cap is maskless then validate filter_mask else filter_mode */
#define U(_mask, _field) (!((fs->cap ? f_mask : fconf) & (_mask)) && S(_field))

	if (chip_ver >= CHELSIO_T7)
		unsupp = U(F_IPSECIDX, ipsecidx) || U(F_T7_FCOE, fcoe) ||
			 U(F_T7_PORT, iport) || U(F_T7_TOS, tos) ||
			 U(F_T7_ETHERTYPE, ethtype) ||
			 U(F_T7_MACMATCH, macidx) ||
			 U(F_T7_MPSHITTYPE, matchtype) ||
			 U(F_T7_FRAGMENTATION, frag) ||
			 U(F_T7_PROTOCOL, proto) ||
			 U(F_T7_VNIC_ID, pfvf_vld) ||
			 U(F_T7_VNIC_ID, ovlan_vld) ||
			 U(F_T7_VNIC_ID, encap_vld) ||
			 U(F_T7_VLAN, ivlan_vld) ||
			 U(F_ROCE, roce) || U(F_SYNONLY, synonly) ||
			 U(F_TCPFLAGS, tcpflags);
	else
		unsupp = U(F_FCOE, fcoe) || U(F_PORT, iport) ||
			 U(F_TOS, tos) || U(F_ETHERTYPE, ethtype) ||
			 U(F_MACMATCH, macidx) ||
			 U(F_MPSHITTYPE, matchtype) ||
			 U(F_FRAGMENTATION, frag) ||
			 U(F_PROTOCOL, proto) ||
			 U(F_VNIC_ID, pfvf_vld) ||
			 U(F_VNIC_ID, ovlan_vld) ||
			 U(F_VNIC_ID, encap_vld) ||
			 U(F_VLAN, ivlan_vld);

	if (unsupp)
		return -EOPNOTSUPP;

	/* T4 inconveniently uses the same W_FT_VNIC_ID bits for both the Outer
	 * VLAN Tag and PF/VF/VFvld fields based on F_VNIC being set
	 * in TP_INGRESS_CONFIG.  Hense the somewhat crazy checks
	 * below.  Additionally, since the T4 firmware interface also
	 * carries that overlap, we need to translate any PF/VF
	 * specification into that internal format below.
	 */
	if ((S(pfvf_vld) && S(ovlan_vld)) ||
	    (S(pfvf_vld) && S(encap_vld)) ||
	    (S(ovlan_vld) && S(encap_vld)))
		return -EOPNOTSUPP;
	if ((S(pfvf_vld) && !(iconf & F_VNIC)) ||
	    (S(ovlan_vld) && (iconf & F_VNIC)))
		return -EOPNOTSUPP;
	if (chip_ver <= CHELSIO_T6 &&
	    (S(ipsecidx) || S(roce) || S(synonly) || S(tcpflags)))
		return -EOPNOTSUPP;

	if (fs->val.pf > 0x7 || fs->val.vf > 0x7f)
		return -ERANGE;
	fs->mask.pf &= 0x7;
	fs->mask.vf &= 0x7f;

#undef S
#undef U

	if (fs->val.encap_vld && chip_ver < CHELSIO_T6)
		return -EOPNOTSUPP;

	/* Don't allow various trivially obvious bogus out-of-range
	 * values ...
	 */
	if (fs->val.iport >= adapter->params.nports)
		return -ERANGE;

	/* If the user is requesting that the filter action loop
	 * matching packets back out one of our ports, make sure that
	 * the egress port is in range.
	 */
	if (fs->action == FILTER_SWITCH &&
	    fs->eport >= adapter->params.nports) {
		/* In T6, loopback channel is supported, which starts from 4
		 * (NUM_UP_TSCH_CHANNEL_INSTANCES), in that case egress
		 * port can be 0-1 or 4-5.
		 */
		if (chip_ver > CHELSIO_T5) {
			if ((fs->eport >= adapter->params.nports &&
			     fs->eport < NUM_UP_TSCH_CHANNEL_INSTANCES) ||
			    (fs->eport >= (adapter->params.nports + 
			    		   NUM_UP_TSCH_CHANNEL_INSTANCES)))
				return -ERANGE;
		} else {
			return -ERANGE;
		}
	}

	/* T4 doesn't support removing VLAN Tags for loop back
	 * filters. Also, swapmac and NAT are not supported on T4.
	 */
	if (is_t4(adapter->params.chip) &&
	    fs->action == FILTER_SWITCH &&
	    (fs->newvlan == VLAN_REMOVE ||
	     fs->newvlan == VLAN_REWRITE))
		return -EOPNOTSUPP;

	if (is_t4(adapter->params.chip) &&
	    fs->action == FILTER_SWITCH &&
	    fs->swapmac)
		return -EOPNOTSUPP;

	if (is_t4(adapter->params.chip) &&
	    fs->action == FILTER_SWITCH &&
	    fs->nat_mode)
		return -EOPNOTSUPP;

	if (fs->drop_encap_hdr && chip_ver < CHELSIO_T6)
		return -EOPNOTSUPP;

	return 0;
}

static u8 cxgb4_hash_filter_get_tx_chan(struct adapter *adap,
					struct filter_entry *f)
{
	if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T6)
		return f->fs.eport & (NUM_UP_TSCH_CHANNEL_INSTANCES - 1);

	/* For T7, the Tx and Rx Channel are a single opaque field
	 * called just the "Channel". Hence, fill the Rx channel
	 * associated with the incoming port. The actual egress port
	 * itself is filled as part of TF_PEND_CTL1 and TF_PEND_CTL2
	 * TCB TFlags when the reply for the active open request is
	 * received.
	 */
	return cxgb4_port_rx_chan(adap->port[f->fs.val.iport]);
}

static u8 cxgb4_hash_filter_get_rx_chan(struct adapter *adap,
					struct filter_entry *f)
{
	if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T6)
		return cxgb4_port_e2cchan(f->dev);

	/* For T7, the Tx and Rx Channel are a single opaque field
	 * called just the "Channel". Hence, the legacy Rx channel
	 * field is deprecated and needs to be filled with 0.
	 */
	return 0;
}

static int cxgb4_filter_get_steerq(struct net_device *dev,
				   struct ch_filter_specification *fs)
{
	struct adapter *adapter = netdev2adap(dev);
	struct port_info *pi = netdev_priv(dev);

	/* If the user has requested steering matching Ingress Packets
	 * to a specific Queue Set, we need to make sure it's in range
	 * for the port and map that into the Absolute Queue ID of the
	 * Queue Set's Response Queue.
	 */
	if (!fs->dirsteer) {
		if (fs->iq)
			return -EINVAL;

		return 0;
	}

	/* If the iq id is greater than the number of qsets, then assume
	 * it is an absolute qid.
	 */
	if (fs->iq < pi->nqsets)
		return adapter->sge.ethrxq[pi->first_qset + fs->iq].rspq.abs_id;

	return fs->iq;
}

static void cxgb4_filter_hw_resources_free(struct adapter *adap,
					   struct filter_entry *f)
{
	struct port_info *pi = netdev_priv(f->dev);

	/* If the filter has loopback rewriting rules then we'll need to free
	 * any existing Layer Two Table (L2T) entries of the filter rule.  The
	 * firmware will handle freeing up any Source MAC Table (SMT) entries
	 * used for rewriting Source MAC Addresses in loopback rules.
	 */
	if (f->l2t) {
		cxgb4_l2t_release(f->l2t);
		f->l2t = NULL;
	}

	if (f->smt) {
		cxgb4_smt_release(f->smt);
		f->smt = NULL;
	}

	if (f->fs.val.encap_vld && f->fs.val.ovlan_vld) {
		cxgb_free_encap_mac_filt(adap, pi->viid,
					 f->fs.val.ovlan & 0x1ff, 0);
		f->fs.val.encap_vld = 0;
		f->fs.val.ovlan_vld = 0;
	}

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T6 && f->fs.type)
		cxgb4_clip_release_filter(f->dev, (const u32 *)&f->fs.val.lip,
					  (const u32 *)&f->fs.mask.lip, 1);
}

static int cxgb4_filter_match_parse(struct adapter *adap,
				    struct filter_entry *f)
{
	u32 iconf;
	int ret;

	iconf = adap->params.tp.ingress_config;
	if (iconf & F_VNIC) {
		f->fs.val.ovlan = (f->fs.val.pf << 13) | f->fs.val.vf;
		f->fs.mask.ovlan = (f->fs.mask.pf << 13) | f->fs.mask.vf;
		f->fs.val.ovlan_vld = f->fs.val.pfvf_vld;
		f->fs.mask.ovlan_vld = f->fs.mask.pfvf_vld;
	} else if ((iconf & F_USE_ENC_IDX) && f->fs.val.encap_vld) {
		struct port_info *pi = netdev_priv(f->dev);

		/* Allocate MPS TCAM entry for encapsulation MAC match */
		ret = cxgb_alloc_encap_mac_filt(adap, pi->viid,
						f->fs.val.encap_inner_mac,
						f->fs.mask.encap_inner_mac,
						f->fs.val.vni,
						f->fs.mask.vni, 0,
						f->fs.val.encap_lookup, 1);
		if (ret < 0)
			goto out_err;

		f->fs.val.ovlan = (f->fs.val.encap_matchtype << 9) | ret;
		f->fs.mask.ovlan = (f->fs.mask.encap_matchtype << 9) | 0x1ff;
		f->fs.val.ovlan_vld = 1;
		f->fs.mask.ovlan_vld = 1;
	}

	/* Issue a cxgb4_clip_get() only if we have non-zero IPv6
	 * address
	 */
	if (ipv6_addr_type((const struct in6_addr *)f->fs.val.lip) !=
	    IPV6_ADDR_ANY && f->fs.type) {
		ret = cxgb4_clip_get_filter(f->dev,
					    (const u32 *)&f->fs.val.lip,
					    (const u32 *)&f->fs.mask.lip, 1);
		if (ret)
			goto out_err;
	}

	return 0;

out_err:
	cxgb4_filter_hw_resources_free(adap, f);
	return ret;
}

static int cxgb4_filter_action_parse(struct adapter *adap,
				     struct filter_entry *f)
{
	int ret;

	/* If the new filter requires loopback Destination MAC and/or VLAN
	 * rewriting then we need to allocate a Layer 2 Table (L2T) entry for
	 * the filter.
	 */
	if (f->fs.newdmac || f->fs.newvlan == VLAN_INSERT ||
	    f->fs.newvlan == VLAN_REWRITE) {
		/* Allocate L2T entry for new filter */
		f->l2t = t4_l2t_alloc_switching(adap, f->fs.vlan, f->fs.eport,
						f->fs.dmac);
		if (!f->l2t) {
			ret = -ENOMEM;
			goto out_free;
		}
	}

	/* If the new filter requires loopback Source MAC rewriting then
	 * we need to allocate a SMT entry for the filter.
	 */
	if (f->fs.newsmac) {
		f->smt = cxgb4_smt_alloc_switching(f->dev, f->fs.smac);
		if (!f->smt) {
			ret = -ENOMEM;
			goto out_free;
		}
		f->smtidx = f->smt->hw_idx;
	}

	return 0;

out_free:
	cxgb4_filter_hw_resources_free(adap, f);
	return ret;
}

/* Clear a filter and release any of its resources that we own.  This also
 * clears the filter's "pending" status.
 */
static void cxgb4_filter_clear(struct adapter *adap, struct filter_entry *f)
{
	cxgb4_filter_hw_resources_free(adap, f);
	kfree(f);
}

static void cxgb4_atid_filter_clear(struct adapter *adap,
				    struct filter_entry *f)
{
	cxgb4_atid_free(adap, f->tid);
	cxgb4_filter_clear(adap, f);
}

static void cxgb4_hashtid_filter_clear(struct adapter *adap,
				       struct filter_entry *f)
{
	spinlock_t *lock; /* Lock for accessing ehash table */

	cxgb4_hashtid_remove(adap, 0, f->tid, f->fs.type);

	if (f->fs.val.proto == IPPROTO_UDP)
		lock = &adap->filter_udphash.ehash_filter_locks[f->filter_hash &
			adap->filter_udphash.ehash_filter_locks_mask];
	else
		lock = &adap->filter_tcphash.ehash_filter_locks[f->filter_hash &
			adap->filter_tcphash.ehash_filter_locks_mask];
	spin_lock_bh(lock);
	f->valid = 0;
	/* Remove hash entry */
	hlist_nulls_del_init_rcu(&f->filter_nulls_node);
	spin_unlock_bh(lock);

	cxgb4_filter_clear(adap, f);
}

static void cxgb4_ftid_filter_clear(struct adapter *adap,
				    struct filter_entry *f)
{
	cxgb4_ftid_free(adap, f->tid, f->fs.type);
	cxgb4_filter_clear(adap, f);
}

/* Return an error number if the indicated filter isn't writable ...
 */
static int cxgb4_filter_writable(struct filter_entry *f)
{
	if (f->locked)
		return -EPERM;
	if (f->pending)
		return -EBUSY;

	return 0;
}

/* Normal Filters
 */

/* Send a Work Request to write the filter at a specified index.  We construct
 * a Firmware Filter Work Request to have the work done and put the indicated
 * filter into "pending" mode which will prevent any further actions against
 * it till we get a reply from the firmware on the completion status of the
 * request.
 */
static int cxgb4_filter_normal_create_wr(struct adapter *adapter,
					 struct filter_entry *f, gfp_t gfp_mask)
{
	struct fw_filter2_wr *fwr;
	struct sk_buff *skb;
	u32 chip_ver;

	if (gfp_mask & GFP_ATOMIC) {
		skb = alloc_skb(sizeof(*fwr), GFP_ATOMIC);
		if (!skb)
			return -ENOMEM;
	} else {
		skb = alloc_skb(sizeof(*fwr), gfp_mask | __GFP_NOFAIL);
	}

	fwr = (struct fw_filter2_wr *)__skb_put(skb, sizeof(*fwr));
	memset(fwr, 0, sizeof(*fwr));

	chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);

	/* It would be nice to put most of the following in t4_hw.c but most
	 * of the work is translating the cxgbtool ch_filter_specification
	 * into the Work Request and the definition of that structure is
	 * currently in cxgbtool.h which isn't appropriate to pull into the
	 * common code.  We may eventually try to come up with a more neutral
	 * filter specification structure but for now it's easiest to simply
	 * put this fairly direct code in line ...
	 */
	if (adapter->params.filter2_wr_support)
		fwr->op_pkd = htonl(V_FW_WR_OP(FW_FILTER2_WR));
	else
		fwr->op_pkd = htonl(V_FW_WR_OP(FW_FILTER_WR));
	fwr->len16_pkd = htonl(V_FW_WR_LEN16(sizeof(*fwr) / 16));
	fwr->tid_to_iq =
		htonl(V_FW_FILTER_WR_TID(f->tid) |
		      V_FW_FILTER_WR_RQTYPE(f->fs.type) |
		      V_FW_FILTER_WR_NOREPLY(0) |
		      V_FW_FILTER_WR_IQ(f->fs.iq));
	fwr->del_filter_to_l2tix =
		htonl(V_FW_FILTER_WR_RPTTID(f->fs.rpttid) |
		      V_FW_FILTER_WR_DROP(f->fs.action == FILTER_DROP) |
		      V_FW_FILTER_WR_DIRSTEER(f->fs.dirsteer) |
		      V_FW_FILTER_WR_MASKHASH(f->fs.maskhash) |
		      V_FW_FILTER_WR_DIRSTEERHASH(f->fs.dirsteerhash) |
		      V_FW_FILTER_WR_LPBK(f->fs.action == FILTER_SWITCH) |
		      V_FW_FILTER2_WR_TX_LOOP(f->fs.eport >=
					 NUM_UP_TSCH_CHANNEL_INSTANCES) |
		      V_FW_FILTER2_WR_DROP_ENCAP(f->fs.drop_encap_hdr) |
		      V_FW_FILTER_WR_DMAC(f->fs.newdmac) |
		      V_FW_FILTER_WR_SMAC(f->fs.newsmac) |
		      V_FW_FILTER_WR_INSVLAN(f->fs.newvlan == VLAN_INSERT ||
					     f->fs.newvlan == VLAN_REWRITE) |
		      V_FW_FILTER_WR_RMVLAN(f->fs.newvlan == VLAN_REMOVE ||
					    f->fs.newvlan == VLAN_REWRITE) |
		      V_FW_FILTER_WR_HITCNTS(f->fs.hitcnts) |
		      V_FW_FILTER_WR_TXCHAN(f->fs.eport &
					(NUM_UP_TSCH_CHANNEL_INSTANCES - 1)) |
		      V_FW_FILTER_WR_PRIO(f->fs.prio) |
		      V_FW_FILTER_WR_L2TIX(f->l2t ? f->l2t->idx : 0));
	fwr->ethtype = htons(f->fs.val.ethtype);
	fwr->ethtypem = htons(f->fs.mask.ethtype);
	fwr->frag_to_ovlan_vldm =
		     (V_FW_FILTER_WR_FRAG(f->fs.val.frag) |
		      V_FW_FILTER_WR_FRAGM(f->fs.mask.frag) |
		      V_FW_FILTER_WR_IVLAN_VLD(f->fs.val.ivlan_vld) |
		      V_FW_FILTER_WR_OVLAN_VLD(f->fs.val.ovlan_vld) |
		      V_FW_FILTER_WR_IVLAN_VLDM(f->fs.mask.ivlan_vld) |
		      V_FW_FILTER_WR_OVLAN_VLDM(f->fs.mask.ovlan_vld));
	fwr->smac_sel = f->smtidx;
	fwr->rx_chan_rx_rpl_iq =
		htons(V_FW_FILTER_WR_RX_RPL_IQ(adapter->sge.fw_evtq.abs_id));
	if (chip_ver <= CHELSIO_T6)
		fwr->rx_chan_rx_rpl_iq |=
			htons(V_FW_FILTER_WR_RX_CHAN(cxgb4_port_e2cchan(f->dev)));
	fwr->maci_to_matchtypem =
		htonl(V_FW_FILTER_WR_MACI(f->fs.val.macidx) |
		      V_FW_FILTER_WR_MACIM(f->fs.mask.macidx) |
		      V_FW_FILTER_WR_FCOE(f->fs.val.fcoe) |
		      V_FW_FILTER_WR_FCOEM(f->fs.mask.fcoe) |
		      V_FW_FILTER_WR_PORT(f->fs.val.iport) |
		      V_FW_FILTER_WR_PORTM(f->fs.mask.iport) |
		      V_FW_FILTER_WR_MATCHTYPE(f->fs.val.matchtype) |
		      V_FW_FILTER_WR_MATCHTYPEM(f->fs.mask.matchtype));
	fwr->ptcl = f->fs.val.proto;
	fwr->ptclm = f->fs.mask.proto;
	fwr->ttyp = f->fs.val.tos;
	fwr->ttypm = f->fs.mask.tos;
	fwr->ivlan = htons(f->fs.val.ivlan);
	fwr->ivlanm = htons(f->fs.mask.ivlan);
	fwr->ovlan = htons(f->fs.val.ovlan);
	fwr->ovlanm = htons(f->fs.mask.ovlan);
	memcpy(fwr->lip, f->fs.val.lip, sizeof(fwr->lip));
	memcpy(fwr->lipm, f->fs.mask.lip, sizeof(fwr->lipm));
	memcpy(fwr->fip, f->fs.val.fip, sizeof(fwr->fip));
	memcpy(fwr->fipm, f->fs.mask.fip, sizeof(fwr->fipm));
	fwr->lp = htons(f->fs.val.lport);
	fwr->lpm = htons(f->fs.mask.lport);
	fwr->fp = htons(f->fs.val.fport);
	fwr->fpm = htons(f->fs.mask.fport);

	if (adapter->params.filter2_wr_support) {
		fwr->filter_type_swapmac =
			 V_FW_FILTER2_WR_SWAPMAC(f->fs.swapmac);
		fwr->natmode_to_ulp_type =
			V_FW_FILTER2_WR_ULP_TYPE(f->fs.nat_mode ?
						 ULP_MODE_TCPDDP :
						 ULP_MODE_NONE) |
			V_FW_FILTER2_WR_NATFLAGCHECK(f->fs.nat_flag_chk) |
			V_FW_FILTER2_WR_NATMODE(f->fs.nat_mode);
		memcpy(fwr->newlip, f->fs.nat_lip, sizeof(fwr->newlip));
		memcpy(fwr->newfip, f->fs.nat_fip, sizeof(fwr->newfip));
		fwr->newlport = htons(f->fs.nat_lport);
		fwr->newfport = htons(f->fs.nat_fport);
		fwr->natseqcheck = htonl(f->fs.nat_seq_chk);
		fwr->rocev2_qpn = htonl(V_FW_FILTER2_WR_ROCEV2(f->fs.val.roce) |
					V_FW_FILTER2_WR_QPN(f->fs.val.rocev2_qpn));
	}

	/* Mark the filter as "pending" and ship off the Filter Work Request.
	 * When we get the Work Request Reply we'll clear the pending status.
	 */
	f->pending = 1;

	set_wr_txq(skb, CPL_PRIORITY_CONTROL, f->fs.val.iport & 0x3);
	cxgb4_sge_xmit_ctrl(f->dev, skb);
	return 0;
}

/* Use cxgb4_filter_normal_create() for creating MAFO failover filter.
 * For other filters, continue using cxgb4_filter_create().
 */

int cxgb4_filter_normal_create(struct net_device *dev, u32 filter_id,
				      struct ch_filter_specification *fs,
				      struct filter_ctx *ctx, gfp_t flags)
{
	struct adapter *adapter = netdev2adap(dev);
	unsigned int fidx, chip_ver;
	struct cxgb4_tid_info *t;
	struct filter_entry *f;
	int iq, ret;
	u8 n = 1;

	iq = cxgb4_filter_get_steerq(dev, fs);
	if (iq < 0)
		return iq;

	chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);
	t = &adapter->tidinfo;

	/* IPv6 filters occupy four slots on T5 and two slots on T6
	 * and must be aligned on four-slot/two-slot boundaries. IPv4
	 * filters only occupy a single slot and have no alignment
	 * requirements.
	 */
	fidx = filter_id;
	if (fidx != CXGB4_FILTER_ID_ANY) {
		if (chip_ver > CHELSIO_T5 && fs->prio) {
			if (fs->type)
				n = t->hpftids.max_range;

			fidx &= ~(n - 1);
			if (cxgb4_hpftid_out_of_range(adapter, fidx)) {
				dev_err(adapter->pdev_dev,
					"Filter ID %u is out of HPFilter ID range (%u, %u)\n",
					filter_id, t->hpftids.start,
					t->hpftids.start + t->hpftids.size - 1);
				return -ERANGE;
			}
		} else {
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
			if (!cxgb4_sftid_out_of_range(adapter, fidx)) {
				dev_err(adapter->pdev_dev,
					"Filter ID %u is an SFTID and can't be created\n",
					filter_id);
				return -EINVAL;
			}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

			if (fs->type)
				n = t->ftids.max_range;

			fidx &= ~(n - 1);
			if (cxgb4_ftid_out_of_range(adapter, fidx)) {
				dev_err(adapter->pdev_dev,
					"Filter ID %u is out of Filter ID range (%u, %u)\n",
					filter_id, t->ftids.start,
					t->ftids.start + t->ftids.size - 1);
				return -ERANGE;
			}
		}
	}

	f = kzalloc(sizeof(*f), flags);
	if (!f)
		return -ENOMEM;

	/* Convert the filter specification into our internal format.
	 * We copy the PF/VF specification into the Outer VLAN field
	 * here so the rest of the code -- including the interface to
	 * the firmware -- doesn't have to constantly do these checks.
	 */
	f->fs = *fs;
	f->fs.iq = iq;
	f->dev = dev;

	ret = cxgb4_filter_match_parse(adapter, f);
	if (ret)
		goto out_free;

	ret = cxgb4_filter_action_parse(adapter, f);
	if (ret)
		goto out_free;

	if (fidx != CXGB4_FILTER_ID_ANY) {
		ret = cxgb4_ftid_insert(adapter, f, fidx, fs->type);
		if (ret)
			goto out_free_filter;
	} else {
		if (chip_ver > CHELSIO_T5 && fs->prio) {
			ret = cxgb4_hpftid_alloc(adapter, f, fs->type);
			if (ret < 0)
				goto out_free_filter;

			fidx = ret;
		} else {
			ret = cxgb4_ftid_alloc(adapter, f, fs->type);
			if (ret < 0)
				goto out_free_filter;

			fidx = ret;
		}
	}

	/* Attempt to set the filter.  If we don't succeed, we clear
	 * it and return the failure.
	 */
	f->ctx = ctx;
	f->tid = fidx; /* Save the actual tid */
	ret = cxgb4_filter_normal_create_wr(adapter, f, flags);
	if (ret)
		goto out_free_ftid;

	return fidx;

out_free_ftid:
	cxgb4_ftid_free(adapter, fidx, fs->type);
out_free_filter:
	cxgb4_filter_clear(adapter, f);
	return ret;

out_free:
	kfree(f);
	return ret;
}

/* Delete the filter at a specified index.
 */
static int cxgb4_filter_normal_delete_wr(struct adapter *adapter,
					 struct filter_entry *f, gfp_t gfp_mask)
{
	struct fw_filter_wr *fwr;
	struct sk_buff *skb;
	unsigned int len;

	len = sizeof(*fwr);

	if (gfp_mask & GFP_ATOMIC) {
		skb = alloc_skb(len, GFP_ATOMIC);
		if (!skb)
			return -ENOMEM;
	} else {
		skb = alloc_skb(len, gfp_mask | __GFP_NOFAIL);
	}

	fwr = (struct fw_filter_wr *)__skb_put(skb, len);
	t4_mk_filtdelwr(f->tid, fwr, f->fs.type, adapter->sge.fw_evtq.abs_id);

	/* Mark the filter as "pending" and ship off the Filter Work Request.
	 * When we get the Work Request Reply we'll clear the pending status.
	 */
	f->pending = 1;
	t4_mgmt_tx(adapter, skb);
	return 0;
}

static int cxgb4_filter_normal_delete(struct net_device *dev, u32 filter_id,
				      struct filter_ctx *ctx, gfp_t flags)
{
	struct adapter *adapter = netdev2adap(dev);
	unsigned int fidx, chip_ver;
	struct cxgb4_tid_info *t;
	struct filter_entry *f;
	int ret;

	chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);
	/* Make sure this is a valid filter and that we can delete it.
	 */
	t = &adapter->tidinfo;
	fidx = filter_id;
	if (cxgb4_hpftid_out_of_range(adapter, fidx)) {
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		if (!cxgb4_sftid_out_of_range(adapter, fidx)) {
			dev_err(adapter->pdev_dev,
				"Filter ID %u is an SFTID and can't be deleted\n",
				filter_id);
			return -EINVAL;
		}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

		if (cxgb4_ftid_out_of_range(adapter, fidx)) {
			dev_err(adapter->pdev_dev,
				"Filter ID %u is out of Filter ID range (%u, %u)\n",
				filter_id, t->ftids.start,
				t->ftids.start + t->ftids.size - 1);
			return -ERANGE;
		}
	}

	f = cxgb4_ftid_lookup(adapter, fidx);
	if (!f)
		return -ENOENT;

	ret = cxgb4_filter_writable(f);
	if (ret)
		return ret;

	f->ctx = ctx;
	ret = cxgb4_filter_normal_delete_wr(adapter, f, flags);
	if (!ret && !ctx)
		cxgb4_ftid_filter_clear(adapter, f);

	return ret;
}

/* Handle a filter write/deletion reply.
 */
void cxgb4_filter_normal_rpl(struct adapter *adap,
			     const struct cpl_set_tcb_rpl *rpl)
{
	unsigned int ret = G_COOKIE(rpl->cookie);
	unsigned int tid = GET_TID(rpl);
	struct filter_entry *f;
	struct filter_ctx *ctx;

	f = cxgb4_ftid_lookup(adap, tid);
	/* We did not find the filter entry for this tid */
	if (!f)
		return;

	/* Pull off any filter operation context attached to the
	 * filter.
	 */
	ctx = f->ctx;
	f->ctx = NULL;

	switch (ret) {
	case FW_FILTER_WR_FLT_DELETED:
		/* Clear the filter when we get confirmation from the
		 * hardware that the filter has been deleted.
		 */
		if (ctx) {
			cxgb4_ftid_filter_clear(adap, f);
			ctx->result = 0;
		}
		break;
	case FW_FILTER_WR_FLT_ADDED:
		f->pending = 0;  /* Asynchronous setup completed */
		f->valid = 1;
		if (ctx) {
			ctx->result = 0;
			ctx->tid = f->tid;
		}
		break;
	default:
		/* Something went wrong.  Issue a warning about the
		 * problem and clear everything out.
		 */
		CH_ERR(adap, "filter %u setup failed with error %u\n",
		       f->tid, ret);
		cxgb4_ftid_filter_clear(adap, f);
		if (ctx)
			ctx->result = -EINVAL;
		break;
	}

	if (ctx)
		complete(&ctx->completion);
}

/* Hash Filters
 */
static u64 cxgb4_filter_hash_ntuple(struct ch_filter_specification *fs,
				    struct net_device *dev)
{
	struct adapter *adap = netdev2adap(dev);
	struct tp_params *tp = &adap->params.tp;
	u64 ntuple = 0;

	/* Initialize each of the fields which we care about which are present
	 * in the Compressed Filter Tuple.
	 */
	if (tp->vlan_shift >= 0 && fs->mask.ivlan)
		ntuple |= (u64)(F_FT_VLAN_VLD | fs->val.ivlan) << tp->vlan_shift;

	if (tp->port_shift >= 0 && fs->mask.iport)
		ntuple |= (u64)fs->val.iport << tp->port_shift;

	if (tp->protocol_shift >= 0) {
		if (!fs->val.proto)
			ntuple |= (u64)IPPROTO_TCP << tp->protocol_shift;
		else
			ntuple |= (u64)fs->val.proto << tp->protocol_shift;
	}

	if (tp->tos_shift >= 0 && fs->mask.tos)
		ntuple |= (u64)(fs->val.tos) << tp->tos_shift;

	if (tp->vnic_shift >= 0) {
		if ((adap->params.tp.ingress_config & F_USE_ENC_IDX) &&
		    fs->mask.encap_vld)
			ntuple |= (u64)((fs->val.encap_vld << 16) |
					(fs->val.encap_matchtype << 9) |
					(fs->val.ovlan)) << tp->vnic_shift;
		else if ((adap->params.tp.ingress_config & F_VNIC) &&
			 fs->mask.pfvf_vld)
			ntuple |= (u64)((fs->val.pfvf_vld << 16) |
					(fs->val.pf << 13) |
					(fs->val.vf)) << tp->vnic_shift;
		else
			ntuple |= (u64)((fs->val.ovlan_vld << 16) |
					(fs->val.ovlan)) << tp->vnic_shift;
	}

	if (tp->macmatch_shift >= 0 && fs->mask.macidx)
		ntuple |= (u64)(fs->val.macidx) << tp->macmatch_shift;

	if (tp->ethertype_shift >= 0 && fs->mask.ethtype)
		ntuple |= (u64)(fs->val.ethtype) << tp->ethertype_shift;

	if (tp->matchtype_shift >= 0 && fs->mask.matchtype)
		ntuple |= (u64)(fs->val.matchtype) << tp->matchtype_shift;

	if (tp->frag_shift >= 0 && fs->mask.frag)
		ntuple |= (u64)(fs->val.frag) << tp->frag_shift;

	if (tp->fcoe_shift >= 0 && fs->mask.fcoe)
		ntuple |= (u64)(fs->val.fcoe) << tp->fcoe_shift;

	if (tp->ipsecidx_shift >= 0 && fs->mask.ipsecidx)
		ntuple |= (u64)(fs->val.ipsecidx) << tp->ipsecidx_shift;

	if (tp->roce_shift >= 0 && fs->mask.roce)
		ntuple |= (u64)(fs->val.roce) << tp->roce_shift;

	if (tp->synonly_shift >= 0 && fs->mask.synonly)
		ntuple |= (u64)(fs->val.synonly) << tp->synonly_shift;

	if (tp->tcpflags_shift >= 0 && fs->mask.tcpflags)
		ntuple |= (u64)(fs->val.tcpflags) << tp->tcpflags_shift;

	return ntuple;
}

static void cxgb4_filter_hash_mk_act_open_req6(struct filter_entry *f,
					       struct sk_buff *skb,
					       u32 qid_filterid)
{
	struct adapter *adap = netdev2adap(f->dev);
	struct cpl_t5_act_open_req6 *t5req = NULL;
	struct cpl_t6_act_open_req6 *t6req = NULL;
	struct cpl_t7_act_open_req6 *t7req = NULL;
	struct cpl_act_open_req6 *req = NULL;
	u32 chip_ver, opt2;
	u64 ntuple, opt0;

	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	ntuple = cxgb4_filter_hash_ntuple(&f->fs, f->dev);

	opt0 = V_NAGLE(f->fs.newvlan == VLAN_REMOVE ||
		       f->fs.newvlan == VLAN_REWRITE) |
	       V_DELACK(f->fs.hitcnts) |
	       V_KEEP_ALIVE(f->fs.drop_encap_hdr) |
	       V_L2T_IDX(f->l2t ? f->l2t->idx : 0) |
	       V_SMAC_SEL((cxgb4_port_viid(f->dev) & 0x7F) << 1) |
	       V_TX_CHAN(cxgb4_hash_filter_get_tx_chan(adap, f)) |
	       V_NO_CONG(f->fs.rpttid) |
	       V_ULP_MODE(f->fs.nat_mode ? ULP_MODE_TCPDDP : ULP_MODE_NONE) |
	       F_TCAM_BYPASS | F_NON_OFFLOAD;

	opt2 = F_RSS_QUEUE_VALID | V_RSS_QUEUE(f->fs.iq) |
	       V_TX_QUEUE(f->fs.nat_mode) | V_WND_SCALE_EN(f->fs.nat_flag_chk) |
	       V_RX_FC_DISABLE(f->fs.nat_seq_chk ? 1 : 0) | F_T5_OPT_2_VALID |
	       V_RX_CHANNEL(cxgb4_hash_filter_get_rx_chan(adap, f)) |
	       V_SACK_EN(f->fs.swapmac) |
	       V_PACE((f->fs.maskhash) | ((f->fs.dirsteerhash) << 1));

	switch (chip_ver) {
	case CHELSIO_T5:
		t5req = (struct cpl_t5_act_open_req6 *)__skb_put(skb,
								sizeof(*t5req));
		INIT_TP_WR(t5req, 0);
		t5req->params = cpu_to_be64(V_FILTER_TUPLE(ntuple));
		t5req->opt0 = cpu_to_be64(opt0);
		t5req->opt2 = cpu_to_be32(opt2);
		req = (struct cpl_act_open_req6 *)t5req;
		break;
	case CHELSIO_T6:
		t6req = (struct cpl_t6_act_open_req6 *)__skb_put(skb,
								sizeof(*t6req));
		INIT_TP_WR(t6req, 0);
		req = (struct cpl_act_open_req6 *)t6req;
		t6req->params = cpu_to_be64(V_FILTER_TUPLE(ntuple));
		t6req->opt0 = cpu_to_be64(opt0);
		t6req->opt2 = cpu_to_be32(opt2);
		break;
	case CHELSIO_T7:
		t7req = (struct cpl_t7_act_open_req6 *)__skb_put(skb,
								sizeof(*t7req));
		INIT_TP_WR(t7req, 0);
		t7req->params = cpu_to_be64(V_T7_FILTER_TUPLE(ntuple));
		t7req->opt0 = cpu_to_be64(opt0);
		t7req->opt2 = cpu_to_be32(opt2);
		req = (struct cpl_act_open_req6 *)t7req;
		break;
	default:
		pr_err("%s: unsupported chip type!\n", __func__);
		return;
	}

	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_ACT_OPEN_REQ6, qid_filterid));
	req->local_port = cpu_to_be16(f->fs.val.lport);
	req->peer_port = cpu_to_be16(f->fs.val.fport);
	req->local_ip_hi = *(__be64 *)(&f->fs.val.lip);
	req->local_ip_lo = *(((__be64 *)&f->fs.val.lip) + 1);
	req->peer_ip_hi = *(__be64 *)(&f->fs.val.fip);
	req->peer_ip_lo = *(((__be64 *)&f->fs.val.fip) + 1);
}

static void cxgb4_filter_hash_mk_act_open_req(struct filter_entry *f,
					      struct sk_buff *skb,
					      u32 qid_filterid)
{
	struct adapter *adap = netdev2adap(f->dev);
	struct cpl_t5_act_open_req *t5req = NULL;
	struct cpl_t6_act_open_req *t6req = NULL;
	struct cpl_t7_act_open_req *t7req = NULL;
	struct cpl_act_open_req *req = NULL;
	u32 chip_ver, opt2;
	u64 ntuple, opt0;

	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	ntuple = cxgb4_filter_hash_ntuple(&f->fs, f->dev);

	opt0 = V_NAGLE(f->fs.newvlan == VLAN_REMOVE ||
		       f->fs.newvlan == VLAN_REWRITE) |
	       V_DELACK(f->fs.hitcnts) |
	       V_KEEP_ALIVE(f->fs.drop_encap_hdr) |
	       V_L2T_IDX(f->l2t ? f->l2t->idx : 0) |
	       V_SMAC_SEL((cxgb4_port_viid(f->dev) & 0x7F) << 1) |
	       V_TX_CHAN(cxgb4_hash_filter_get_tx_chan(adap, f)) |
	       V_NO_CONG(f->fs.rpttid) |
	       V_ULP_MODE(f->fs.nat_mode ? ULP_MODE_TCPDDP : ULP_MODE_NONE) |
	       F_TCAM_BYPASS | F_NON_OFFLOAD;

	opt2 = F_RSS_QUEUE_VALID | V_RSS_QUEUE(f->fs.iq) |
	       V_TX_QUEUE(f->fs.nat_mode) | V_WND_SCALE_EN(f->fs.nat_flag_chk) |
	       V_RX_FC_DISABLE(f->fs.nat_seq_chk ? 1 : 0) | F_T5_OPT_2_VALID |
	       V_RX_CHANNEL(cxgb4_hash_filter_get_rx_chan(adap, f)) |
	       V_SACK_EN(f->fs.swapmac) |
	       V_PACE((f->fs.maskhash) | ((f->fs.dirsteerhash) << 1));

	switch (chip_ver) {
	case CHELSIO_T5:
		t5req = (struct cpl_t5_act_open_req *)__skb_put(skb,
								sizeof(*t5req));
		INIT_TP_WR(t5req, 0);
		t5req->params = cpu_to_be64(V_FILTER_TUPLE(ntuple));
		t5req->opt0 = cpu_to_be64(opt0);
		t5req->opt2 = cpu_to_be32(opt2);
		req = (struct cpl_act_open_req *)t5req;
		break;
	case CHELSIO_T6:
		t6req = (struct cpl_t6_act_open_req *)__skb_put(skb,
								sizeof(*t6req));
		INIT_TP_WR(t6req, 0);
		req = (struct cpl_act_open_req *)t6req;
		t6req->params = cpu_to_be64(V_FILTER_TUPLE(ntuple));
		t6req->opt0 = cpu_to_be64(opt0);
		t6req->opt2 = cpu_to_be32(opt2);
		break;
	case CHELSIO_T7:
		t7req = (struct cpl_t7_act_open_req *)__skb_put(skb,
								sizeof(*t7req));
		INIT_TP_WR(t7req, 0);
		t7req->params = cpu_to_be64(V_T7_FILTER_TUPLE(ntuple));
		t7req->opt0 = cpu_to_be64(opt0);
		t7req->opt2 = cpu_to_be32(opt2);
		req = (struct cpl_act_open_req *)t7req;
		break;
	default:
		pr_err("%s: unsupported chip type!\n", __func__);
		return;
	}

	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_ACT_OPEN_REQ, qid_filterid));
	req->local_port = cpu_to_be16(f->fs.val.lport);
	req->peer_port = cpu_to_be16(f->fs.val.fport);
	req->local_ip = f->fs.val.lip[0] | (f->fs.val.lip[1] << 8) |
			(f->fs.val.lip[2] << 16) | (f->fs.val.lip[3] << 24);
	req->peer_ip = f->fs.val.fip[0] | (f->fs.val.fip[1] << 8) |
		       (f->fs.val.fip[2] << 16) | (f->fs.val.fip[3] << 24);
}

static int cxgb4_filter_hash_create(struct net_device *dev,
				    struct ch_filter_specification *fs,
				    struct filter_ctx *ctx, gfp_t flags)
{
	struct adapter *adapter = netdev2adap(dev);
	const struct hlist_nulls_node *node;
	u32 hash, slot, fw_qid, atid, size;
	struct filter_ehash_bucket *head;
	struct filter_entry *f = NULL;
	unsigned int chip_ver;
	struct sk_buff *skb;
	int iq, ret;

	chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);

	iq = cxgb4_filter_get_steerq(dev, fs);
	if (iq < 0)
		return iq;

	/* lookup for an existing entry if its a T6+ */
	if (chip_ver >= CHELSIO_T6) {
		if (fs->type) {
			const struct in6_addr *laddr = (struct in6_addr *)fs->val.lip;
			const struct in6_addr *faddr = (struct in6_addr *)fs->val.fip;
			u32 lhash, fhash;
			u32 ports = (((u32)fs->val.lport) << 16) |
				    (__force u32)fs->val.fport;

			lhash = (__force u32)laddr->s6_addr32[3];
			fhash = __ipv6_addr_jhash(faddr, 0);
			hash = jhash_3words(lhash, fhash, ports,
					    cxgb4_filter_hash_ntuple(fs, dev) &
					    0xFFFFFFFF);
		} else {
			u32 lip = fs->val.lip[0] | fs->val.lip[1] << 8 |
				  fs->val.lip[2] << 16 | fs->val.lip[3] << 24;
			u32 fip = fs->val.fip[0] | fs->val.fip[1] << 8 |
				  fs->val.fip[2] << 16 | fs->val.fip[3] << 24;

			hash = jhash_3words((__force __u32)lip,
					    (__force __u32)fip,
					    ((__u32)fs->val.lport) << 16 |
					    (__force __u32)fs->val.fport,
					    cxgb4_filter_hash_ntuple(fs, dev) &
					    0xFFFFFFFF);
		}

		if (fs->val.proto == IPPROTO_UDP) {
			slot = hash & adapter->filter_udphash.ehash_mask;
			head = &adapter->filter_udphash.ehash[slot];
		} else {
			slot = hash & adapter->filter_tcphash.ehash_mask;
			head = &adapter->filter_tcphash.ehash[slot];
		}

		rcu_read_lock();
begin:
		hlist_nulls_for_each_entry_rcu(f, node, &head->chain, filter_nulls_node) {
			u8 lip = memcmp(f->fs.val.lip, fs->val.lip,
					sizeof(fs->val.lip));
			u8 fip = memcmp(f->fs.val.fip, fs->val.fip,
					sizeof(fs->val.fip));

			if (f->filter_hash == hash &&
			    f->fs.val.lport == fs->val.lport &&
			    f->fs.val.fport == fs->val.fport &&
			    !lip && !fip) {
				rcu_read_unlock();
				return -EEXIST;
			}
		}
		/* If the nulls value we got at the end of this lookup is
		 * not the expected one, we must restart lookup.
		 * We probably met an item that was moved to another chain.
		 */
		if (get_nulls_value(node) != slot)
			goto begin;

		rcu_read_unlock();
	}

	f = kzalloc(sizeof(*f), flags);
	if (!f)
		return -ENOMEM;

	f->fs = *fs;
	f->ctx = ctx;
	f->dev = dev;
	f->fs.iq = iq;

	ret = cxgb4_filter_match_parse(adapter, f);
	if (ret)
		goto out_free;

	ret = cxgb4_filter_action_parse(adapter, f);
	if (ret)
		goto out_free;

	atid = cxgb4_atid_alloc(adapter, f);
	if (atid < 0)
		goto out_free_filter;

	fw_qid = adapter->sge.fw_evtq.abs_id;
	if (f->fs.type) {
		switch (chip_ver) {
		case CHELSIO_T5:
			size = sizeof(struct cpl_t5_act_open_req6);
			break;
		case CHELSIO_T6:
			size = sizeof(struct cpl_t6_act_open_req6);
			break;
		default:
			size = sizeof(struct cpl_t7_act_open_req6);
			break;
		}

		skb = alloc_skb(size, flags);
		if (!skb) {
			ret = -ENOMEM;
			goto out_free_atid;
		}

		cxgb4_filter_hash_mk_act_open_req6(f, skb,
						   (fw_qid << 14) | atid);
	} else {
		switch (chip_ver) {
		case CHELSIO_T5:
			size = sizeof(struct cpl_t5_act_open_req);
			break;
		case CHELSIO_T6:
			size = sizeof(struct cpl_t6_act_open_req);
			break;
		default:
			size = sizeof(struct cpl_t7_act_open_req);
			break;
		}

		skb = alloc_skb(size, flags);
		if (!skb) {
			ret = -ENOMEM;
			goto out_free_atid;
		}

		cxgb4_filter_hash_mk_act_open_req(f, skb,
						  (fw_qid << 14) | atid);
	}

	f->pending = 1;
	set_wr_txq(skb, CPL_PRIORITY_SETUP, f->fs.val.iport & 0x3);
	cxgb4_sge_xmit_ctrl(dev, skb);
	return 0;

out_free_atid:
	cxgb4_atid_free(adapter, atid);
out_free_filter:
	cxgb4_filter_clear(adapter, f);
	return ret;

out_free:
	kfree(f);
	return ret;
}

/* Build a CPL_SET_TCB_FIELD message as payload of a ULP_TX_PKT command.
 */
static void cxgb4_filter_hash_mk_set_tcb_field_ulp(struct filter_entry *f,
						   struct cpl_set_tcb_field *req,
						   unsigned int word,
						   u64 mask, u64 val, u8 cookie,
						   int no_reply)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)req;
	struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);
	struct adapter *adap = netdev2adap(f->dev);

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	txpkt->len = htonl(DIV_ROUND_UP(sizeof(*req), 16));
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
	sc->len = htonl(sizeof(*req) - sizeof(struct work_request_hdr));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, f->tid));
	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7)
		req->reply_ctrl = htons(V_NO_REPLY(no_reply) |
					V_T7_REPLY_CHAN(0) |
					V_T7_QUEUENO(0));
	else
		req->reply_ctrl = htons(V_NO_REPLY(no_reply) |
					V_REPLY_CHAN(0) |
					V_QUEUENO(0));
	req->word_cookie = htons(V_WORD(word) | V_COOKIE(cookie));
	req->mask = cpu_to_be64(mask);
	req->val = cpu_to_be64(val);
	sc = (struct ulptx_idata *)(req + 1);
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_NOOP));
	sc->len = htonl(0);
}

/* Build a CPL_ABORT_REQ message as payload of a ULP_TX_PKT command.
 */
static void cxgb4_filter_hash_mk_abort_req_ulp(struct cpl_abort_req *abort_req,
					       unsigned int tid)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)abort_req;
	struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	txpkt->len = htonl(DIV_ROUND_UP(sizeof(*abort_req), 16));
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
	sc->len = htonl(sizeof(*abort_req) - sizeof(struct work_request_hdr));
	OPCODE_TID(abort_req) = htonl(MK_OPCODE_TID(CPL_ABORT_REQ, tid));
	abort_req->rsvd0 = htonl(0);
	abort_req->rsvd1 = 0;
	abort_req->cmd = CPL_ABORT_NO_RST;
}

static void cxgb4_filter_hash_mk_abort_rpl_ulp(struct cpl_abort_rpl *abort_rpl,
					       unsigned int tid)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)abort_rpl;
	struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	txpkt->len = htonl(DIV_ROUND_UP(sizeof(*abort_rpl), 16));
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
	sc->len = htonl(sizeof(*abort_rpl) - sizeof(struct work_request_hdr));
	OPCODE_TID(abort_rpl) = htonl(MK_OPCODE_TID(CPL_ABORT_RPL, tid));
	abort_rpl->rsvd0 = htonl(0);
	abort_rpl->rsvd1 = 0;
	abort_rpl->cmd = CPL_ABORT_NO_RST;
}

static int cxgb4_filter_hash_delete(struct net_device *dev, u32 filter_id,
				    struct filter_ctx *ctx, gfp_t flags)
{
	struct adapter *adapter = netdev2adap(dev);
	struct cpl_abort_req *abort_req;
	struct cpl_abort_rpl *abort_rpl;
	struct cpl_set_tcb_field *req;
	struct ulptx_idata *aligner;
	struct work_request_hdr *wr;
	struct filter_entry *f;
	struct sk_buff *skb;
	u32 wrlen, fw_qid;
	int ret;

	CH_MSG(adapter, INFO, HW, "%s: filter_id = %d ; nhashtids = %d\n",
	       __func__, filter_id,
	       adapter->tidinfo.hashcoll_tids.size +
	       adapter->tidinfo.hashtids.size);

	if (unlikely(cxgb4_hashtid_out_of_range(adapter, filter_id))) {
		CH_ERR(adapter, "%s: hash filter TID %u out of range\n",
		       __func__, filter_id);
		return -E2BIG;
	}

	if (unlikely(cxgb4_hashtid_out_of_range(adapter, filter_id))) {
		f = cxgb4_atid_lookup(adapter, filter_id);
	} else {
		f = cxgb4_hashtid_lookup(adapter, filter_id);
	}

	if (!f) {
		CH_ERR(adapter, "%s: no filter entry for filter_id = %d",
		       __func__, filter_id);
		return -EINVAL;
	}

	ret = cxgb4_filter_writable(f);
	if (ret)
		return ret;

	f->ctx = ctx;
	f->pending = 1;

	wrlen = roundup(sizeof(*wr) + (sizeof(*req) + sizeof(*aligner)) +
			sizeof(*abort_req) + sizeof(*abort_rpl), 16);
	skb = alloc_skb(wrlen, flags);
	if (!skb) {
		CH_ERR(adapter, "%s: could not allocate skb ..\n", __func__);
		return -ENOMEM;
	}

	fw_qid = adapter->sge.fw_evtq.abs_id;
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, f->fs.val.iport & 0x3);
	req = (struct cpl_set_tcb_field *)__skb_put(skb, wrlen);
	INIT_ULPTX_WR(req, wrlen, 0, 0);
	wr = (struct work_request_hdr *)req;
	wr++;
	req = (struct cpl_set_tcb_field *)wr;
	cxgb4_filter_hash_mk_set_tcb_field_ulp(f, req, W_TCB_RSS_INFO,
					       V_TCB_RSS_INFO(M_TCB_RSS_INFO),
					       V_TCB_RSS_INFO(fw_qid),
					       0, 1);
	aligner = (struct ulptx_idata *)(req + 1);
	abort_req = (struct cpl_abort_req *)(aligner + 1);
	cxgb4_filter_hash_mk_abort_req_ulp(abort_req, f->tid);
	abort_rpl = (struct cpl_abort_rpl *)(abort_req + 1);
	cxgb4_filter_hash_mk_abort_rpl_ulp(abort_rpl, f->tid);
	cxgb4_sge_xmit_ctrl(dev, skb);

	if (!ctx)
		cxgb4_hashtid_filter_clear(adapter, f);

	return 0;
}

#ifndef INET_HASHFN
unsigned int inet_ehashfn(struct net *net, const __be32 laddr,
			  const __u16 lport, const __be32 faddr,
			  const __be16 fport)
{
	static u32 inet_ehash_secret __read_mostly;

	net_get_random_once(&inet_ehash_secret, sizeof(inet_ehash_secret));

	return __inet_ehashfn(laddr, lport, faddr, fport,
			      inet_ehash_secret + net_hash_mix(net));
}
#endif

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
unsigned int t4_inet6_ehashfn(struct net *net,
			      const struct in6_addr *laddr,
			      const u16 lport,
			      const struct in6_addr *faddr,
			      const __be16 fport)
{
	static u32 inet6_ehash_secret __read_mostly;
	static u32 ipv6_hash_secret __read_mostly;

	u32 lhash, fhash;

	net_get_random_once(&inet6_ehash_secret, sizeof(inet6_ehash_secret));
	net_get_random_once(&ipv6_hash_secret, sizeof(ipv6_hash_secret));

	lhash = (__force u32)laddr->s6_addr32[3];
	fhash = __ipv6_addr_jhash(faddr, ipv6_hash_secret);

	return __inet6_ehashfn(lhash, lport, fhash, fport,
			       inet6_ehash_secret + net_hash_mix(net));
}
#else
unsigned int t4_inet6_ehashfn(struct net *net,
			      const struct in6_addr *laddr,
			      const u16 lport,
			      const struct in6_addr *faddr,
			      const __be16 fport)
{
	return 0;
}
#endif

static void set_tcb_field(struct adapter *adap, struct filter_entry *f,
			  u32 ftid, u16 word, u64 mask, u64 val, int no_reply)
{
	struct cpl_set_tcb_field *req;
	struct sk_buff *skb;

	skb = alloc_skb(sizeof(struct cpl_set_tcb_field), GFP_ATOMIC);
	BUG_ON(!skb);

	req = (struct cpl_set_tcb_field *)__skb_put(skb, sizeof(*req));
	memset(req, 0, sizeof(*req));
	INIT_TP_WR_MIT_CPL(req, CPL_SET_TCB_FIELD, ftid);
	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7)
		req->reply_ctrl = htons(V_T7_REPLY_CHAN(0) |
					V_T7_QUEUENO(adap->sge.fw_evtq.abs_id) |
					V_NO_REPLY(no_reply));
	else
		req->reply_ctrl = htons(V_REPLY_CHAN(0) |
					V_QUEUENO(adap->sge.fw_evtq.abs_id) |
					V_NO_REPLY(no_reply));
	req->word_cookie = htons(V_WORD(word) | V_COOKIE(ftid));
	req->mask = cpu_to_be64(mask);
	req->val = cpu_to_be64(val);

	set_wr_txq(skb, CPL_PRIORITY_CONTROL, f->fs.val.iport & 0x3);
	cxgb4_sge_xmit_ctrl(f->dev, skb);
}

/* Set one of the t_flags bits in the TCB.
 */
static void set_tcb_tflag(struct adapter *adap, struct filter_entry *f,
			  u32 ftid, u32 bit_pos, u32 val, int no_reply)
{
	set_tcb_field(adap, f, ftid,  W_TCB_T_FLAGS, 1ULL << bit_pos,
		      (unsigned long long)val << bit_pos, no_reply);
}

static void set_nat_params(struct adapter *adap, struct filter_entry *f,
			   u32 tid, bool dip, bool sip, bool dp, bool sp)
{
	if (dip) {
		if (f->fs.type) {
			set_tcb_field(adap, f, tid, W_TCB_SND_UNA_RAW,
				      WORD_MASK, f->fs.nat_lip[15] |
				      f->fs.nat_lip[14] << 8 |
				      f->fs.nat_lip[13] << 16 |
				      f->fs.nat_lip[12] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_SND_UNA_RAW + 1,
				      WORD_MASK, f->fs.nat_lip[11] |
				      f->fs.nat_lip[10] << 8 |
				      f->fs.nat_lip[9] << 16 |
				      f->fs.nat_lip[8] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_SND_UNA_RAW + 2,
				      WORD_MASK, f->fs.nat_lip[7] |
				      f->fs.nat_lip[6] << 8 |
				      f->fs.nat_lip[5] << 16 |
				      f->fs.nat_lip[4] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_SND_UNA_RAW + 3,
				      WORD_MASK, f->fs.nat_lip[3] |
				      f->fs.nat_lip[2] << 8 |
				      f->fs.nat_lip[1] << 16 |
				      f->fs.nat_lip[0] << 24, 1);
		} else {
			set_tcb_field(adap, f, tid, W_TCB_RX_FRAG3_LEN_RAW,
				      WORD_MASK, f->fs.nat_lip[3] |
				      f->fs.nat_lip[2] << 8 |
				      f->fs.nat_lip[1] << 16 |
				      f->fs.nat_lip[0] << 24, 1);
		}
	}

	if (sip) {
		if (f->fs.type) {
			set_tcb_field(adap, f, tid, W_TCB_RX_FRAG2_PTR_RAW,
				      WORD_MASK, f->fs.nat_fip[15] |
				      f->fs.nat_fip[14] << 8 |
				      f->fs.nat_fip[13] << 16 |
				      f->fs.nat_fip[12] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_RX_FRAG2_PTR_RAW + 1,
				      WORD_MASK, f->fs.nat_fip[11] |
				      f->fs.nat_fip[10] << 8 |
				      f->fs.nat_fip[9] << 16 |
				      f->fs.nat_fip[8] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_RX_FRAG2_PTR_RAW + 2,
				      WORD_MASK, f->fs.nat_fip[7] |
				      f->fs.nat_fip[6] << 8 |
				      f->fs.nat_fip[5] << 16 |
				      f->fs.nat_fip[4] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_RX_FRAG2_PTR_RAW + 3,
				      WORD_MASK, f->fs.nat_fip[3] |
				      f->fs.nat_fip[2] << 8 |
				      f->fs.nat_fip[1] << 16 |
				      f->fs.nat_fip[0] << 24, 1);

		} else {
			set_tcb_field(adap, f, tid,
				      W_TCB_RX_FRAG3_START_IDX_OFFSET_RAW,
				      WORD_MASK, f->fs.nat_fip[3] |
				      f->fs.nat_fip[2] << 8 |
				      f->fs.nat_fip[1] << 16 |
				      f->fs.nat_fip[0] << 24, 1);
		}
	}

	set_tcb_field(adap, f, tid, W_TCB_PDU_HDR_LEN, WORD_MASK,
		      (dp ? f->fs.nat_lport : 0) |
		      (sp ? f->fs.nat_fport << 16 : 0), 1);
}

void cxgb4_filter_hash_create_rpl(struct adapter *adap,
				  const struct cpl_act_open_rpl *rpl)
{
	unsigned int ftid = G_TID_TID(G_AOPEN_ATID(ntohl(rpl->atid_status)));
	unsigned int status  = G_AOPEN_STATUS(ntohl(rpl->atid_status));
	struct filter_ehash_bucket *head;
	unsigned int tid = GET_TID(rpl);
	struct hlist_nulls_head *list;
	struct filter_ctx *ctx = NULL;
	struct filter_entry *f;
	spinlock_t *lock; /* Lock for accessing ehash table */
	int ret;

	CH_MSG(adap, INFO, HW,
	       "%s: tid = %u; atid = %u; status = %u\n",
	       __func__, tid, ftid, status);

#ifdef CONFIG_PO_FCOE
	/* ATID is 14 bit value [0..13], MAX_ATIDS is 8192
	 * ATID needs max 13 bits [0..12], using 13th bit in
	 * ATID for FCoE CPL_ACT_OPEN_REQ.
	 */
	if (ftid & BIT(CXGB_FCOE_ATID)) {
		cxgb_fcoe_cpl_act_open_rpl(adap, ftid, tid, status);
		return;
	}
#endif

	f = cxgb4_atid_lookup(adap, ftid);
	if (!f) {
		CH_WARN_RATELIMIT(adap, "%s:could not find filter entry",
				  __func__);
		return;
	}

	ctx = f->ctx;
	f->ctx = NULL;

	if (status != CPL_ERR_NONE) {
		CH_WARN_RATELIMIT(adap,
				  "%s: filter creation PROBLEM; status = %u\n",
				  __func__, status);

		cxgb4_atid_filter_clear(adap, f);
		if (ctx) {
			if (status == CPL_ERR_TCAM_FULL)
				ctx->result = -EAGAIN;
			else
				ctx->result = -EINVAL;
		}
		goto out_complete;
	}

	/* Hash 4-tuple and add filter entry */
	if (f->fs.type) {
		if (is_t5(adap->params.chip)) {
			f->filter_hash = t4_inet6_ehashfn(dev_net(f->dev),
							  (struct in6_addr *)f->fs.val.lip,
							  f->fs.val.lport,
							  (struct in6_addr *)f->fs.val.fip,
							  f->fs.val.fport);
		} else {
			const struct in6_addr *laddr = (struct in6_addr *)f->fs.val.lip;
			const struct in6_addr *faddr = (struct in6_addr *)f->fs.val.fip;
			u32 ports = (((u32)f->fs.val.lport) << 16) |
				    (__force u32)f->fs.val.fport;
			u32 lhash, fhash;

			lhash = (__force u32)laddr->s6_addr32[3];
			fhash = __ipv6_addr_jhash(faddr, 0);
			f->filter_hash = jhash_3words(lhash, fhash, ports,
						      cxgb4_filter_hash_ntuple(&f->fs, f->dev) &
						      0xFFFFFFFF);
		}
	} else {
		u32 lip = f->fs.val.lip[0] | f->fs.val.lip[1] << 8 |
			  f->fs.val.lip[2] << 16 | f->fs.val.lip[3] << 24;
		u32 fip = f->fs.val.fip[0] | f->fs.val.fip[1] << 8 |
			  f->fs.val.fip[2] << 16 | f->fs.val.fip[3] << 24;

		if (is_t5(adap->params.chip))
			f->filter_hash = inet_ehashfn(dev_net(f->dev), lip,
						      f->fs.val.lport, fip,
						      f->fs.val.fport);
		else
			f->filter_hash = jhash_3words((__force __u32)lip,
						      (__force __u32)fip,
						      ((__u32)f->fs.val.lport) << 16 |
						      (__force __u32)f->fs.val.fport,
						      cxgb4_filter_hash_ntuple(&f->fs, f->dev) &
						      0xFFFFFFFF);
	}

	if (f->fs.val.proto == IPPROTO_UDP) {
		head = &adap->filter_udphash.ehash[f->filter_hash &
			adap->filter_udphash.ehash_mask];
		lock = &adap->filter_udphash.ehash_filter_locks[f->filter_hash &
			adap->filter_udphash.ehash_filter_locks_mask];
	} else {
		head = &adap->filter_tcphash.ehash[f->filter_hash &
			adap->filter_tcphash.ehash_mask];
		lock = &adap->filter_tcphash.ehash_filter_locks[f->filter_hash &
			adap->filter_tcphash.ehash_filter_locks_mask];
	}

	/* Store tid value in special filter entry field */
	f->pending = 0;  /* Asynchronous setup completed */
	f->valid = 1;
	ret = cxgb4_hashtid_insert(adap, tid, f, f->fs.type);
	if (ret) {
		if (ctx)
			ctx->result = ret;
		cxgb4_filter_hash_delete(f->dev, tid, NULL, GFP_KERNEL);
		cxgb4_atid_filter_clear(adap, f);
		goto out_complete;
	}

	cxgb4_atid_free(adap, ftid);
	f->tid = tid;

	spin_lock_bh(lock);
	list = &head->chain;
	hlist_nulls_add_head_rcu(&f->filter_nulls_node, list);
	spin_unlock_bh(lock);

	if (ctx) {
		ctx->tid = f->tid;
		ctx->result = 0;
	}

	if (f->fs.hitcnts) {
		set_tcb_field(adap, f, tid, W_TCB_TIMESTAMP,
			      V_TCB_TIMESTAMP(M_TCB_TIMESTAMP),
			      V_TCB_TIMESTAMP(0ULL), 1);
		set_tcb_field(adap, f, tid, W_TCB_T_RTT_TS_RECENT_AGE,
			      V_TCB_T_RTT_TS_RECENT_AGE(M_TCB_T_RTT_TS_RECENT_AGE),
			      V_TCB_T_RTT_TS_RECENT_AGE(0ULL), 1);
	}

	if (f->fs.newdmac)
		set_tcb_tflag(adap, f, tid, S_TF_CCTRL_ECE, 1, 1);

	if (f->fs.newvlan == VLAN_INSERT || f->fs.newvlan == VLAN_REWRITE)
		set_tcb_tflag(adap, f, tid, S_TF_CCTRL_RFR, 1, 1);

	if (f->fs.newsmac) {
		set_tcb_field(adap, f, tid, W_TCB_SMAC_SEL,
			      V_TCB_SMAC_SEL(M_TCB_SMAC_SEL),
			      V_TCB_SMAC_SEL(f->smtidx), 1);
		set_tcb_tflag(adap, f, tid, S_TF_CCTRL_CWR, 1, 1);
	}

	switch (f->fs.nat_mode) {
	case NAT_MODE_NONE:
		break;
	case NAT_MODE_DIP:
		set_nat_params(adap, f, tid, true, false, false, false);
		break;
	case NAT_MODE_DIP_DP:
		set_nat_params(adap, f, tid, true, false, true, false);
		break;
	case NAT_MODE_DIP_DP_SIP:
		set_nat_params(adap, f, tid, true, true, true, false);
		break;
	case NAT_MODE_DIP_DP_SP:
		set_nat_params(adap, f, tid, true, false, true, true);
		break;
	case NAT_MODE_SIP_SP:
		set_nat_params(adap, f, tid, false, true, false, true);
		break;
	case NAT_MODE_DIP_SIP_SP:
		set_nat_params(adap, f, tid, true, true, false, true);
		break;
	case NAT_MODE_ALL:
		set_nat_params(adap, f, tid, true, true, true, true);
		break;
	default:
		dev_err(adap->pdev_dev, "Invalid NAT mode: %d\n",
			f->fs.nat_mode);
		cxgb4_filter_hash_delete(f->dev, tid, NULL, GFP_KERNEL);
		if (ctx) {
			ctx->result = -EINVAL;
			goto out_complete;
		}
		break;
	}

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7)
		set_tcb_field(adap, f, tid, W_TCB_T_FLAGS,
			      V_TF_PEND_CTL1(1) | V_TF_PEND_CTL2(1),
			      V_TF_PEND_CTL1(f->fs.eport & 0x1) |
			      V_TF_PEND_CTL2((f->fs.eport >> 1) & 0x1), 1);

	if (f->fs.eport >= NUM_UP_TSCH_CHANNEL_INSTANCES)
		set_tcb_tflag(adap, f, tid, S_TF_RECV_TSTMP, 1, 1);

	if (f->fs.nat_seq_chk)
		set_tcb_field(adap, f, tid, W_TCB_RCV_NXT,
			      V_TCB_RCV_NXT(M_TCB_RCV_NXT),
			      V_TCB_RCV_NXT(f->fs.nat_seq_chk), 1);

	switch (f->fs.action) {
	case FILTER_PASS:
		if (f->fs.dirsteer)
			set_tcb_tflag(adap, f, tid, S_TF_DIRECT_STEER, 1, 1);
		break;
	case FILTER_DROP:
		set_tcb_tflag(adap, f, tid, S_TF_DROP, 1, 1);
		break;
	case FILTER_SWITCH:
		set_tcb_tflag(adap, f, tid, S_TF_LPBK, 1, 1);
		break;
	}

	if (is_t5(adap->params.chip) && f->fs.action == FILTER_DROP) {
		/* Set Migrating bit to 1, and
		 * set Non-offload bit to 0 - to achieve
		 * Drop action with Hash filters
		 */
		set_tcb_field(adap, f, tid, W_TCB_T_FLAGS,
			      V_TF_NON_OFFLOAD(1) | V_TF_MIGRATING(1),
			      V_TF_MIGRATING(1), 1);
	}

out_complete:
	if (ctx)
		complete(&ctx->completion);
}

void cxgb4_filter_hash_delete_rpl(struct adapter *adap,
				  const struct cpl_abort_rpl_rss *rpl)
{
	unsigned int status = rpl->status;
	unsigned int tid = GET_TID(rpl);
	struct filter_ctx *ctx = NULL;
	struct filter_entry *f;

	CH_MSG(adap, INFO, HW,
	       "%s: status = %u; tid = %u\n", __func__, status, tid);

	f = cxgb4_hashtid_lookup(adap, tid);
	if (!f) {
		CH_MSG(adap, INFO, HW, "%s:could not find filter entry",
		       __func__);
		return;
	}

	ctx = f->ctx;
	f->ctx = NULL;
	if (ctx) {
		cxgb4_hashtid_filter_clear(adap, f);
		ctx->result = 0;
		complete(&ctx->completion);
	}
}

/* Check a Chelsio Filter Request for validity, convert it into our internal
 * format and send it to the hardware.  Return 0 on success, an error number
 * otherwise.  We attach any provided filter operation context to the internal
 * filter specification in order to facilitate signaling completion of the
 * operation.  The RTNL must be held when calling this function.
 */
int cxgb4_filter_create(struct net_device *dev, u32 filter_id,
			struct ch_filter_specification *fs,
			struct filter_ctx *ctx, gfp_t flags)
{
	struct adapter *adap = netdev2adap(dev);
	int ret;

	ret = cxgb4_filter_validate(dev, fs);
	if (ret)
		return ret;

	if (fs->cap) {
		if (is_hashfilter(adap))
			return cxgb4_filter_hash_create(dev, fs, ctx, flags);

		dev_err(adap->pdev_dev,
			"Attempt to use maskless filter in non hash-filter configuration; mod-param use_ddr_filters = %d\n",
			use_ddr_filters);
		return -EINVAL;
	}

	return cxgb4_filter_normal_create(dev, filter_id, fs, ctx, flags);
}

/* Check a delete filter request for validity and send it to the hardware.
 * Return 0 on success, an error number otherwise.  We attach any provided
 * filter operation context to the internal filter specification in order to
 * facilitate signaling completion of the operation.  The RTNL must be held
 * when calling this function.
 */
int cxgb4_filter_delete(struct net_device *dev, u32 filter_id,
			struct ch_filter_specification *fs,
			struct filter_ctx *ctx, gfp_t flags)
{
	struct adapter *adapter = netdev2adap(dev);

	if (fs && fs->cap) {
		if (is_hashfilter(adapter))
			return cxgb4_filter_hash_delete(dev, filter_id, ctx,
							flags);

		dev_err(adapter->pdev_dev,
			"Attempt to use maskless filter in non hash-filter configuration; mod-param use_ddr_filters = %d\n",
			use_ddr_filters);
		return -EINVAL;
	}

	return cxgb4_filter_normal_delete(dev, filter_id, ctx, flags);
}

void cxgb4_filter_clear_all(struct adapter *adapter)
{
	struct cxgb4_tid_info *t = &adapter->tidinfo;
	struct filter_entry *f;
	u8 type, chip_ver;
	unsigned int i;

	chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);
	if (t->hpftids.size) {
		i = t->hpftids.start;
		while (!cxgb4_hpftid_out_of_range(adapter, i)) {
			type = 0;
			f = cxgb4_ftid_lookup(adapter, i);
			if (f && (f->valid || f->pending)) {
				type = f->fs.type;
				cxgb4_filter_normal_delete(f->dev, f->tid, NULL,
							   GFP_KERNEL);
			}
			i += type ? t->hpftids.max_range : 1;
		}
	}

	if (t->ftids.size) {
		i = t->ftids.start;
		while (!cxgb4_ftid_out_of_range(adapter, i)) {
			type = 0;
			f = cxgb4_ftid_lookup(adapter, i);
			if (f && (f->valid || f->pending)) {
				type = f->fs.type;
				cxgb4_filter_normal_delete(f->dev, f->tid, NULL,
							   GFP_KERNEL);
			}
			i += type ? t->ftids.max_range : 1;
		}
	}

	if (is_hashfilter(adapter) && t->hashtids.size) {
		i = t->hashcoll_tids.start;
		while (!cxgb4_hashtid_out_of_range(adapter, i)) {
			type = 0;
			f = cxgb4_hashtid_lookup(adapter, i);
			if (f && (f->valid || f->pending)) {
				type = f->fs.type;
				cxgb4_filter_hash_delete(f->dev, f->tid, NULL,
							 GFP_KERNEL);
			}
			i += type ? t->hashcoll_tids.max_range : 1;
		}

		i = t->hashtids.start;
		while (!cxgb4_hashtid_out_of_range(adapter, i)) {
			type = 0;
			f = cxgb4_hashtid_lookup(adapter, i);
			if (f && (f->valid || f->pending)) {
				type = f->fs.type;
				cxgb4_filter_hash_delete(f->dev, f->tid, NULL,
							 GFP_KERNEL);
			}
			i += type ? t->hashtids.max_range : 1;
		}
	}
}

void cxgb4_flush_all_filters(struct adapter *adapter, gfp_t flags)
{
	cxgb4_filter_clear_all(adapter);
}
EXPORT_SYMBOL(cxgb4_flush_all_filters);

/* Retrieve the packet count for the specified filter.
 */
int cxgb4_filter_get_count(struct adapter *adapter, unsigned int fidx,
			   u64 *c, int hash, bool get_byte)
{
	unsigned int tcb_base, tcbaddr;
	struct filter_entry *f;
	int ret;

	tcb_base = t4_read_reg(adapter, A_TP_CMM_TCB_BASE);
	if (is_hashfilter(adapter) && hash) {
		f = cxgb4_hashtid_lookup(adapter, fidx);
		if (!f)
			return -EINVAL;

		if (is_t5(adapter->params.chip)) {
			*c = get_byte ? f->byte_counter : f->pkt_counter;
			return 0;
		}
	} else {
		f = cxgb4_ftid_lookup(adapter, fidx);
		if (!f)
			return -EINVAL;
	}

	if (!f->valid)
		return -EINVAL;

	tcbaddr = tcb_base + f->tid * TCB_SIZE;

	if (is_t4(adapter->params.chip)) {
		/* For T4, the Filter Packet Hit Count is maintained as a
		 * 64-bit Big Endian value in the TCB fields
		 * {t_rtt_ts_recent_age, t_rtseq_recent} ...  For insanely
		 * crazy (and completely unknown) reasons, the format in
		 * memory is swizzled/mapped in a manner such that instead
		 * of having this 64-bit counter show up at offset 24
		 * ((W_TCB_T_RTT_TS_RECENT_AGE == 6) * sizeof(u32)), it
		 * actually shows up at offset 16.  After more than an hour
		 * trying to untangle things so it could be properly coded
		 * and documented here, it's simply not worth the effort.
		 * So we use an incredibly gross "4" constant instead of
		 * W_TCB_T_RTT_TS_RECENT_AGE.
		 */
		if (get_byte) {
			unsigned int word_offset = 4;
			__be64 be64_byte_count;

			spin_lock(&adapter->win0_lock);
			ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
					   tcbaddr + (word_offset * sizeof(__be32)),
					   sizeof(be64_byte_count), &be64_byte_count,
					   T4_MEMORY_READ);
			spin_unlock(&adapter->win0_lock);
			if (ret < 0)
				return ret;
			*c = be64_to_cpu(be64_byte_count);
		} else {
			unsigned int word_offset = 4;
			__be64 be64_count;

			spin_lock(&adapter->win0_lock);
			ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
					   tcbaddr + (word_offset * sizeof(__be32)),
					   sizeof(be64_count), (__be32 *)&be64_count,
					   T4_MEMORY_READ);
			spin_unlock(&adapter->win0_lock);
			if (ret < 0)
				return ret;
			*c = be64_to_cpu(be64_count);
		}
	} else {
		/* For T5, the Filter Packet Hit Count is maintained as a
		 * 32-bit Big Endian value in the TCB field {timestamp}.
		 * Similar to the craziness above, instead of the filter hit
		 * count showing up at offset 20 ((W_TCB_TIMESTAMP == 5) *
		 * sizeof(u32)), it actually shows up at offset 24.  Whacky.
		 */
		if (get_byte) {
			unsigned int word_offset = 4;
			__be64 be64_byte_count;

			spin_lock(&adapter->win0_lock);
			ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
					   tcbaddr + (word_offset * sizeof(__be32)),
					   sizeof(be64_byte_count), &be64_byte_count,
					   T4_MEMORY_READ);
			spin_unlock(&adapter->win0_lock);
			if (ret < 0)
				return ret;
			*c = be64_to_cpu(be64_byte_count);
		} else {
			unsigned int word_offset = 6;
			__be32 be32_count;

			spin_lock(&adapter->win0_lock);
			ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
					   tcbaddr + (word_offset * sizeof(__be32)),
					   sizeof(be32_count), &be32_count,
					   T4_MEMORY_READ);
			spin_unlock(&adapter->win0_lock);
			if (ret < 0)
				return ret;
			*c = (u64)be32_to_cpu(be32_count);
		}
	}

	return 0;
}

int cxgb4_filter_get_counters(struct net_device *dev, unsigned int fidx,
			      u64 *hitcnt, u64 *bytecnt, int hash)
{
	struct adapter *adapter = netdev2adap(dev);
	int ret;

	ret = cxgb4_filter_get_count(adapter, fidx, hitcnt, hash, false);
	if (ret < 0)
		return ret;

	return cxgb4_filter_get_count(adapter, fidx, bytecnt, hash, true);
}
EXPORT_SYMBOL(cxgb4_filter_get_counters);

static int cxgb4_filter_ehash_locks_alloc(struct filter_hashinfo *hashinfo)
{
	unsigned int i, size = 256;
#if defined(CONFIG_PROVE_LOCKING)
	unsigned int nr_pcpus = 2;
#else
	unsigned int nr_pcpus = num_possible_cpus();
#endif
	if (nr_pcpus >= 4)
		size = 512;
	if (nr_pcpus >= 8)
		size = 1024;
	if (nr_pcpus >= 16)
		size = 2048;
	if (nr_pcpus >= 32)
		size = 4096;
	if (sizeof(spinlock_t) != 0) {
#ifdef CONFIG_NUMA
		if (size * sizeof(spinlock_t) > PAGE_SIZE)
			hashinfo->ehash_filter_locks =
				vmalloc(size * sizeof(spinlock_t));
		else
#endif
			hashinfo->ehash_filter_locks =
				kmalloc(size * sizeof(spinlock_t), GFP_KERNEL);
		if (!hashinfo->ehash_filter_locks)
			return -ENOMEM;
		for (i = 0; i < size; i++)
			spin_lock_init(&hashinfo->ehash_filter_locks[i]);
	}
	hashinfo->ehash_filter_locks_mask = size - 1;
	return 0;
}

int cxgb4_hash_filter_config_verify(struct adapter *adap, bool offload_caps)
{
	u32 val;

	if (CHELSIO_CHIP_VERSION(adap->params.chip) < CHELSIO_T5)
		return 0;

	if (CHELSIO_CHIP_VERSION(adap->params.chip) == CHELSIO_T5) {
		if (offload_caps)
			return -EOPNOTSUPP;

		return 0;
	}

	/* On T6+, if hash filter is enabled with or without ofld enabled, verify
	 * necessary register configs and warn the user in case of improper
	 * config.
	 */
	if (offload_caps) {
		val = t4_read_reg(adap, A_TP_GLOBAL_CONFIG);
		if (!(val & F_ACTIVEFILTERCOUNTS)) {
			dev_warn(adap->pdev_dev,
				 "Invalid hash filter + ofld config: reg[0x%x] = 0x%x\n",
				 A_TP_GLOBAL_CONFIG, val);
			return -EOPNOTSUPP;
		}
	} else {
		val = t4_read_reg(adap, A_LE_DB_RSP_CODE_0);
		if (G_TCAM_ACTV_HIT(val) != 4) {
			dev_warn(adap->pdev_dev,
				 "Invalid hash filter config: [0x%x]=0x%x\n",
				 A_LE_DB_RSP_CODE_0, val);
			return -EOPNOTSUPP;
		}

		val = t4_read_reg(adap, A_LE_DB_RSP_CODE_1);
		if (G_HASH_ACTV_HIT(val) != 4) {
			dev_warn(adap->pdev_dev,
				 "Invalid hash filter config: [0x%x]=0x%x\n",
				 A_LE_DB_RSP_CODE_1, val);
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

int cxgb4_hash_filter_init(struct adapter *adap)
{
	unsigned int hash_size = adap->tidinfo.hashtids.size;
	int i;

	if (!hash_size)
		return 0;

	adap->filter_tcphash.ehash_mask = hash_size - 1;
	adap->filter_udphash.ehash_mask = hash_size - 1;
	adap->filter_tcphash.ehash = t4_alloc_mem(hash_size *
					sizeof(struct filter_ehash_bucket));

	if (!adap->filter_tcphash.ehash) {
		pr_err("%s: No mem for filter_tcphash.ehash ..\n",
		       __func__);
		return -ENOMEM;
	}

	if (cxgb4_filter_ehash_locks_alloc(&adap->filter_tcphash)) {
		pr_err("%s: Failed to alloc locks for filter_tcphash ..\n",
		       __func__);
		t4_free_mem(adap->filter_tcphash.ehash);
		return -ENOMEM;
	}

	adap->filter_udphash.ehash = t4_alloc_mem(hash_size *
					sizeof(struct filter_ehash_bucket));

	if (!adap->filter_udphash.ehash) {
		pr_err("%s: No mem for filter_udphash.ehash ..\n",
		       __func__);
		ehash_filter_locks_free(&adap->filter_tcphash);
		t4_free_mem(adap->filter_tcphash.ehash);
		return -ENOMEM;
	}

	if (cxgb4_filter_ehash_locks_alloc(&adap->filter_udphash)) {
		pr_err("%s: Failed to alloc locks for filter_udphash ..\n",
		       __func__);
		t4_free_mem(adap->filter_udphash.ehash);
		ehash_filter_locks_free(&adap->filter_tcphash);
		t4_free_mem(adap->filter_tcphash.ehash);
		return -ENOMEM;
	}

	for (i = 0; i <= adap->filter_tcphash.ehash_mask; i++)
		INIT_HLIST_NULLS_HEAD(&adap->filter_tcphash.ehash[i].chain, i);

	for (i = 0; i <= adap->filter_udphash.ehash_mask; i++)
		INIT_HLIST_NULLS_HEAD(&adap->filter_udphash.ehash[i].chain, i);

	adap->params.hash_filter = 1;
	return 0;
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
int cxgb4_uld_filter_create(struct net_device *dev, u32 filter_id,
			    struct ch_filter_specification *fs,
			    struct filter_ctx *ctx, gfp_t flags)
{
	return cxgb4_filter_create(dev, filter_id, fs, ctx, flags);
}
EXPORT_SYMBOL(cxgb4_uld_filter_create);

int cxgb4_uld_filter_delete(struct net_device *dev, u32 filter_id,
			    struct ch_filter_specification *fs,
			    struct filter_ctx *ctx, gfp_t flags)
{
	return cxgb4_filter_delete(dev, filter_id, fs, ctx, flags);
}
EXPORT_SYMBOL(cxgb4_uld_filter_delete);

int cxgb4_uld_server_filter_insert(const struct net_device *dev, u32 stid,
				   __be32 sip, __be16 sport, __be16 vlan,
				   u32 queue, u8 port, u8 port_mask)
{
	struct adapter *adap = netdev2adap(dev);
	struct filter_entry *f;
	int i, ret;
	u8 *val;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;

	ret = cxgb4_ftid_insert(adap, f, stid, 0);
	if (ret)
		goto out_free;

	f->fs.val.lport = cpu_to_be16(sport);
	f->fs.mask.lport = ~0;
	val = (u8 *)&sip;
	if ((val[0] | val[1] | val[2] | val[3]) != 0) {
		for (i = 0; i < 4; i++) {
			f->fs.val.lip[i] = val[i];
			f->fs.mask.lip[i] = ~0;
		}
		if (adap->params.tp.vlan_pri_map & F_PORT) {
			f->fs.val.iport = port;
			f->fs.mask.iport = port_mask;
		}
	}

	if (adap->params.tp.vlan_pri_map & F_PROTOCOL) {
		f->fs.val.proto = IPPROTO_TCP;
		f->fs.mask.proto = ~0;
	}

	/* This code demonstrates how one would selectively Offload
	 * (TOE) certain incoming connections by using the extended
	 * "Filter Information" capabilities of Server Control Blocks
	 * (SCB).  (See "Classification and Filtering" in the T4 Data
	 * Book for a description of Ingress Packet pattern matching
	 * capabilities.  See also documentation on the
	 * TP_VLAN_PRI_MAP register.)  Because this selective
	 * Offloading is happening in the chip, this allows
	 * non-Offloading and Offloading drivers to coexist.  For
	 * example, an Offloading Driver might be running in a
	 * Hypervisor while non-Offloading vNIC Drivers might be
	 * running in Virtual Machines.
	 *
	 * This particular example code demonstrates how one would
	 * selectively Offload incoming connections based on VLANs.
	 * We allow one VLAN to be designated as the "Offloading
	 * VLAN".  Ingress SYNs on this Offload VLAN will match the
	 * filter which we put into the Listen SCB and will result in
	 * Offloaded Connections on that VLAN.  Incoming SYNs on other
	 * VLANs will not match and will go through normal NIC
	 * processing.
	 *
	 * This is not production code since one would want a lot more
	 * infrastructure to allow a variety of filter specifications
	 * on a per-server basis.  But this demonstrates the
	 * fundamental mechanisms one would use to build such an
	 * infrastructure.
	 */
	if (vlan && (adap->params.tp.vlan_pri_map & F_VLAN)) {
		f->fs.val.ivlan_vld = 1;
		f->fs.val.ivlan = be16_to_cpu(vlan);
		f->fs.mask.ivlan_vld = ~0;
		f->fs.mask.ivlan = ~0;
	}

	f->fs.dirsteer = 1;
	f->fs.iq = queue;
	/* Mark filter as locked */
	f->locked = 1;
	f->fs.rpttid = 1;

	/* Save the actual tid. We need this to get the corresponding
	 * filter entry structure in filter_rpl.
	 */
	f->tid = stid;
	ret = cxgb4_filter_normal_create_wr(adap, f, GFP_KERNEL);
	if (ret)
		goto out_filter_free;

	return 0;

out_filter_free:
	cxgb4_ftid_filter_clear(adap, f);
	return ret;

out_free:
	kfree(f);
	return ret;
}
EXPORT_SYMBOL(cxgb4_uld_server_filter_insert);

int cxgb4_uld_server_filter_remove(const struct net_device *dev, u32 stid)
{
	struct adapter *adap = netdev2adap(dev);
	struct filter_entry *f;
	int ret;

	f = cxgb4_ftid_lookup(adap, stid);
	if (!f || !f->valid)
		return -ENOENT;

	/* Unlock the filter */
	f->locked = 0;

	ret = cxgb4_filter_normal_delete_wr(adap, f, GFP_KERNEL);
	if (!ret)
		cxgb4_ftid_filter_clear(adap, f);

	return ret;
}
EXPORT_SYMBOL(cxgb4_uld_server_filter_remove);

/**
 *	cxgb4_uld_create_filter_info - return Compressed Filter Value/Mask tuple
 *	@dev: the device
 *	@filter_value: Filter Value return value pointer
 *	@filter_mask: Filter Mask return value pointer
 *	@fcoe: FCoE filter selection
 *	@port: physical port filter selection
 *	@vnic: Virtual NIC ID filter selection
 *	@vlan: VLAN ID filter selection
 *	@vlan_pcp: VLAN Priority Code Point filter selection
 *	@vlan_dei: VLAN Drop Eligibility Indicator filter selection
 *	@tos: Type Of Server filter selection
 *	@protocol: IP Protocol filter selection
 *	@ethertype: Ethernet Type filter selection
 *	@macmatch: MPS MAC Index filter selection
 *	@matchtype: MPS Hit Type filter selection
 *	@frag: IP Fragmentation filter selection
 *
 *	Exported Symbols front end to the Common Code t4_create_filter_info()
 *	API.  On error, returns a negative error code.  On success, returns 0
 *	and Filter Value/Mask Tuple given the various file field selections.
 */
int cxgb4_uld_create_filter_info(const struct net_device *dev,
				 u64 *filter_value, u64 *filter_mask,
				 int fcoe, int port, int vnic,
				 int vlan, int vlan_pcp, int vlan_dei,
				 int tos, int protocol, int ethertype,
				 int macmatch, int matchtype, int frag)
{
	const struct adapter *adap = netdev2adap(dev);

	return t4_create_filter_info(adap, filter_value, filter_mask, fcoe,
				     port, vnic, vlan, vlan_pcp, vlan_dei, tos,
				     protocol, ethertype, macmatch, matchtype,
				     frag);
}
EXPORT_SYMBOL(cxgb4_uld_create_filter_info);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

/* Filter Table Debugfs.
 */
static void cxgb4_filter_debugfs_show_field_name(struct seq_file *seq,
						 u32 chip_ver, u8 offset,
						 u32 fconf, u32 tpiconf)
{
	if (chip_ver >= CHELSIO_T7) {
		switch (fconf & (1 << offset)) {
		case 0:
			/* Compressed filter field not enabled */
			break;
		case F_IPSECIDX:
			seq_puts(seq, " IPSecIdx");
			break;
		case F_T7_FCOE:
			seq_puts(seq, " FCoE");
			break;
		case F_T7_PORT:
			seq_puts(seq, " Port");
			break;
		case F_T7_VNIC_ID:
			if (tpiconf & F_USE_ENC_IDX)
				seq_puts(seq, "    vld:MPS:Id");
			else if(tpiconf & F_VNIC)
				seq_puts(seq, "   VFvld:PF:VF");
			else
				seq_puts(seq, "     vld:oVLAN");
			break;
		case F_T7_VLAN:
			seq_puts(seq, "     vld:iVLAN");
			break;
		case F_T7_TOS:
			seq_puts(seq, "   TOS");
			break;
		case F_T7_PROTOCOL:
			seq_puts(seq, "  Prot");
			break;
		case F_T7_ETHERTYPE:
			seq_puts(seq, "   EthType");
			break;
		case F_T7_MACMATCH:
			seq_puts(seq, "  MACIdx");
			break;
		case F_T7_MPSHITTYPE:
			seq_puts(seq, " MPS");
			break;
		case F_T7_FRAGMENTATION:
			seq_puts(seq, " Frag");
			break;
		case F_ROCE:
			seq_puts(seq, " RoCE");
			break;
		case F_SYNONLY:
			seq_puts(seq, " SYN");
			break;
		case F_TCPFLAGS:
			seq_puts(seq, " TCPFlags");
			break;
		}

		return;
	}

	switch (fconf & (1 << offset)) {
	case 0:
		/* Compressed filter field not enabled */
		break;
	case F_FCOE:
		seq_puts(seq, " FCoE");
		break;
	case F_PORT:
		seq_puts(seq, " Port");
		break;
	case F_VNIC_ID:
		if (tpiconf & F_USE_ENC_IDX)
			seq_puts(seq, "    vld:MPS:Id");
		else if(tpiconf & F_VNIC)
			seq_puts(seq, "   VFvld:PF:VF");
		else
			seq_puts(seq, "     vld:oVLAN");
		break;
	case F_VLAN:
		seq_puts(seq, "     vld:iVLAN");
		break;
	case F_TOS:
		seq_puts(seq, "   TOS");
		break;
	case F_PROTOCOL:
		seq_puts(seq, "  Prot");
		break;
	case F_ETHERTYPE:
		seq_puts(seq, "   EthType");
		break;
	case F_MACMATCH:
		seq_puts(seq, "  MACIdx");
		break;
	case F_MPSHITTYPE:
		seq_puts(seq, " MPS");
		break;
	case F_FRAGMENTATION:
		seq_puts(seq, " Frag");
		break;
	}
}

static void cxgb4_filter_debugfs_show_field_data(struct seq_file *seq,
						 u32 chip_ver, u8 offset,
						 u32 fconf, u32 tpiconf,
						 struct filter_entry *f)
{
	if (chip_ver >= CHELSIO_T7) {
		switch (fconf & (1 << offset)) {
		case 0:
			/* Compressed filter field not enabled */
			break;
		case F_IPSECIDX:
			seq_printf(seq, "  %04x/%04x", f->fs.val.ipsecidx,
				   f->fs.mask.ipsecidx);
			break;
		case F_T7_FCOE:
			seq_printf(seq, "  %1d/%1d", f->fs.val.fcoe,
				   f->fs.mask.fcoe);
			break;
		case F_T7_PORT:
			seq_printf(seq, "  %1d/%1d", f->fs.val.iport,
				   f->fs.mask.iport);
			break;
		case F_T7_VNIC_ID:
			if (tpiconf & F_USE_ENC_IDX)
				seq_printf(seq, " %1d:%1x:%02x/%1d:%1x:%02x",
					   f->fs.val.ovlan_vld,
					   (f->fs.val.ovlan >> 9) & 0x7,
					   f->fs.val.ovlan & 0x1ff,
					   f->fs.mask.ovlan_vld,
					   (f->fs.mask.ovlan >> 9) & 0x7,
					   f->fs.mask.ovlan & 0x1ff);
			else if (tpiconf & F_VNIC)
				seq_printf(seq, " %1d:%1x:%02x/%1d:%1x:%02x",
					   f->fs.val.ovlan_vld,
					   (f->fs.val.ovlan >> 13) & 0x7,
					   f->fs.val.ovlan & 0x7f,
					   f->fs.mask.ovlan_vld,
					   (f->fs.mask.ovlan >> 13) & 0x7,
					   f->fs.mask.ovlan & 0x7f);
			else
				seq_printf(seq, " %1d:%04x/%1d:%04x",
					   f->fs.val.ovlan_vld,
					   f->fs.val.ovlan,
					   f->fs.mask.ovlan_vld,
					   f->fs.mask.ovlan);
			break;
		case F_T7_VLAN:
			seq_printf(seq, " %1d:%04x/%1d:%04x",
				   f->fs.val.ivlan_vld,
				   f->fs.val.ivlan,
				   f->fs.mask.ivlan_vld,
				   f->fs.mask.ivlan);
			break;
		case F_T7_TOS:
			seq_printf(seq, " %02x/%02x", f->fs.val.tos,
				   f->fs.mask.tos);
			break;
		case F_T7_PROTOCOL:
			seq_printf(seq, " %02x/%02x", f->fs.val.proto,
				   f->fs.mask.proto);
			break;
		case F_T7_ETHERTYPE:
			seq_printf(seq, " %04x/%04x", f->fs.val.ethtype,
				   f->fs.mask.ethtype);
			break;
		case F_T7_MACMATCH:
			seq_printf(seq, " %03x/%03x", f->fs.val.macidx,
				   f->fs.mask.macidx);
			break;
		case F_T7_MPSHITTYPE:
			seq_printf(seq, " %1x/%1x", f->fs.val.matchtype,
				   f->fs.mask.matchtype);
			break;
		case F_T7_FRAGMENTATION:
			seq_printf(seq, "  %1d/%1d", f->fs.val.frag,
				   f->fs.mask.frag);
			break;
		case F_ROCE:
			seq_printf(seq, "  %1d/%1d", f->fs.val.roce,
				   f->fs.mask.roce);
			break;
		case F_SYNONLY:
			seq_printf(seq, "  %1d/%1d", f->fs.val.synonly,
				   f->fs.mask.synonly);
			break;
		case F_TCPFLAGS:
			seq_printf(seq, "  %04x/%04x", f->fs.val.tcpflags,
				   f->fs.mask.tcpflags);
			break;
		}

		return;
	}

	switch (fconf & (1 << offset)) {
	case 0:
		/* Compressed filter field not enabled */
		break;
	case F_FCOE:
		seq_printf(seq, "  %1d/%1d", f->fs.val.fcoe, f->fs.mask.fcoe);
		break;
	case F_PORT:
		seq_printf(seq, "  %1d/%1d", f->fs.val.iport, f->fs.mask.iport);
		break;
	case F_VNIC_ID:
		if (tpiconf & F_USE_ENC_IDX)
			seq_printf(seq, " %1d:%1x:%02x/%1d:%1x:%02x",
				   f->fs.val.ovlan_vld,
				   (f->fs.val.ovlan >> 9) & 0x7,
				   f->fs.val.ovlan & 0x1ff,
				   f->fs.mask.ovlan_vld,
				   (f->fs.mask.ovlan >> 9) & 0x7,
				   f->fs.mask.ovlan & 0x1ff);
		else if (tpiconf & F_VNIC)
			seq_printf(seq, " %1d:%1x:%02x/%1d:%1x:%02x",
				   f->fs.val.ovlan_vld,
				   (f->fs.val.ovlan >> 13) & 0x7,
				   f->fs.val.ovlan & 0x7f,
				   f->fs.mask.ovlan_vld,
				   (f->fs.mask.ovlan >> 13) & 0x7,
				   f->fs.mask.ovlan & 0x7f);
		else
			seq_printf(seq, " %1d:%04x/%1d:%04x",
				   f->fs.val.ovlan_vld,
				   f->fs.val.ovlan,
				   f->fs.mask.ovlan_vld,
				   f->fs.mask.ovlan);
		break;
	case F_VLAN:
		seq_printf(seq, " %1d:%04x/%1d:%04x",
			   f->fs.val.ivlan_vld,
			   f->fs.val.ivlan,
			   f->fs.mask.ivlan_vld,
			   f->fs.mask.ivlan);
		break;
	case F_TOS:
		seq_printf(seq, " %02x/%02x", f->fs.val.tos, f->fs.mask.tos);
		break;
	case F_PROTOCOL:
		seq_printf(seq, " %02x/%02x", f->fs.val.proto,
			   f->fs.mask.proto);
		break;
	case F_ETHERTYPE:
		seq_printf(seq, " %04x/%04x", f->fs.val.ethtype,
			   f->fs.mask.ethtype);
		break;
	case F_MACMATCH:
		seq_printf(seq, " %03x/%03x", f->fs.val.macidx,
			   f->fs.mask.macidx);
		break;
	case F_MPSHITTYPE:
		seq_printf(seq, " %1x/%1x", f->fs.val.matchtype,
			   f->fs.mask.matchtype);
		break;
	case F_FRAGMENTATION:
		seq_printf(seq, "  %1d/%1d", f->fs.val.frag, f->fs.mask.frag);
		break;
	}
}

static void cxgb4_filter_debugfs_show_ipaddr(struct seq_file *seq,
					     int type, u8 *addr, u8 *addrm)
{
	int noctets, octet;

	seq_puts(seq, " ");
	if (type == 0) {
		noctets = 4;
		seq_printf(seq, "%48s", " ");
	} else
		noctets = 16;

	for (octet = 0; octet < noctets; octet++)
		seq_printf(seq, "%02x", addr[octet]);
	seq_puts(seq, "/");
	for (octet = 0; octet < noctets; octet++)
		seq_printf(seq, "%02x", addrm[octet]);
}

static void cxgb4_filter_debugfs_display(struct seq_file *seq, u32 fidx,
					 struct filter_entry *f, int hash)
{
	struct adapter *adap = seq->private;
	u32 fconf, tpiconf, chip_ver;
	u8 first, last;
	int i;

	fconf = adap->params.tp.vlan_pri_map;
	tpiconf = adap->params.tp.ingress_config;
	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	if (chip_ver >= CHELSIO_T7) {
		first = S_T7_FT_FIRST;
		last = S_T7_FT_LAST;
	} else {
		first = S_FT_FIRST;
		last = S_FT_LAST;
	}

	/* Filter index. */
	/* T7: for both ipv4 and ipv6, the hash tid is only one, So fall to ipv4 print here */
	if (f->fs.type && !(hash && chip_ver >= CHELSIO_T7))
		seq_printf(seq, "%4d ..%4d%c%c", fidx,
			   chip_ver < CHELSIO_T6 ? fidx+3 : fidx+1,
			   (!f->locked  ? ' ' : '!'),
			   (!f->pending ? ' ' : (!f->valid ? '+' : '-')));
	else
		seq_printf(seq, "%4d       %c%c", fidx,
			   (!f->locked  ? ' ' : '!'),
			   (!f->pending ? ' ' : (!f->valid ? '+' : '-')));

	if (f->fs.hitcnts) {
		u64 hitcnt;
		int ret;

		ret = cxgb4_filter_get_count(adap, f->tid, &hitcnt, hash, false);
		if (ret)
			seq_printf(seq, " %20s", "hits={ERROR}");
		else
			seq_printf(seq, " %20llu", hitcnt);

		ret = cxgb4_filter_get_count(adap, f->tid, &hitcnt, hash, true);
		if (ret)
			seq_printf(seq, " %20s", "bytes={ERROR}");
		else
			seq_printf(seq, " %20llu", hitcnt);
	} else {
		seq_printf(seq, " %20s", "Disabled");
		seq_printf(seq, " %20s", "Disabled");
	}

	/* Compressed header portion of filter. */
	for (i = first; i <= last; i++)
		cxgb4_filter_debugfs_show_field_data(seq, chip_ver, i, fconf,
						     tpiconf, f);

	/* Fixed portion of filter. */
	cxgb4_filter_debugfs_show_ipaddr(seq, f->fs.type, f->fs.val.lip,
					 f->fs.mask.lip);
	cxgb4_filter_debugfs_show_ipaddr(seq, f->fs.type, f->fs.val.fip,
					 f->fs.mask.fip);
	seq_printf(seq, " %04x/%04x %04x/%04x",
		   f->fs.val.lport, f->fs.mask.lport,
		   f->fs.val.fport, f->fs.mask.fport);

	/* Variable length filter action. */
	if (f->fs.action == FILTER_DROP)
		seq_puts(seq, " Drop");
	else if (f->fs.action == FILTER_SWITCH) {
		seq_printf(seq, " Switch: port=%d", f->fs.eport);
		if (f->fs.newdmac)
			seq_printf(seq,
				   ", dmac=%02x:%02x:%02x:%02x:%02x:%02x"
				   ", l2tidx=%d",
				   f->fs.dmac[0], f->fs.dmac[1],
				   f->fs.dmac[2], f->fs.dmac[3],
				   f->fs.dmac[4], f->fs.dmac[5],
				   f->l2t->idx);
		if (f->fs.newsmac)
			seq_printf(seq,
				   ", smac=%02x:%02x:%02x:%02x:%02x:%02x"
				   ", smtidx=%d",
				   f->fs.smac[0], f->fs.smac[1],
				   f->fs.smac[2], f->fs.smac[3],
				   f->fs.smac[4], f->fs.smac[5],
				   f->smtidx);
		if (f->fs.newvlan == VLAN_REMOVE)
			seq_printf(seq, ", vlan=none");
		else if (f->fs.newvlan == VLAN_INSERT)
			seq_printf(seq, ", vlan=insert(%x)",
					f->fs.vlan);
		else if (f->fs.newvlan == VLAN_REWRITE)
			seq_printf(seq, ", vlan=rewrite(%x)",
					f->fs.vlan);
	} else {
		seq_puts(seq, " Pass: Q=");
		if (f->fs.dirsteer == 0) {
			seq_puts(seq, "RSS");
			if (f->fs.maskhash)
				seq_puts(seq, "(TCB=hash)");
		} else {
			seq_printf(seq, "%d", f->fs.iq);
			if (f->fs.dirsteerhash == 0)
				seq_puts(seq, "(QID)");
			else
				seq_puts(seq, "(hash)");
		}
	}
	if (f->fs.prio)
		seq_puts(seq, " Prio");
	if (f->fs.rpttid)
		seq_puts(seq, " RptTID");
	seq_puts(seq, "\n");
}

static int cxgb4_filter_normal_debugfs_show(struct seq_file *seq, void *v)
{
	struct adapter *adap = seq->private;
	u32 fconf, tpiconf, chip_ver;
	struct cxgb4_tid_info *t;
	u8 first, last;
	int i;

	fconf = adap->params.tp.vlan_pri_map;
	tpiconf = adap->params.tp.ingress_config;
	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	if (chip_ver >= CHELSIO_T7) {
		first = S_T7_FT_FIRST;
		last = S_T7_FT_LAST;
	} else {
		first = S_FT_FIRST;
		last = S_FT_LAST;
	}

	t = &adap->tidinfo;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "[[Legend: "
			 "'!' => locked; "
			 "'+' => pending set; "
			 "'-' => pending clear]]\n");
		seq_puts(seq, " Idx                          Hits");
		seq_puts(seq, "            Hit-Bytes");
		for (i = first; i <= last; i++)
			cxgb4_filter_debugfs_show_field_name(seq, chip_ver,
							     i, fconf, tpiconf);
		seq_printf(seq, " %65s %65s %9s %9s %s\n",
			   "LIP", "FIP", "LPORT", "FPORT", "Action");
	} else {
		u32 ftid, fidx = (uintptr_t)v - 2;
		struct filter_entry *f;

		ftid = fidx + t->hpftids.start;
		if (cxgb4_hpftid_out_of_range(adap, ftid))
			ftid += t->ftids.start - t->hpftids.size;

		f = cxgb4_ftid_lookup(adap, ftid);

		/* If this entry isn't filled in just return */
		if (!f || (!f->valid && !f->pending))
			return 0;

		cxgb4_filter_debugfs_display(seq, fidx, f, 0);
	}
	return 0;
}

static inline void *cxgb4_filter_normal_debugfs_get_idx(struct adapter *adap,
							loff_t pos)
{
	if (pos > (adap->tidinfo.ftids.size + adap->tidinfo.hpftids.size))
		return NULL;

	return (void *)(uintptr_t)(pos + 1);
}

static void *cxgb4_filter_normal_debugfs_start(struct seq_file *seq,
					       loff_t *pos)
{
	struct adapter *adap = seq->private;

	return (*pos ? cxgb4_filter_normal_debugfs_get_idx(adap, *pos) :
		       SEQ_START_TOKEN);
}

static void *cxgb4_filter_normal_debugfs_next(struct seq_file *seq, void *v,
					      loff_t *pos)
{
	struct adapter *adap = seq->private;

	(*pos)++;
	return cxgb4_filter_normal_debugfs_get_idx(adap, *pos);
}

static void cxgb4_filter_normal_debugfs_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations filters_seq_ops = {
	.start = cxgb4_filter_normal_debugfs_start,
	.next  = cxgb4_filter_normal_debugfs_next,
	.stop  = cxgb4_filter_normal_debugfs_stop,
	.show  = cxgb4_filter_normal_debugfs_show
};

static int cxgb4_filter_normal_debugfs_open(struct inode *inode,
					    struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	int res;

	res = seq_open(file, &filters_seq_ops);
	if (!res) {
		struct seq_file *seq = file->private_data;

		seq->private = adap;
	}
	return res;
}

const struct file_operations filters_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = cxgb4_filter_normal_debugfs_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
};

static int cxgb4_filter_hash_debugfs_show(struct seq_file *seq, void *v)
{
	struct adapter *adap = seq->private;
	u32 fconf, tpiconf, chip_ver;
	u8 first, last;
	int i;

	fconf = adap->params.tp.vlan_pri_map;
	tpiconf = adap->params.tp.ingress_config;
	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	if (chip_ver >= CHELSIO_T7) {
		first = S_T7_FT_FIRST;
		last = S_T7_FT_LAST;
	} else {
		first = S_FT_FIRST;
		last = S_FT_LAST;
	}

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "[[Legend: "
			 "'!' => locked; "
			 "'+' => pending set; "
			 "'-' => pending clear]]\n");
		seq_puts(seq, " Idx                          Hits");
		seq_puts(seq, "            Hit-Bytes");
		for (i = first; i <= last; i++)
			cxgb4_filter_debugfs_show_field_name(seq, chip_ver,
							     i, fconf, tpiconf);
		seq_printf(seq, " %65s %65s %9s %9s %s\n",
			   "LIP", "FIP", "LPORT", "FPORT", "Action");
	} else {
		int fidx = (uintptr_t)v - 2;
		struct filter_entry *f;
		spinlock_t *lock; /* Lock for accessing ehash table */

		if (!is_hashfilter(adap))
			return 0;

		f = cxgb4_hashtid_lookup(adap, fidx);
		if (!f)
			return 0;

		if (f->fs.val.proto == IPPROTO_UDP)
			lock = &adap->filter_udphash.ehash_filter_locks[f->filter_hash &
				adap->filter_udphash.ehash_filter_locks_mask];
		else
			lock = &adap->filter_tcphash.ehash_filter_locks[f->filter_hash &
				adap->filter_tcphash.ehash_filter_locks_mask];
		spin_lock_bh(lock);
		/* If this entry isn't filled in just return */
		if (!f->valid) {
			spin_unlock_bh(lock);
			return 0;
		}

		cxgb4_filter_debugfs_display(seq, fidx, f, 1);
		spin_unlock_bh(lock);
	}
	return 0;
}

static inline void *cxgb4_filter_hash_debugfs_get_idx(struct adapter *adap,
						      loff_t pos)
{
	if (!is_hashfilter(adap))
		return NULL;

	if (pos > adap->tidinfo.hashtids.start + adap->tidinfo.hashtids.size)
		return NULL;

	return (void *)(uintptr_t)(pos + 1);
}

static void *cxgb4_filter_hash_debugfs_start(struct seq_file *seq, loff_t *pos)
{
	struct adapter *adap = seq->private;

	return (*pos ? cxgb4_filter_hash_debugfs_get_idx(adap, *pos) :
		       SEQ_START_TOKEN);
}

static void *cxgb4_filter_hash_debugfs_next(struct seq_file *seq, void *v,
					    loff_t *pos)
{
	struct adapter *adap = seq->private;

	(*pos)++;
	return cxgb4_filter_hash_debugfs_get_idx(adap, *pos);
}

static void cxgb4_filter_hash_debugfs_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations hash_filters_seq_ops = {
	.start = cxgb4_filter_hash_debugfs_start,
	.next  = cxgb4_filter_hash_debugfs_next,
	.stop  = cxgb4_filter_hash_debugfs_stop,
	.show  = cxgb4_filter_hash_debugfs_show
};

static int cxgb4_filter_hash_debugfs_open(struct inode *inode,
					  struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	int res;

	res = seq_open(file, &hash_filters_seq_ops);
	if (!res) {
		struct seq_file *seq = file->private_data;

		seq->private = adap;
	}
	return res;
}

const struct file_operations hash_filters_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = cxgb4_filter_hash_debugfs_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
};
