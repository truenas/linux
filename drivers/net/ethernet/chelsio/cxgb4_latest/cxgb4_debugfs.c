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

#include <linux/seq_file.h>
#include <linux/debugfs.h>

#include "common.h"
#include "cxgbtool.h"
#include "cxgb4_cxgbtool.h"
#include "cxgb4_filter.h"
#include "t4_regs.h"
#include "t4_regs_values.h"
#include "t4_msg.h"
#include "t4_tcb.h"
#include "t4fw_interface.h"
#include "t4_ma_failover.h"
#include "t4_linux_fs.h"
#include "cxgb4_dcb.h"
#include "smt.h"
#include "srq.h"
#include "l2t.h"
#include "clip_tbl.h"
#include "cxgb4_debugfs.h"

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#include "cxgb4_ofld.h"
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

/*
 * debugfs support
 */

DEFINE_SIMPLE_DEBUGFS_FILE(clip_tbl);

/*
 * Read a vector of numbers from a user space buffer.  Each number must be
 * between min and max inclusive and in the given base.
 */
static int rd_usr_int_vec(const char __user *buf, size_t usr_len, int vec_len,
			  unsigned long *vals, unsigned long min,
			  unsigned long max, int base)
{
	size_t l;
	unsigned long v;
	char c, word[68], *end;

	while (usr_len) {
		/* skip whitespace to beginning of next word */
		while (usr_len) {
			if (get_user(c, buf))
				return -EFAULT;
			if (!isspace(c))
				break;
			usr_len--;
			buf++;
		}

		if (!usr_len)
			break;
		if (!vec_len)
			return -EINVAL;              /* too many numbers */

		/* get next word (possibly going beyond its end) */
		l = min(usr_len, sizeof(word) - 1);
		if (copy_from_user(word, buf, l))
			return -EFAULT;
		word[l] = '\0';

		v = simple_strtoul(word, &end, base);
		l = end - word;
		if (!l)
			return -EINVAL;              /* catch embedded '\0's */
		if (*end && !isspace(*end))
			return -EINVAL;
		/*
		 * Complain if we encountered a too long sequence of digits.
		 * The most we can consume in one iteration is for a 64-bit
		 * number in binary.  Too bad simple_strtoul doesn't catch
		 * overflows.
		 */
		if (l > 64)
			return -EINVAL;
		if (v < min || v > max)
			return -ERANGE;
		*vals++ = v;
		vec_len--;
		usr_len -= l;
		buf += l;
	}
	if (vec_len)
		return -EINVAL;                      /* not enough numbers */
	return 0;
}

#ifdef CONFIG_CXGB4_DCB
extern char *dcb_ver_array[];

/*
 * Data Center Briging information for each port.
 */
static int dcb_info_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Data Center Bridging Information\n");
	else {
		int port = (uintptr_t)v - 2;
		struct net_device *dev = adap->port[port];
		struct port_info *pi = netdev2pinfo(dev);
		struct port_dcb_info *dcb = &pi->dcb;

		seq_puts(seq, "\n");
		seq_printf(seq, "Port: %d (DCB negotiated: %s)\n",
			   port,
			   cxgb4_dcb_enabled(dev) ? "yes" : "no");

		if (cxgb4_dcb_enabled(dev))
			seq_printf(seq, "[ DCBx Version %s ]\n",
				   dcb_ver_array[dcb->dcb_version]);

		if (dcb->msgs) {
			int i;

			seq_puts(seq, "\n  Index\t\t\t  :\t");
			for (i = 0; i < 8; i++)
				seq_printf(seq, " %3d", i);
			seq_puts(seq, "\n\n");
		}

		if (dcb->msgs & CXGB4_DCB_FW_PGID) {
			int prio, pgid;

			seq_puts(seq, "  Priority Group IDs\t  :\t");
			for (prio = 0; prio < 8; prio++) {
				pgid = (dcb->pgid >> 4*(7 - prio)) & 0xf;
				seq_printf(seq, " %3d", pgid);
			}
			seq_puts(seq, "\n");
		}

		if (dcb->msgs & CXGB4_DCB_FW_PGRATE) {
			int pg;

			seq_puts(seq, "  Priority Group BW(%)\t  :\t");
			for (pg = 0; pg < 8; pg++)
				seq_printf(seq, " %3d", dcb->pgrate[pg]);
			seq_puts(seq, "\n");

			if (dcb->dcb_version == FW_PORT_DCB_VER_IEEE) {
				seq_puts(seq, "  TSA Algorithm\t\t  :\t");
				for (pg = 0; pg < 8; pg++)
					seq_printf(seq, " %3d", dcb->tsa[pg]);
				seq_puts(seq, "\n");
			}

			seq_printf(seq, "  Max PG Traffic Classes  [%3d  ]\n",
				   dcb->pg_num_tcs_supported);

			seq_puts(seq, "\n");
		}

		if (dcb->msgs & CXGB4_DCB_FW_PRIORATE) {
			int prio;

			seq_puts(seq, "  Priority Rate\t:\t");
			for (prio = 0; prio < 8; prio++)
				seq_printf(seq, " %3d", dcb->priorate[prio]);
			seq_puts(seq, "\n");
		}

		if (dcb->msgs & CXGB4_DCB_FW_PFC) {
			int prio;

			seq_puts(seq, "  Priority Flow Control   :\t");
			for (prio = 0; prio < 8; prio++) {
				int pfcen = (dcb->pfcen >> 1*(7 - prio)) & 0x1;
				seq_printf(seq, " %3d", pfcen);
			}
			seq_puts(seq, "\n");

			seq_printf(seq, "  Max PFC Traffic Classes [%3d  ]\n",
				   dcb->pfc_num_tcs_supported);

			seq_puts(seq, "\n");
		}

		if (dcb->msgs & CXGB4_DCB_FW_APP_ID) {
			int app, napps;

			seq_puts(seq, "  Application Information:\n");
			seq_puts(seq, "  App    Priority    Selection         Protocol\n");
			seq_puts(seq, "  Index  Map         Field             ID\n");
			for (app = 0, napps = 0; app < CXGB4_MAX_DCBX_APP_SUPPORTED; app++) {
				struct app_priority *ap = &dcb->app_priority[app];
				const char *sel_names[] = {
					"Ethertype",
					"Socket TCP",
					"Socket UDP",
					"Socket All",
				};
				const char *sel_name;

				/* skip empty slots */
				if (ap->protocolid == 0)
					continue;
				napps++;

				if (ap->sel_field < ARRAY_SIZE(sel_names))
					sel_name = sel_names[ap->sel_field];
				else
					sel_name = "UNKNOWN";

				seq_printf(seq, "  %3d    %#04x        %-10s (%d)"
					   "    %#06x (%d)\n",
					   app,
					   ap->user_prio_map,
					   sel_name, ap->sel_field,
					   ap->protocolid, ap->protocolid);
			}
			if (napps == 0)
				seq_puts(seq, "    --- None ---\n");
		}
	}
	return 0;
}

static inline void *dcb_info_get_idx(struct adapter *adap, loff_t pos)
{
	return pos <= adap->params.nports ? (void *)((uintptr_t)pos + 1) : NULL;
}

static void *dcb_info_start(struct seq_file *seq, loff_t *pos)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;

	return *pos ? dcb_info_get_idx(adap, *pos) : SEQ_START_TOKEN;
}

static void dcb_info_stop(struct seq_file *seq, void *v)
{
}

static void *dcb_info_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;

	(*pos)++;
	return dcb_info_get_idx(adap, *pos);
}

static const struct seq_operations dcb_info_seq_ops = {
	.start = dcb_info_start,
	.next  = dcb_info_next,
	.stop  = dcb_info_stop,
	.show  = dcb_info_show
};

static int dcb_info_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &dcb_info_seq_ops);

	if (!res) {
		struct seq_file *seq = file->private_data;

		seq->private = inode->i_private;
	}
	return res;
}

static const struct file_operations dcb_info_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = dcb_info_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};
#endif /* CONFIG_CXGB4_DCB */

static int resources_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct pf_resources *pfres;

	pfres = &adap->params.pfres;

	#define S(desc, fmt, var) \
		seq_printf(seq, "%-60s " fmt "\n", \
			   desc " (" #var "):", pfres->var)

	S("Virtual Interfaces", "%d", nvi);
	S("Egress Queues", "%d", neq);
	S("Ethernet Control", "%d", nethctrl);
	S("Ingress Queues/w Free Lists/Interrupts", "%d", niqflint);
	S("Ingress Queues", "%d", niq);
	S("Traffic Class", "%d", tc);
	S("Port Access Rights Mask", "%#x", pmask);
	S("MAC Address Filters", "%d", nexactf);
	S("Firmware Command Read Capabilities", "%#x", r_caps);
	S("Firmware Command Write/Execute Capabilities", "%#x", wx_caps);

	#undef S

	return 0;
}

static int resources_open(struct inode *inode, struct file *file)
{
	return single_open(file, resources_show, inode->i_private);
}

static const struct file_operations resources_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = resources_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

#ifdef CONFIG_CXGB4_DCB
/**
 * ethqset2pinfo - return port_info of an Ethernet Queue Set
 * @adap: the adapter
 * @qset: Ethernet Queue Set
 */
static struct port_info *ethqset2pinfo(struct adapter *adap, int qset)
{
	int pidx;

	for_each_port(adap, pidx) {
		struct port_info *pi = adap2pinfo(adap, pidx);

		if (qset >= pi->first_qset &&
		    qset < pi->first_qset + pi->nqsets)
			return pi;
	}

	/* should never happen! */
	BUG_ON(1);
	return NULL;
}
#endif /* CONFIG_CXGB4_DCB */

#define SGE_QINFO_NUM_PER_ROW 4

#define S3(fmt_spec, s, v) \
do { \
	seq_printf(seq, "%-12s", s); \
	for (i = 0; i < n; ++i) \
		seq_printf(seq, " %16" fmt_spec, v); \
	seq_putc(seq, '\n'); \
} while (0)
#define S(s, v) S3("s", s, v)
#define T3(fmt_spec, s, v) S3(fmt_spec, s, tx[i].v)
#define T(s, v) S3("u", s, tx[i].v)
#define TL(s, v) T3("lu", s, v)
#define R3(fmt_spec, s, v) S3(fmt_spec, s, rx[i].v)
#define R(s, v) S3("u", s, rx[i].v)
#define RL(s, v) R3("lu", s, v)

static void cxgb4_sge_qinfo_eth(struct seq_file *seq, int r, int nentries,
				const struct sge_eth_rxq *rx,
				const struct sge_eth_txq *tx,
				const char *qname)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct sge *s = &adap->sge;
	int i, n;

	n = min(SGE_QINFO_NUM_PER_ROW, nentries - SGE_QINFO_NUM_PER_ROW * r);

	S("QType:", qname);
	if (rx) {
		S("Interface:",
		  rx[i].rspq.netdev ? rx[i].rspq.netdev->name : "N/A");
		R("RspQ ID:", rspq.abs_id);
		R("RspQ size:", rspq.size);
		R("RspQE size:", rspq.iqe_len);
		R("RspQ CIDX:", rspq.cidx);
		R("RspQ Gen:", rspq.gen);
		S3("u", "Intr delay:", rspq_intr_timer(s, &rx[i].rspq));
		S3("u", "Intr pktcnt:", rspq_intr_pktcnt(s, &rx[i].rspq));
		RL("RxPackets:", stats.pkts);
		RL("RxCSO:", stats.rx_cso);
		RL("VLANxtract:", stats.vlan_ex);
		RL("LROmerged:", stats.lro_merged);
		RL("LROpackets:", stats.lro_pkts);
		RL("RxDrops:", stats.rx_drops);
		RL("RxBadPkts:", stats.bad_rx_pkts);
		if (rx[i].fl.size) {
			R("FL ID:", fl.cntxt_id);
			R("FL size:", fl.size - 8);
			R("FL pend:", fl.pend_cred);
			R("FL avail:", fl.avail);
			R("FL PIDX:", fl.pidx);
			R("FL CIDX:", fl.cidx);
			RL("FLAllocErr:", fl.alloc_failed);
			RL("FLLrgAlcErr:", fl.large_alloc_failed);
			RL("FLMapErr:", fl.mapping_err);
			RL("FLLow:", fl.low);
			RL("FLStarving:", fl.starving);
		}
	}

	if (tx) {
		T("TxQ ID:", q.cntxt_id);
		T("TxQ size:", q.size);
		T("TxQ inuse:", q.in_use);
		T("TxQ CIDX:", q.cidx);
		T("TxQ PIDX:", q.pidx);
		TL("TSO:", tso);
		TL("TxCSO:", tx_cso);
		TL("VLANins:", vlan_ins);
		TL("TxQFull:", q.stops);
		TL("TxQRestarts:", q.restarts);
		TL("TxMapErr:", mapping_err);
		TL("TxCoalWR:", coal_wr);
		TL("TxCoalPkt:", coal_pkts);
	}
}

static void cxgb4_sge_qinfo_ctrl(struct seq_file *seq, int r, int nentries,
				 const struct sge_ctrl_txq *tx,
				 const char *qname)
{
	int i, n;

	n = min(SGE_QINFO_NUM_PER_ROW, nentries - SGE_QINFO_NUM_PER_ROW * r);
	S("QType:", qname);
	T("TxQ ID:", q.cntxt_id);
	T("TxQ size:", q.size);
	T("TxQ inuse:", q.in_use);
	T("TxQ CIDX:", q.cidx);
	T("TxQ PIDX:", q.pidx);
	TL("TxPkts:", q.txp);
	TL("TxQFull:", q.stops);
	TL("TxQRestarts:", q.restarts);
}

static int cxgb4_sge_qinfo_eth_nic(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct sge_eth_rxq *rx;
	const struct sge_eth_txq *tx;
	struct sge *s = &adap->sge;
	int r, nentries, base_qset;
#ifdef CONFIG_CXGB4_DCB
	int i, n;
#endif

	nentries = DIV_ROUND_UP(s->ethqsets, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;
	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	base_qset = r * SGE_QINFO_NUM_PER_ROW;
	tx = &s->ethtxq[base_qset];
	rx = &s->ethrxq[base_qset];

	cxgb4_sge_qinfo_eth(seq, r, s->ethqsets, rx, tx, "ETHERNET");
#ifdef CONFIG_CXGB4_DCB
	n = min(SGE_QINFO_NUM_PER_ROW, nentries - SGE_QINFO_NUM_PER_ROW * r);
	T("DCB Prio:", dcb_prio);
	S3("u", "DCB PGID:",
	   (ethqset2pinfo(adap, base_qset + i)->dcb.pgid >>
	    4 * (7 - tx[i].dcb_prio)) & 0xf);
	S3("u", "DCB PFC:",
	   (ethqset2pinfo(adap, base_qset + i)->dcb.pfcen >>
	    1 * (7 - tx[i].dcb_prio)) & 0x1);
#endif

	return 0;
}

static int cxgb4_sge_qinfo_eth_trace(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct sge_eth_rxq *rx;
	struct sge *s = &adap->sge;
	int r, nentries;

	nentries = DIV_ROUND_UP(s->ntraceq, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	rx = &s->traceq[r * SGE_QINFO_NUM_PER_ROW];
	cxgb4_sge_qinfo_eth(seq, r, s->ntraceq, rx, NULL, "TRACE");
	return 0;
}

static int cxgb4_sge_qinfo_eth_mirror(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct sge_eth_rxq *rx;
	struct sge *s = &adap->sge;
	int r, nentries;

	nentries = DIV_ROUND_UP(s->nmirrorq, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
 	}

	rx = &s->mirrorq[r * SGE_QINFO_NUM_PER_ROW];
	cxgb4_sge_qinfo_eth(seq, r, s->nmirrorq, rx, NULL, "MIRROR");
	return 0;
}

static int cxgb4_sge_qinfo_eth_vxlan(struct seq_file *seq, int *row)
{
#if IS_ENABLED(CONFIG_VXLAN)
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct sge_eth_txq *tx;
	struct sge *s = &adap->sge;
	int r, nentries;

	nentries = DIV_ROUND_UP(s->nvxlanq, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;
	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	tx = &s->vxlantxq[r * SGE_QINFO_NUM_PER_ROW];
	cxgb4_sge_qinfo_eth(seq, r, s->nvxlanq, NULL, tx, "VxLAN");
	return 0;
#else
	return row ? -EINVAL : 0;
#endif /* IS_ENABLED(CONFIG_VXLAN) */
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static void cxgb4_sge_qinfo_uld_rx(struct seq_file *seq, int r, int nentries,
				   const struct sge_ofld_rxq *rx,
				   const char *qname)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct sge *s = &adap->sge;
	int i, n;

	n = min(SGE_QINFO_NUM_PER_ROW, nentries - SGE_QINFO_NUM_PER_ROW * r);

	S("QType:", qname);
	S("Interface:",
	  rx[i].rspq.netdev ? rx[i].rspq.netdev->name : "N/A");
	R("RspQ ID:", rspq.abs_id);
	R("RspQ size:", rspq.size);
	R("RspQE size:", rspq.iqe_len);
	R("RspQ CIDX:", rspq.cidx);
	R("RspQ Gen:", rspq.gen);
	S3("u", "Intr delay:", rspq_intr_timer(s, &rx[i].rspq));
	S3("u", "Intr pktcnt:",	rspq_intr_pktcnt(s, &rx[i].rspq));
	RL("RxPackets:", stats.pkts);
	RL("RxImmPkts:", stats.imm);
	RL("RxNoMem:", stats.nomem);
	RL("RxAN:", stats.an);
	RL("LROmerged:", rspq.lro_mgr.lro_merged);
	RL("LROpackets:", rspq.lro_mgr.lro_pkts);
	if (rx[i].fl.size > 0) {
 		R("FL ID:", fl.cntxt_id);
 		R("FL size:", fl.size - 8);
 		R("FL pend:", fl.pend_cred);
 		R("FL avail:", fl.avail);
 		R("FL PIDX:", fl.pidx);
 		R("FL CIDX:", fl.cidx);
 		RL("FLAllocErr:", fl.alloc_failed);
 		RL("FLLrgAlcErr:", fl.large_alloc_failed);
 		RL("FLMapErr:", fl.mapping_err);
 		RL("FLLow:", fl.low);
 		RL("FLStarving:", fl.starving);
	}
}

static void cxgb4_sge_qinfo_uld_tx(struct seq_file *seq, int r,
				   enum cxgb4_uld_txq_type qtype,
				   enum cxgb4_uld_type uld,
				   const char *qname)
{
	struct t4_linux_debugfs_data *d = seq->private;
	int start = 0, nentries = 0, extra = 0;
	struct cxgb4_uld_queue_map *map;
	struct adapter *adap = d->adap;
	struct cxgb4_uld_txq *txq;
	struct net_device *netdev;
	unsigned long index;
	int n, i;
	u8 port;

	for_each_port(adap, port) {
		netdev = adap->port[port];
		map = cxgb4_uld_queues_txq_map_get(netdev, qtype, uld);
		nentries += map->num_queues;
		if (nentries > r * SGE_QINFO_NUM_PER_ROW - extra)
			break;
		start += map->num_queues;
		extra += roundup(map->num_queues, SGE_QINFO_NUM_PER_ROW) -
			 map->num_queues;
 	}

	if (!map)
		return;

#define S3X(fmt_spec, s, v) do { \
	seq_printf(seq, "%-12s", s); \
	i = start + extra; \
	xa_for_each(&map->queues, index, txq) { \
		if (i >= r * SGE_QINFO_NUM_PER_ROW + n) \
			break; \
		if (i >= r * SGE_QINFO_NUM_PER_ROW) \
			seq_printf(seq, " %16" fmt_spec, v); \
		i++; \
	} \
	seq_putc(seq, '\n'); \
} while (0)

#define TX(s, v) S3X("u", s, v)
#define TLX(s, v) S3X("lu", s, v)

	n = min(SGE_QINFO_NUM_PER_ROW,
		nentries - (SGE_QINFO_NUM_PER_ROW * r - extra));

	S("QType:", qname);
	S("Interface:", netdev->name);
	TX("TxQ ID:", txq->ofldtxq->q.cntxt_id);
	TX("TxQ size:", txq->ofldtxq->q.size);
	TX("TxQ inuse:", txq->ofldtxq->q.in_use);
	TX("TxQ CIDX:", txq->ofldtxq->q.cidx);
	TX("TxQ PIDX:", txq->ofldtxq->q.pidx);
	TLX("TxPkts:", txq->ofldtxq->q.txp);
	TLX("TxQFull:", txq->ofldtxq->q.stops);
	TLX("TxQRestarts:", txq->ofldtxq->q.restarts);
	TLX("TxMapErr:", txq->ofldtxq->mapping_err);
	if (qtype == CXGB4_ULD_TXQ_TYPE_SHARED)
		TX("uPCore:", txq->tid_qid_group_id);

#undef TLX
#undef TX
#undef S3X
}

static int cxgb4_sge_qinfo_uld_txq_num(struct adapter *adap,
				       enum cxgb4_uld_txq_type qtype,
				       enum cxgb4_uld_type uld)
{
	struct cxgb4_uld_queue_map *map;
	struct net_device *netdev;
	int ntx = 0;
	u8 port;

	for_each_port(adap, port) {
		netdev = adap->port[port];
		map = cxgb4_uld_queues_txq_map_get(netdev, qtype, uld);
		ntx += roundup(map->num_queues, SGE_QINFO_NUM_PER_ROW);
 	}

	return ntx;
}

static int cxgb4_sge_qinfo_uld_toe(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	int r, nentries, nsharetx, nsendtx;
	struct adapter *adap = d->adap;
	const struct sge_ofld_rxq *rx;
	struct sge *s = &adap->sge;

	if (!cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_TOE))
		return -EOPNOTSUPP;

	nsharetx = cxgb4_sge_qinfo_uld_txq_num(adap, CXGB4_ULD_TXQ_TYPE_SHARED,
					       CXGB4_ULD_TYPE_TOE);
	nsendtx = cxgb4_sge_qinfo_uld_txq_num(adap, CXGB4_ULD_TXQ_TYPE_SENDPATH,
					      CXGB4_ULD_TYPE_TOE);
	nentries = DIV_ROUND_UP(s->ofldqsets, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(nsharetx, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(nsendtx, SGE_QINFO_NUM_PER_ROW);
#ifdef CONFIG_T4_MA_FAILOVER
	nentries += DIV_ROUND_UP(s->nfailoverq, SGE_QINFO_NUM_PER_ROW);
#endif /* CONFIG_T4_MA_FAILOVER */

	if (!row)
		return nentries;
	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	if (r < DIV_ROUND_UP(s->ofldqsets, SGE_QINFO_NUM_PER_ROW)) {
		rx = &s->ofldrxq[r * SGE_QINFO_NUM_PER_ROW];
		cxgb4_sge_qinfo_uld_rx(seq, r, s->ofldqsets, rx, "TOE-RX");
		return 0;
	}

	r -= DIV_ROUND_UP(s->ofldqsets, SGE_QINFO_NUM_PER_ROW);
#ifdef CONFIG_T4_MA_FAILOVER
	if (r < DIV_ROUND_UP(s->nfailoverq, SGE_QINFO_NUM_PER_ROW)) {
		rx = &s->failoverq;
		cxgb4_sge_qinfo_uld_rx(seq, r, s->nfailoverq, rx,
				       "MA-FAILOVER");
		return 0;
	}

	r -= DIV_ROUND_UP(s->nfailoverq, SGE_QINFO_NUM_PER_ROW);
#endif /* CONFIG_T4_MA_FAILOVER */

	if (r < DIV_ROUND_UP(nsharetx, SGE_QINFO_NUM_PER_ROW)) {
		cxgb4_sge_qinfo_uld_tx(seq, r, CXGB4_ULD_TXQ_TYPE_SHARED,
				       CXGB4_ULD_TYPE_TOE, "TOE-TX");
		return 0;
	}

	r -= DIV_ROUND_UP(nsharetx, SGE_QINFO_NUM_PER_ROW);
	cxgb4_sge_qinfo_uld_tx(seq, r, CXGB4_ULD_TXQ_TYPE_SENDPATH,
			       CXGB4_ULD_TYPE_TOE, "TOE-SENDTX");
	return 0;
}

static int cxgb4_sge_qinfo_uld_rdma(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct sge_ofld_rxq *rx;
	struct sge *s = &adap->sge;
	int r, nentries, nsendtx;

	if (!cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_RDMA))
		return -EOPNOTSUPP;

	nsendtx = cxgb4_sge_qinfo_uld_txq_num(adap, CXGB4_ULD_TXQ_TYPE_SENDPATH,
					      CXGB4_ULD_TYPE_RDMA);
	nentries = DIV_ROUND_UP(s->rdmaqs, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(s->rdmaciqs, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(nsendtx, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	if (r < DIV_ROUND_UP(s->rdmaqs, SGE_QINFO_NUM_PER_ROW)) {
		rx = &s->rdmarxq[r * SGE_QINFO_NUM_PER_ROW];
		cxgb4_sge_qinfo_uld_rx(seq, r, s->rdmaqs, rx, "RDMA-CPL");
		return 0;
	}

	r -= DIV_ROUND_UP(s->rdmaqs, SGE_QINFO_NUM_PER_ROW);
	if (r < DIV_ROUND_UP(s->rdmaciqs, SGE_QINFO_NUM_PER_ROW)) {
		rx = &s->rdmaciq[r * SGE_QINFO_NUM_PER_ROW];
		cxgb4_sge_qinfo_uld_rx(seq, r, s->rdmaciqs, rx, "RDMA-CIQ");
		return 0;
	}

	r -= DIV_ROUND_UP(s->rdmaciqs, SGE_QINFO_NUM_PER_ROW);
	cxgb4_sge_qinfo_uld_tx(seq, r, CXGB4_ULD_TXQ_TYPE_SENDPATH,
			       CXGB4_ULD_TYPE_RDMA, "RDMA-SENDTX");
	return 0;
}

static int cxgb4_sge_qinfo_uld_iscsi(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct sge_ofld_rxq *rx;
	struct sge *s = &adap->sge;
	int r, nentries, nsendtx;

	if (!cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_ISCSI))
		return -EOPNOTSUPP;

	nsendtx = cxgb4_sge_qinfo_uld_txq_num(adap, CXGB4_ULD_TXQ_TYPE_SENDPATH,
					      CXGB4_ULD_TYPE_ISCSI);
	nentries = DIV_ROUND_UP(s->niscsiq, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(nsendtx, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	if (r < DIV_ROUND_UP(s->niscsiq, SGE_QINFO_NUM_PER_ROW)) {
		rx = &s->iscsirxq[r * SGE_QINFO_NUM_PER_ROW];
		cxgb4_sge_qinfo_uld_rx(seq, r, s->niscsiq, rx, "iSCSI-RX");
		return 0;
	}

	r -= DIV_ROUND_UP(s->niscsiq, SGE_QINFO_NUM_PER_ROW);
	cxgb4_sge_qinfo_uld_tx(seq, r, CXGB4_ULD_TXQ_TYPE_SENDPATH,
			       CXGB4_ULD_TYPE_ISCSI, "iSCSI-SENDTX");
	return 0;
}

static int cxgb4_sge_qinfo_uld_iscsit(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct sge_ofld_rxq *rx;
	struct sge *s = &adap->sge;
	int r, nentries, nsendtx;

	if (!cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_ISCSIT))
		return -EOPNOTSUPP;

	nsendtx = cxgb4_sge_qinfo_uld_txq_num(adap, CXGB4_ULD_TXQ_TYPE_SENDPATH,
					      CXGB4_ULD_TYPE_ISCSIT);
	nentries = DIV_ROUND_UP(s->niscsitq, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(nsendtx, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	if (r < DIV_ROUND_UP(s->niscsitq, SGE_QINFO_NUM_PER_ROW)) {
		rx = &s->iscsitrxq[r * SGE_QINFO_NUM_PER_ROW];
		cxgb4_sge_qinfo_uld_rx(seq, r, s->niscsitq, rx, "iSCSIT-RX");
		return 0;
	}

	r -= DIV_ROUND_UP(s->niscsitq, SGE_QINFO_NUM_PER_ROW);
	cxgb4_sge_qinfo_uld_tx(seq, r, CXGB4_ULD_TXQ_TYPE_SENDPATH,
			       CXGB4_ULD_TYPE_ISCSIT, "iSCSIT-SENDTX");
	return 0;
}

static int cxgb4_sge_qinfo_uld_nvmeh(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct sge_ofld_rxq *rx;
	struct sge *s = &adap->sge;
	int r, nentries, nsendtx;

	if (!cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_NVME_TCP_HOST))
		return -EOPNOTSUPP;

	nsendtx = cxgb4_sge_qinfo_uld_txq_num(adap, CXGB4_ULD_TXQ_TYPE_SENDPATH,
					      CXGB4_ULD_TYPE_NVME_TCP_HOST);
	nentries = DIV_ROUND_UP(s->n_nvmehq, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(nsendtx, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	if (r < DIV_ROUND_UP(s->n_nvmehq, SGE_QINFO_NUM_PER_ROW)) {
		rx = &s->nvmehrxq[r * SGE_QINFO_NUM_PER_ROW];
		cxgb4_sge_qinfo_uld_rx(seq, r, s->n_nvmehq, rx, "NVMEH-RX");
		return 0;
	}

	r -= DIV_ROUND_UP(s->n_nvmehq, SGE_QINFO_NUM_PER_ROW);
	cxgb4_sge_qinfo_uld_tx(seq, r, CXGB4_ULD_TXQ_TYPE_SENDPATH,
			       CXGB4_ULD_TYPE_NVME_TCP_HOST, "NVMEH-SENDTX");
	return 0;
}

static int cxgb4_sge_qinfo_uld_nvmet(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct sge_ofld_rxq *rx;
	struct sge *s = &adap->sge;
	int r, nentries, nsendtx;

	if (!cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_NVME_TCP_TARGET))
		return -EOPNOTSUPP;

	nsendtx = cxgb4_sge_qinfo_uld_txq_num(adap, CXGB4_ULD_TXQ_TYPE_SENDPATH,
					      CXGB4_ULD_TYPE_NVME_TCP_TARGET);
	nentries = DIV_ROUND_UP(s->n_nvmetq, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(nsendtx, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	if (r < DIV_ROUND_UP(s->n_nvmetq, SGE_QINFO_NUM_PER_ROW)) {
		rx = &s->nvmetrxq[r * SGE_QINFO_NUM_PER_ROW];
		cxgb4_sge_qinfo_uld_rx(seq, r, s->n_nvmetq, rx, "NVMET-RX");
		return 0;
	}

	r -= DIV_ROUND_UP(s->n_nvmetq, SGE_QINFO_NUM_PER_ROW);
	cxgb4_sge_qinfo_uld_tx(seq, r, CXGB4_ULD_TXQ_TYPE_SENDPATH,
			       CXGB4_ULD_TYPE_NVME_TCP_TARGET, "NVMET-SENDTX");
	return 0;
}

static int cxgb4_sge_qinfo_uld_cstor(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct sge_ofld_rxq *rx;
	struct sge *s = &adap->sge;
	int r, nentries, nsendtx;

	if (!cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_CSTOR))
		return -EOPNOTSUPP;

	nsendtx = cxgb4_sge_qinfo_uld_txq_num(adap, CXGB4_ULD_TXQ_TYPE_SENDPATH,
					      CXGB4_ULD_TYPE_CSTOR);
	nentries = DIV_ROUND_UP(s->ncstorq, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(s->ncstorciq, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(nsendtx, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	if (r < DIV_ROUND_UP(s->ncstorq, SGE_QINFO_NUM_PER_ROW)) {
		rx = &s->cstorrxq[r * SGE_QINFO_NUM_PER_ROW];
		cxgb4_sge_qinfo_uld_rx(seq, r, s->ncstorq, rx, "CSTOR-RXQ");
		return 0;
	}

	r -= DIV_ROUND_UP(s->ncstorq, SGE_QINFO_NUM_PER_ROW);
	if (r < DIV_ROUND_UP(s->ncstorciq, SGE_QINFO_NUM_PER_ROW)) {
		rx = &s->cstorciq[r * SGE_QINFO_NUM_PER_ROW];
		cxgb4_sge_qinfo_uld_rx(seq, r, s->ncstorciq, rx, "CSTOR-CIQ");
		return 0;
	}

	r -= DIV_ROUND_UP(s->ncstorciq, SGE_QINFO_NUM_PER_ROW);
	cxgb4_sge_qinfo_uld_tx(seq, r, CXGB4_ULD_TXQ_TYPE_SENDPATH,
			       CXGB4_ULD_TYPE_CSTOR, "CSTOR-SENDTX");
	return 0;
}

static int cxgb4_sge_qinfo_uld_crypto(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	int r, nentries, nsharetx, nsendtx;
	struct adapter *adap = d->adap;
	const struct sge_ofld_rxq *rx;
	struct sge *s = &adap->sge;

	if (!cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_CRYPTO))
		return -EOPNOTSUPP;

	nsharetx = cxgb4_sge_qinfo_uld_txq_num(adap, CXGB4_ULD_TXQ_TYPE_SHARED,
					       CXGB4_ULD_TYPE_CRYPTO);
	nsendtx = cxgb4_sge_qinfo_uld_txq_num(adap, CXGB4_ULD_TXQ_TYPE_SENDPATH,
					      CXGB4_ULD_TYPE_CRYPTO);
	nentries = DIV_ROUND_UP(s->ncryptoq, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(nsharetx, SGE_QINFO_NUM_PER_ROW) +
		   DIV_ROUND_UP(nsendtx, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	if (r < DIV_ROUND_UP(s->ncryptoq, SGE_QINFO_NUM_PER_ROW)) {
		rx = &s->cryptorxq[r * SGE_QINFO_NUM_PER_ROW];
		cxgb4_sge_qinfo_uld_rx(seq, r, s->ncryptoq, rx, "CRYPTO-RX");
		return 0;
	}

	r -= DIV_ROUND_UP(s->ncryptoq, SGE_QINFO_NUM_PER_ROW);
	if (r < DIV_ROUND_UP(nsharetx, SGE_QINFO_NUM_PER_ROW)) {
		cxgb4_sge_qinfo_uld_tx(seq, r, CXGB4_ULD_TXQ_TYPE_SHARED,
				       CXGB4_ULD_TYPE_CRYPTO, "CRYPTO-TX");
		return 0;
	}

	r -= DIV_ROUND_UP(nsharetx, SGE_QINFO_NUM_PER_ROW);
	cxgb4_sge_qinfo_uld_tx(seq, r, CXGB4_ULD_TXQ_TYPE_SENDPATH,
			       CXGB4_ULD_TYPE_CRYPTO, "CRYPTO-SENDTX");
	return 0;
}

static int cxgb4_sge_qinfo_uld_chtcp(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	int r, nentries, nsendtx;

	if (!cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_CHTCP))
		return -EOPNOTSUPP;

	nsendtx = cxgb4_sge_qinfo_uld_txq_num(adap, CXGB4_ULD_TXQ_TYPE_SENDPATH,
					      CXGB4_ULD_TYPE_CHTCP);
	nentries = DIV_ROUND_UP(nsendtx, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	cxgb4_sge_qinfo_uld_tx(seq, r, CXGB4_ULD_TXQ_TYPE_SENDPATH,
			       CXGB4_ULD_TYPE_CHTCP, "CHTCP-SENDTX");
	return 0;
}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

static int cxgb4_sge_qinfo_ctrl_nic(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	const struct sge_ctrl_txq *ctrlq;
	struct adapter *adap = d->adap;
	struct sge *s = &adap->sge;
	int r, nq, nentries;

	nq = adap->params.nports;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (adap->tidinfo.sftids.size)
		nq = 1;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	nentries = DIV_ROUND_UP(nq, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	ctrlq = &s->ctrlq[r * SGE_QINFO_NUM_PER_ROW];
	cxgb4_sge_qinfo_ctrl(seq, r, nq, ctrlq, "CONTROL");
	return 0;
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static int cxgb4_sge_qinfo_ctrl_rdma(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	const struct sge_ctrl_txq *ctrlq;
	struct adapter *adap = d->adap;
	struct sge *s = &adap->sge;
	int r, nq, nentries;

	if (!cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_RDMA))
		return -EOPNOTSUPP;

	nq = adap->tidinfo.sftids.size ? 1 : adap->params.nports;
	nentries = DIV_ROUND_UP(nq, SGE_QINFO_NUM_PER_ROW);
	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	ctrlq = &s->ctrlq[NCHAN + r * SGE_QINFO_NUM_PER_ROW];
	cxgb4_sge_qinfo_ctrl(seq, r, nq, ctrlq, "RDMA-CONTROL");
	return 0;
}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

static int cxgb4_sge_qinfo_fwevtq(struct seq_file *seq, int *row)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct sge_rspq *fwevtq;
	struct sge *s = &adap->sge;
	int i, n, r, nentries = 1;

	if (!row)
		return nentries;

	r = *row;
	if (r >= nentries) {
		*row -= nentries;
		return -EINVAL;
	}

	fwevtq = &s->fw_evtq;
	n = nentries;
	S("QType:", "FW-EVENT-QUEUE");
	S3("u", "RspQ ID:", fwevtq->abs_id);
	S3("u", "RspQ size:", fwevtq->size);
	S3("u", "RspQE size:", fwevtq->iqe_len);
	S3("u", "RspQ CIDX:", fwevtq->cidx);
	S3("u", "RspQ Gen:", fwevtq->gen);
	S3("u", "Intr delay:", rspq_intr_timer(s, fwevtq));
	S3("u", "Intr pktcnt:", rspq_intr_pktcnt(s, fwevtq));
	return 0;
}

#undef RL
#undef R
#undef R3
#undef TL
#undef T
#undef T3
#undef S
#undef S3

static int sge_qinfo_show(struct seq_file *seq, void *v)
{
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	int ret, r = (uintptr_t)v - 1;

	if (r)
		seq_putc(seq, '\n');

#define SGE_QINFO_CALL(qtype) do { \
	ret = cxgb4_sge_qinfo_##qtype(seq, &r); \
	if (!ret) \
		goto out; \
} while (0)

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	mutex_lock(&adap->uld.uld_mutex);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	SGE_QINFO_CALL(eth_nic);
	SGE_QINFO_CALL(eth_trace);
	SGE_QINFO_CALL(eth_mirror);
	SGE_QINFO_CALL(eth_vxlan);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	SGE_QINFO_CALL(uld_toe);
	SGE_QINFO_CALL(uld_rdma);
	SGE_QINFO_CALL(uld_iscsi);
	SGE_QINFO_CALL(uld_iscsit);
	SGE_QINFO_CALL(uld_nvmeh);
	SGE_QINFO_CALL(uld_nvmet);
	SGE_QINFO_CALL(uld_cstor);
	SGE_QINFO_CALL(uld_crypto);
	SGE_QINFO_CALL(uld_chtcp);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	SGE_QINFO_CALL(ctrl_nic);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	SGE_QINFO_CALL(ctrl_rdma);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	SGE_QINFO_CALL(fwevtq);

#undef SGE_QINFO_CALL

out:
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	mutex_unlock(&adap->uld.uld_mutex);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	return 0;
}

static int sge_queue_entries(struct seq_file *seq)
{
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	int ret, nentries = 0;

#define SGE_QINFO_NUM_CALL(qtype) do { \
	ret = cxgb4_sge_qinfo_##qtype(seq, NULL); \
	if (ret > 0) \
		nentries += ret; \
} while (0)

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	mutex_lock(&adap->uld.uld_mutex);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	SGE_QINFO_NUM_CALL(eth_nic);
	SGE_QINFO_NUM_CALL(eth_trace);
	SGE_QINFO_NUM_CALL(eth_mirror);
	SGE_QINFO_NUM_CALL(eth_vxlan);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	SGE_QINFO_NUM_CALL(uld_toe);
	SGE_QINFO_NUM_CALL(uld_rdma);
	SGE_QINFO_NUM_CALL(uld_iscsi);
	SGE_QINFO_NUM_CALL(uld_iscsit);
	SGE_QINFO_NUM_CALL(uld_nvmeh);
	SGE_QINFO_NUM_CALL(uld_nvmet);
	SGE_QINFO_NUM_CALL(uld_cstor);
	SGE_QINFO_NUM_CALL(uld_crypto);
	SGE_QINFO_NUM_CALL(uld_chtcp);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	SGE_QINFO_NUM_CALL(ctrl_nic);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	SGE_QINFO_NUM_CALL(ctrl_rdma);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	SGE_QINFO_NUM_CALL(fwevtq);

#undef SGE_QINFO_NUM_CALL

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	mutex_unlock(&adap->uld.uld_mutex);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	return nentries;
}

static void *sge_queue_start(struct seq_file *seq, loff_t *pos)
{
	return *pos < sge_queue_entries(seq) ?
	       (void *)((uintptr_t)*pos + 1) : NULL;
}

static void sge_queue_stop(struct seq_file *seq, void *v)
{
}

static void *sge_queue_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return *pos < sge_queue_entries(seq) ?
	       (void *)((uintptr_t)*pos + 1) : NULL;
}

static const struct seq_operations sge_qinfo_seq_ops = {
	.start = sge_queue_start,
	.next  = sge_queue_next,
	.stop  = sge_queue_stop,
	.show  = sge_qinfo_show
};

static int sge_qinfo_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &sge_qinfo_seq_ops);

	if (!res) {
		struct seq_file *seq = file->private_data;

		seq->private = inode->i_private;
	}
	return res;
}

static const struct file_operations sge_qinfo_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = sge_qinfo_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static int intr_holdoff_show(struct seq_file *seq, void *v)
{

	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct sge *s = &adap->sge;
	int i;

	for (i=0; i < SGE_NTIMERS; i ++)
		seq_printf(seq, "%u ", s->timer_val[i]);
	seq_printf(seq, "\n");

	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(intr_holdoff);

static int intr_cnt_show(struct seq_file *seq, void *v)
{

	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct sge *s = &adap->sge;
	int i;

	for (i=0; i < SGE_NCOUNTERS; i ++)
		seq_printf(seq, "%u ", s->counter_val[i]);
	seq_printf(seq, "\n");

	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(intr_cnt);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static int uld_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	int i;

	for (i = 0; i < CXGB4_ULD_TYPE_MAX; i++)
		if (adap->uld_handle[i])
			seq_printf(seq, "%s: %s\n",
				   cxgb4_uld_type_to_name(i),
				   cxgb4_ulds[i].name);
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(uld);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

#ifdef CXGB4_DEBUG
/* Inject parity error, only for debug purpose */
static int inject_err_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static ssize_t inject_err_read(struct file *filp, char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t inject_err_write(struct file *filp, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct t4_linux_debugfs_data *d = filp->private_data;
	struct adapter *adap = d->adap;
	struct fw_ldst_cmd c;

	if (!cxgb4_modparam_attempt_err_recovery())
		return count;

	memset(&c, 0, sizeof(c));
	c.op_to_addrspace =
		cpu_to_be32(V_FW_CMD_OP(FW_LDST_CMD) |
			    F_FW_CMD_REQUEST | F_FW_CMD_READ |
			    V_FW_LDST_CMD_ADDRSPACE(FW_LDST_ADDRSPC_FIRMWARE));
	c.cycles_to_len16 = cpu_to_be32(FW_LEN16(c));
	c.u.addrval.addr = cpu_to_be32(0xffffffff);
	c.u.addrval.val = cpu_to_be32(0xffffffff);

	t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), NULL);
	return count;
}

static const struct file_operations inject_err_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = inject_err_open,
	.read    = inject_err_read,
	.write   = inject_err_write,
	.llseek  = generic_file_llseek,
};
#endif /* CXGB4_DEBUG */

static int blocked_fl_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static ssize_t blocked_fl_read(struct file *filp, char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	struct t4_linux_debugfs_data *d = filp->private_data;
	const struct adapter *adap = d->adap;
	ssize_t size;
	char *buf;
	int len;

	size = (adap->sge.egr_sz + 3) / 4 +
		adap->sge.egr_sz / 32 + 2; /* includes ,/\n/\0 */

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	len = snprintf(buf, size - 1, "%*pb\n",
		       adap->sge.egr_sz, adap->sge.blocked_fl);
	len += sprintf(buf + len, "\n");
	size = simple_read_from_buffer(ubuf, count, ppos, buf, len);
	t4_free_mem(buf);
	return size;
}

static ssize_t blocked_fl_write(struct file *filp, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct t4_linux_debugfs_data *d = filp->private_data;
	struct adapter *adap = d->adap;
	unsigned long *t;
	int err;

	t = kcalloc(BITS_TO_LONGS(adap->sge.egr_sz), sizeof(long), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	err = bitmap_parse_user(ubuf, count, t, adap->sge.egr_sz);
	if (err)
		return err;

	bitmap_copy(adap->sge.blocked_fl, t, adap->sge.egr_sz);
	t4_free_mem(t);
	return count;
}

static const struct file_operations blocked_fl_fops = {
	.owner   = THIS_MODULE,
	.open    = blocked_fl_open,
	.read    = blocked_fl_read,
	.write   = blocked_fl_write,
	.llseek  = generic_file_llseek,
};

static int tid_info_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	const struct cxgb4_tid_info *t;

	if (!(adap->flags & FULL_INIT_DONE))
		return 0;

	t = &adap->tidinfo;
	seq_printf(seq, "Connections in use: %u\n",
		   t->tids.in_use + t->tids.range_in_use / t->tids.max_range +
		   t->hashcoll_tids.in_use +
		   t->hashcoll_tids.range_in_use / t->hashcoll_tids.max_range +
		   t->hashtids.in_use +
		   t->hashtids.range_in_use / t->hashtids.max_range);

	if (t->hpftids.size)
		seq_printf(seq, "HPFTID range: %u..%u in use-IPv4/IPv6: %u/%u\n",
			   t->hpftids.start,
			   t->hpftids.start + t->hpftids.size - 1,
			   t->hpftids.in_use, t->hpftids.range_in_use);

	if (t->hashtids.size) {
		seq_printf(seq, "TID range: %u..%u/%u..%u",
			   t->hashcoll_tids.start,
			   t->hashcoll_tids.start + t->hashcoll_tids.size - 1,
			   t->hashtids.start,
			   t->hashtids.start + t->hashtids.size - 1);
		seq_printf(seq, ", in use IPv4: %u/%u",
			   t->tids.in_use + t->hashcoll_tids.in_use,
			   t->hashtids.in_use);
		seq_printf(seq, ", in use IPv6: %u/%u\n",
			   t->tids.range_in_use + t->hashcoll_tids.range_in_use,
			   t->hashtids.range_in_use);
	} else if (t->tids.size) {
		seq_printf(seq, "TID range: %u..%u", t->tids.start,
			   t->tids.start + t->tids.size - 1);
		seq_printf(seq, ", in use-IPv4/IPv6: %u/%u\n",
			   t->tids.in_use, t->tids.range_in_use);
	}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (t->stids.size)
		seq_printf(seq, "STID range: %u..%u, in use-IPv4/IPv6: %u/%u\n",
			   t->stids.start, t->stids.start + t->stids.size - 1,
			   t->stids.in_use, t->stids.range_in_use);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	if (t->atids.size)
		seq_printf(seq, "ATID range: %u..%u, in use: %u\n",
			   t->atids.start, t->atids.start + t->atids.size - 1,
			   t->atids.in_use);

	if (t->ftids.size)
		seq_printf(seq, "FTID range: %u..%u in use-IPv4/IPv6: %u/%u\n",
			   t->ftids.start, t->ftids.start + t->ftids.size - 1,
			   t->ftids.in_use, t->ftids.range_in_use);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (t->sftids.size)
		seq_printf(seq, "SFTID range: %u..%u in use: %u\n",
			   t->sftids.start,
			   t->sftids.start + t->sftids.size - 1,
			   t->sftids.in_use);

	if (t->uotids.size)
		seq_printf(seq, "UOTID range: %u..%u, in use: %u\n",
			   t->uotids.start,
			   t->uotids.start + t->uotids.size - 1,
			   t->uotids.in_use);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	if (t->tids.size)
		seq_printf(seq, "HW TID usage: %u IP users, %u IPv6 users\n",
			   t4_read_reg(adap, A_LE_DB_ACT_CNT_IPV4),
			   t4_read_reg(adap, A_LE_DB_ACT_CNT_IPV6));
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(tid_info);

static int mtutab_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	u16 mtus[NMTUS];

	spin_lock(&adap->stats_lock);
	t4_read_mtu_tbl(adap, mtus, NULL);
	spin_unlock(&adap->stats_lock);

	seq_printf(seq, "%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",
		   mtus[0], mtus[1], mtus[2], mtus[3], mtus[4], mtus[5],
		   mtus[6], mtus[7], mtus[8], mtus[9], mtus[10], mtus[11],
		   mtus[12], mtus[13], mtus[14], mtus[15]);
	return 0;
}

static int mtutab_open(struct inode *inode, struct file *file)
{
	return single_open(file, mtutab_show, inode->i_private);
}

static ssize_t mtutab_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *pos)
{
	struct t4_linux_debugfs_data *d = file_inode(file)->i_private;
	struct adapter * const adap = d->adap;
	unsigned long mtus[NMTUS];
	int i;

	/* Require min MTU of 81 to accommodate SACK */
	i = rd_usr_int_vec(buf, count, NMTUS, mtus, 81, MAX_MTU, 10);
	if (i)
		return i;

	/* MTUs must be in ascending order */
	for (i = 1; i < NMTUS; ++i)
		if (mtus[i] < mtus[i - 1])
			return -EINVAL;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	/* can't change the MTU table if offload is in use */
	mutex_lock(&uld_mutex);
	for (i = 0; i < CXGB4_ULD_TYPE_MAX; i++)
		if (adap->uld_handle[i]) {
			mutex_unlock(&uld_mutex);
			return -EBUSY;
		}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	for (i = 0; i < NMTUS; ++i)
		adap->params.mtus[i] = mtus[i];
	t4_load_mtus(adap, adap->params.mtus, adap->params.a_wnd,
		     adap->params.b_wnd);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	mutex_unlock(&uld_mutex);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	return count;
}

static const struct file_operations mtutab_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = mtutab_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = mtutab_write
};

static int mps_trc_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	unsigned int trcidx = d->data;
	struct trace_params tp;
	int enabled, i;

	t4_get_trace_filter(adap, &tp, trcidx, &enabled);
	if (!enabled) {
		seq_puts(seq, "tracer is disabled\n");
		return 0;
	}

	if (tp.skip_ofst * 8 >= TRACE_LEN) {
		dev_err(adap->pdev_dev, "illegal trace pattern skip offset\n");
		return -EINVAL;
	}
	if (tp.port < 8) {
		i = adap->chan_map[tp.port & 3];
		if (i >= MAX_NPORTS) {
			dev_err(adap->pdev_dev, "tracer %u is assigned "
				"to non-existing port\n", trcidx);
			return -EINVAL;
		}
		seq_printf(seq, "tracer is capturing %s %s, ",
			   adap->port[i]->name, tp.port < 4 ? "Rx" : "Tx");
	} else
		seq_printf(seq, "tracer is capturing loopback %d, ",
			   tp.port - 8);
	seq_printf(seq, "snap length: %u, min length: %u\n", tp.snap_len,
		   tp.min_len);
	seq_printf(seq, "packets captured %smatch filter\n",
		   tp.invert ? "do not " : "");

	if (tp.skip_ofst) {
		seq_puts(seq, "filter pattern: ");
		for (i = 0; i < tp.skip_ofst * 2; i += 2)
			seq_printf(seq, "%08x%08x", tp.data[i], tp.data[i + 1]);
		seq_putc(seq, '/');
		for (i = 0; i < tp.skip_ofst * 2; i += 2)
			seq_printf(seq, "%08x%08x", tp.mask[i], tp.mask[i + 1]);
		seq_puts(seq, "@0\n");
	}

	seq_puts(seq, "filter pattern: ");
	for (i = tp.skip_ofst * 2; i < TRACE_LEN / 4; i += 2)
		seq_printf(seq, "%08x%08x", tp.data[i], tp.data[i + 1]);
	seq_putc(seq, '/');
	for (i = tp.skip_ofst * 2; i < TRACE_LEN / 4; i += 2)
		seq_printf(seq, "%08x%08x", tp.mask[i], tp.mask[i + 1]);
	seq_printf(seq, "@%u\n", (tp.skip_ofst + tp.skip_len) * 8);
	return 0;
}

static int mps_trc_open(struct inode *inode, struct file *file)
{
	return single_open(file, mps_trc_show, inode->i_private);
}

static unsigned int xdigit2int(unsigned char c)
{
	return isdigit(c) ? c - '0' : tolower(c) - 'a' + 10;
}

#define TRC_PORT_NONE 0xff

/*
 * Set an MPS trace filter.  Syntax is:
 *
 * disable
 *
 * to disable tracing, or
 *
 * interface [snaplen=<val>] [minlen=<val>] [not] [<pattern>]...
 *
 * where interface is one of rxN, txN, or loopbackN, N = 0..3, and pattern
 * has the form
 *
 * <pattern data>[/<pattern mask>][@<anchor>]
 *
 * Up to 2 filter patterns can be specified.  If 2 are supplied the first one
 * must be anchored at 0.  An omited mask is taken as a mask of 1s, an omitted
 * anchor is taken as 0.
 */
static ssize_t mps_trc_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *pos)
{
	struct t4_linux_debugfs_data *d = file_inode(file)->i_private;
	struct adapter *adap = d->adap;
	unsigned int trcidx = d->data;
	char *s, *p, *word, *end;
	struct trace_params tp;
	int i, j, enable;
	u32 *data, *mask;

	/*
	 * Don't accept input more than 1K, can't be anything valid except lots
	 * of whitespace.  Well, use less.
	 */
	if (count > 1024)
		return -EFBIG;
	p = s = kzalloc(count + 1, GFP_USER);
	if (!s)
		return -ENOMEM;
	if (copy_from_user(s, buf, count)) {
		count = -EFAULT;
		goto out;
	}

	if (s[count - 1] == '\n')
		s[count - 1] = '\0';

	enable = strcmp("disable", s) != 0;
	if (!enable)
		goto apply;

	memset(&tp, 0, sizeof(tp));
	tp.port = TRC_PORT_NONE;
	i = 0;                                      /* counts pattern nibbles */

	while (p) {
		while (isspace(*p))
			p++;
		word = strsep(&p, " ");
		if (!*word)
			break;

		if (!strncmp(word, "snaplen=", 8)) {
			j = simple_strtoul(word + 8, &end, 10);
			if (*end || j > 9600) {
inval:				count = -EINVAL;
				goto out;
			}
			tp.snap_len = j;
			continue;
		}
		if (!strncmp(word, "minlen=", 7)) {
			j = simple_strtoul(word + 7, &end, 10);
			if (*end || j > M_TFMINPKTSIZE)
				goto inval;
			tp.min_len = j;
			continue;
		}
		if (!strcmp(word, "not")) {
			tp.invert = !tp.invert;
			continue;
		}
		if (!strncmp(word, "loopback", 8) && tp.port == TRC_PORT_NONE) {
			if (word[8] < '0' || word[8] > '3' || word[9])
				goto inval;
			tp.port = word[8] - '0' + 8;
			continue;
		}
		if (!strncmp(word, "tx", 2) && tp.port == TRC_PORT_NONE) {
			if (word[2] < '0' || word[2] > '3' || word[3])
				goto inval;
			tp.port = word[2] - '0' + 4;
			if (adap->chan_map[tp.port & 3] >= MAX_NPORTS)
				goto inval;
			continue;
		}
		if (!strncmp(word, "rx", 2) && tp.port == TRC_PORT_NONE) {
			if (word[2] < '0' || word[2] > '3' || word[3])
				goto inval;
			tp.port = word[2] - '0';
			if (adap->chan_map[tp.port] >= MAX_NPORTS)
				goto inval;
			continue;
		}
		if (!isxdigit(*word))
			goto inval;

		/* we have found a trace pattern */
		if (i) {                            /* split pattern */
			if (tp.skip_len)            /* too many splits */
				goto inval;
			tp.skip_ofst = i / 16;
		}

		data = &tp.data[i / 8];
		mask = &tp.mask[i / 8];
		j = i;

		while (isxdigit(*word)) {
			if (i >= TRACE_LEN * 2) {
				count = -EFBIG;
				goto out;
			}
			*data = (*data << 4) + xdigit2int(*word++);
			if (++i % 8 == 0)
				data++;
		}
		if (*word == '/') {
			word++;
			while (isxdigit(*word)) {
				if (j >= i)         /* mask longer than data */
					goto inval;
				*mask = (*mask << 4) + xdigit2int(*word++);
				if (++j % 8 == 0)
					mask++;
			}
			if (i != j)                 /* mask shorter than data */
				goto inval;
		} else {                            /* no mask, use all 1s */
			for ( ; i - j >= 8; j += 8)
				*mask++ = 0xffffffff;
			if (i % 8)
				*mask = (1 << (i % 8) * 4) - 1;
		}
		if (*word == '@') {
			j = simple_strtoul(word + 1, &end, 10);
			if (*end && *end != '\n')
				goto inval;
			if (j & 7)          /* doesn't start at multiple of 8 */
				goto inval;
			j /= 8;
			if (j < tp.skip_ofst)     /* overlaps earlier pattern */
				goto inval;
			if (j - tp.skip_ofst > 31)            /* skip too big */
				goto inval;
			tp.skip_len = j - tp.skip_ofst;
		}
		if (i % 8) {
			*data <<= (8 - i % 8) * 4;
			*mask <<= (8 - i % 8) * 4;
			i = (i + 15) & ~15;         /* 8-byte align */
		}
	}

	if (tp.port == TRC_PORT_NONE)
		goto inval;

#if 0
	if (tp.port < 8)
		printk("tracer is capturing %s %s, ",
			adap->port[adap->chan_map[tp.port & 3]]->name,
			tp.port < 4 ? "Rx" : "Tx");
	else
		printk("tracer is capturing loopback %u, ", tp.port - 8);
	printk("snap length: %u, min length: %u\n", tp.snap_len, tp.min_len);
	printk("packets captured %smatch filter\n", tp.invert ? "do not " : "");

	if (tp.skip_ofst) {
		printk("filter pattern: ");
		for (i = 0; i < tp.skip_ofst * 2; i += 2)
			printk("%08x%08x", tp.data[i], tp.data[i + 1]);
		printk("/");
		for (i = 0; i < tp.skip_ofst * 2; i += 2)
			printk("%08x%08x", tp.mask[i], tp.mask[i + 1]);
		printk("@0\n");
	}

	printk("filter pattern: ");
	for (i = tp.skip_ofst * 2; i < TRACE_LEN / 4; i += 2)
		printk("%08x%08x", tp.data[i], tp.data[i + 1]);
	printk("/");
	for (i = tp.skip_ofst * 2; i < TRACE_LEN / 4; i += 2)
		printk("%08x%08x", tp.mask[i], tp.mask[i + 1]);
	printk("@%u\n", (tp.skip_ofst + tp.skip_len) * 8);
#endif

apply:
	i = t4_set_trace_filter(adap, &tp, trcidx, enable);
	if (i)
		count = i;
out:
	kfree(s);
	return count;
}

static const struct file_operations mps_trc_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = mps_trc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = mps_trc_write
};

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static int chcr_stats_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)
	struct ch_ipsec_stats_debug *ch_ipsec_stats;
#endif
	struct adapter *adap = d->adap;
	struct chcr_stats *chcr_stats;

	chcr_stats = &adap->uld.stats.chcr;
	seq_puts(seq, "Chelsio Crypto Co-processor Stats \n");
	seq_printf(seq, "Cipher_ops: %u \n",
		atomic_read(&chcr_stats->cipher_rqst));
	seq_printf(seq, "Digest_ops: %u \n",
		atomic_read(&chcr_stats->digest_rqst)); 
	seq_printf(seq, "Aead_ops: %u \n",
		atomic_read(&chcr_stats->aead_rqst)); 
	seq_printf(seq, "Completion: %u \n",
		atomic_read(&chcr_stats->rqst_comp));
	seq_printf(seq, "Error: %u \n",
		atomic_read(&chcr_stats->rsp_error));
	seq_printf(seq, "Fallback: %u \n",
		atomic_read(&chcr_stats->fallback));
#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)
	ch_ipsec_stats = &adap->uld.stats.ipsec;
	seq_puts(seq, "\nChelsio Inline IPsec Crypto Accelerator Stats\n");
	seq_printf(seq, "IPSec PDU: %10u\n",
		atomic_read(&ch_ipsec_stats->ipsec_cnt));
	seq_printf(seq, "rx IPSec PDU: %10u\n",
		atomic_read(&ch_ipsec_stats->ipsec_rx_cnt));
	seq_printf(seq, "nipsec_transport: %10u\n",
		atomic_read(&ch_ipsec_stats->nipsec_transport));
	seq_printf(seq, "nipsec_tunnel: %10u\n",
		atomic_read(&ch_ipsec_stats->nipsec_tunnel));
	if (cxgb4_ulds[CXGB4_ULD_TYPE_IPSEC].ch_ipsec_show)
		cxgb4_ulds[CXGB4_ULD_TYPE_IPSEC].ch_ipsec_show(adap, seq);
#endif

	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(chcr_stats);

static int tls_stats_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct tls_stats *tls_stats;

	tls_stats = &adap->uld.stats.tls;

	seq_puts(seq, "Chelsio Inline TLS and DTLS Stats\n");
	seq_printf(seq, "TLS PDU Tx: %u \n",
		atomic_read(&tls_stats->tls_pdu_tx)); 
	seq_printf(seq, "TLS PDU Rx: %u \n",
		atomic_read(&tls_stats->tls_pdu_rx)); 
	seq_printf(seq, "DTLS PDU Tx: %u\n",
		atomic_read(&tls_stats->dtls_pdu_tx));
	seq_printf(seq, "DTLS PDU Rx: %u\n",
		atomic_read(&tls_stats->dtls_pdu_rx));
	seq_printf(seq, "TLS Keys (DDR) Count: %u \n",
		atomic_read(&tls_stats->tls_key)); 

	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(tls_stats);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

static int cudbg_kcrash_flags_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;

	seq_printf(seq, "%lu\n", adap->cudbg_kcrash_flags);
	return 0;
}

static int cudbg_kcrash_flags_open(struct inode *inode, struct file *file)
{
	return single_open(file, cudbg_kcrash_flags_show, inode->i_private);
}

static ssize_t cudbg_kcrash_flags_write(struct file *file,
					const char __user *buf,
					size_t count, loff_t *pos)
{
	struct t4_linux_debugfs_data *d = file_inode(file)->i_private;
	struct adapter *adap = d->adap;
	unsigned long val;
	size_t size;
	char s[32];
	int err;

	size = min(sizeof(s) - 1, count);
	if (copy_from_user(s, buf, size))
		return -EFAULT;

	s[size] = '\0';
	err = kstrtoul(s, 0, &val);
	if (err)
		return err;

	adap->cudbg_kcrash_flags = val;
	return count;
}

static const struct file_operations cudbg_kcrash_flags_fops = {
	.owner   = THIS_MODULE,
	.open    = cudbg_kcrash_flags_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = cudbg_kcrash_flags_write,
};

/*
 * Add an array of Debug FS files.
 */
static void cxgb4_add_debugfs_files(struct adapter *adap,
				    struct t4_linux_debugfs_entry *files,
				    unsigned int nfiles)
{
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	int ofld = cxgb4_uld_supported_any(adap);
	int crypto = is_crypto(adap);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	int i;

	/* debugfs support is best effort */
	for (i = 0; i < nfiles; i++) {
		unsigned int req = files[i].req;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		if ((req & ADAP_NEED_OFLD) && !ofld)
			continue;
		if ((req & ADAP_NEED_SRQ) && !adap->uld.srq)
			continue;
		if ((req & ADAP_NEED_CRYPTO) && (!crypto))
			continue;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
		if ((req & ADAP_NEED_L2T) && !adap->l2t)
			continue;
                if ((req & ADAP_NEED_SMT) && !adap->smt)
                        continue;
		add_debugfs_files(adap, adap->debugfs_root, 0, &files[i], 1);
	}
}

int cxgb4_setup_debugfs(struct adapter *adap)
{
	static struct t4_linux_debugfs_entry cxgb4_debugfs_files[] = {
		{ "blocked_fl", &blocked_fl_fops, 0600, 0, 0},
#ifdef CONFIG_CXGB4_DCB
		{ "dcb_info", &dcb_info_debugfs_fops, 0400, 0, 0 },
#endif
		{ "resources", &resources_debugfs_fops, 0400, 0, 0 },
		{ "sge_qinfo", &sge_qinfo_debugfs_fops, 0400, 0, 0 },
		{ "intr_holdoff", &intr_holdoff_debugfs_fops, 0400, 0, 0 },
		{ "intr_cnt", &intr_cnt_debugfs_fops, 0400, 0, 0 },
#ifdef CXGB4_DEBUG
		{ "inject_err", &inject_err_debugfs_fops, 0400, 0, 0 },
#endif
		{ "clip_tbl", &clip_tbl_debugfs_fops, 0400, 0, 0 },
		{ "tids", &tid_info_debugfs_fops, 0400, 0, ADAP_NEED_FILT },
		{ "path_mtus", &mtutab_debugfs_fops, 0600, 0, 0 },
		{ "filters", &filters_debugfs_fops, 0400, 0, 0 },
		{ "hash_filters", &hash_filters_debugfs_fops, 0400, 0, 0 },
		{ "trace0", &mps_trc_debugfs_fops, 0600, 0, 0 },
		{ "trace1", &mps_trc_debugfs_fops, 0600, 1, 0 },
		{ "trace2", &mps_trc_debugfs_fops, 0600, 2, 0 },
		{ "trace3", &mps_trc_debugfs_fops, 0600, 3, 0 },
		{ "cudbg_kcrash_flags", &cudbg_kcrash_flags_fops, 0600, 0, 0 },
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		{ "uld", &uld_debugfs_fops, 0400, 0, 0 },
		{ "l2t", &t4_l2t_debugfs_fops, 0400, 0, ADAP_NEED_L2T },
		{ "smt", &t4_smt_debugfs_fops, 0400, 0, ADAP_NEED_SMT },
		{ "srq", &t4_srq_debugfs_fops, 0400, 0, ADAP_NEED_SRQ },
		{ "crypto", &chcr_stats_debugfs_fops, 0400, 0, ADAP_NEED_CRYPTO },
		{ "tls", &tls_stats_debugfs_fops, 0400, 0, ADAP_NEED_CRYPTO },
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	};

	static struct t4_linux_debugfs_entry cxgb4_t7_debugfs_files[] = {
		{ "trace4", &mps_trc_debugfs_fops, 0600, 4, 0 },
		{ "trace5", &mps_trc_debugfs_fops, 0600, 5, 0 },
		{ "trace6", &mps_trc_debugfs_fops, 0600, 6, 0 },
		{ "trace7", &mps_trc_debugfs_fops, 0600, 7, 0 },
	};

	if (setup_debugfs(adap))
		return -1;

	cxgb4_add_debugfs_files(adap,
			  cxgb4_debugfs_files,
			  ARRAY_SIZE(cxgb4_debugfs_files));

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7)
		cxgb4_add_debugfs_files(adap, cxgb4_t7_debugfs_files,
					ARRAY_SIZE(cxgb4_t7_debugfs_files));
	return 0;
}

