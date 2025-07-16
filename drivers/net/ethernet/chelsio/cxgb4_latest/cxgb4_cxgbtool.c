/*
 *  Copyright (C) 2008-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 */
#include "common.h"
#include "cxgbtool.h"
#include "cxgb4_cxgbtool.h"
#include "cxgb4_filter.h"
#include "t4_regs.h"

#ifdef CONFIG_CHELSIO_T4_OFFLOAD

#define ERR(fmt, ...) do {\
	printk(KERN_ERR "%s: " fmt "\n", dev->name, ## __VA_ARGS__); \
	return -EINVAL; \
} while (0)

/*
 * Perform device independent validation of offload policy.
 */
static int validate_offload_policy(const struct net_device *dev,
				   const struct ofld_policy_file *f,
				   size_t tot_len)
{
	size_t txt_hdr_sz = sizeof(struct cop_txt_hdr);
	const struct ofld_prog_inst *pi;
	const struct cop_txt_hdr *th;
	size_t op_len = 0;
	const u32 *p;
	int i, inst;

	if (f->vers == 0)
		op_len = SETTINGS_LEN(f->nrules, f->prog_size, f->opt_prog_size,
				      SZ_VER_0);
	else if (f->vers >= 1)
		op_len = SETTINGS_LEN(f->nrules, f->prog_size, f->opt_prog_size,
				      SZ_VER_1);
	/*
	 * We validate the following:
	 * - Program sizes match what's in the header
	 * - Branch targets are within the program
	 * - Offsets do not step outside struct offload_req
	 * - Outputs are valid
	 */
	printk(KERN_DEBUG "version %u, program length %zu bytes, alternate "
	       "program length %zu bytes\n", f->vers,
	       f->prog_size * sizeof(*pi), f->opt_prog_size * sizeof(*p));

	if ((f->vers <= 1) && (op_len != tot_len))
			ERR("bad offload policy length %zu\n", tot_len);
	else if (f->vers == 2) {
		/* bail out if text header is missing */
		if (tot_len < op_len + txt_hdr_sz)
			ERR("bad cop text header length\n");

		/* get the pointer to text header */
		th = (const struct cop_txt_hdr *)((char *)f + op_len);
		if (strncmp((const char *)th->sig, "CCOP", strlen("CCOP")) != 0)
			ERR("invalid cop text header signature\n");
		if (th->vers != 1)
			ERR("invalid cop text header version\n");
		/* total length should be equal to
		 * offload policy length + cop text length
		 */
		if (th->size && (th->size + op_len + txt_hdr_sz != tot_len))
			ERR("bad cop text length");
	}

	if (f->output_everything >= 0 && f->output_everything > f->nrules)
		ERR("illegal output_everything %d in header",
		    f->output_everything);

	pi = f->prog;

	for (i = 0; i < f->prog_size; i++, pi++) {
		if (pi->offset < 0 ||
		    pi->offset >= sizeof(struct offload_req) / 4)
			ERR("illegal offset %d at instruction %d", pi->offset,
			    i);
		if (pi->next[0] < 0 && -pi->next[0] > f->nrules)
			ERR("illegal output %d at instruction %d",
			    -pi->next[0], i);
		if (pi->next[1] < 0 && -pi->next[1] > f->nrules)
			ERR("illegal output %d at instruction %d",
			    -pi->next[1], i);
		if (pi->next[0] > 0 && pi->next[0] >= f->prog_size)
			ERR("illegal branch target %d at instruction %d",
			    pi->next[0], i);
		if (pi->next[1] > 0 && pi->next[1] >= f->prog_size)
			ERR("illegal branch target %d at instruction %d",
			    pi->next[1], i);
	}

	p = (const u32 *)pi;

	for (inst = i = 0; i < f->opt_prog_size; inst++) {
		unsigned int off = *p & 0xffff, nvals = *p >> 16;

		if (off >= sizeof(struct offload_req) / 4)
			ERR("illegal offset %u at opt instruction %d",
			    off, inst);
		if ((int32_t)p[1] < 0 && -p[1] > f->nrules)
			ERR("illegal output %d at opt instruction %d",
			    -p[1], inst);
		if ((int32_t)p[2] < 0 && -p[2] > f->nrules)
			ERR("illegal output %d at opt instruction %d",
			    -p[2], inst);
		if ((int32_t)p[1] > 0 && p[1] >= f->opt_prog_size)
			ERR("illegal branch target %d at opt instruction %d",
			    p[1], inst);
		if ((int32_t)p[2] > 0 && p[2] >= f->opt_prog_size)
			ERR("illegal branch target %d at opt instruction %d",
			    p[2], inst);
		p += 4 + nvals;
		i += 4 + nvals;
		if (i > f->opt_prog_size)
			ERR("too many values %u for opt instruction %d",
			    nvals, inst);
	}

	return 0;
}

#undef ERR

static int validate_policy_settings(const struct net_device *dev,
				    struct adapter *adap,
				    const struct ofld_policy_file *f)
{
	int i;
	const u32 *op = (const u32 *)&f->prog[f->prog_size];
	const struct offload_settings *s = (void *)&op[f->opt_prog_size];

	for (i = 0; i <= f->nrules; i++, s++) {
		if (s->cong_algo > 3) {
			printk(KERN_ERR "%s: illegal congestion algorithm %d\n",
			       dev->name, s->cong_algo);
			return -EINVAL;
		}
		if (s->rssq >= adap->sge.ofldqsets) {
			printk(KERN_ERR "%s: illegal RSS queue %d\n", dev->name,
			       s->rssq);
			return -EINVAL;
		}
		if (s->sched_class >= 0 &&
		    s->sched_class >= adap->params.nsched_cls) {
			printk(KERN_ERR "%s: illegal scheduling class %d\n",
			       dev->name, s->sched_class);
			return -EINVAL;
		}
	}
	return 0;
}
#endif

/* clear port-related stats maintained by the port's associated queues */
static void clear_sge_port_stats(struct adapter *adap, struct port_info *p)
{
	int i;
	struct sge_eth_txq *tx = &adap->sge.ethtxq[p->first_qset];
	struct sge_eth_rxq *rx = &adap->sge.ethrxq[p->first_qset];

	for (i = 0; i < p->nqsets; i++, rx++, tx++) {
		memset(&rx->stats, 0, sizeof(rx->stats));
		tx->tso = 0;
		tx->tx_cso = 0;
		tx->vlan_ins = 0;
		tx->coal_wr = 0;
		tx->coal_pkts = 0;
		rx->stats.lro_pkts = 0;
		rx->stats.lro_merged = 0;
	}
}

/* clear statistics for the given Ethernet Tx and Rx queues */
static void clear_ethq_stats(struct sge *p, unsigned int idx)
{
	struct sge_eth_rxq *rxq = &p->ethrxq[idx];
	struct sge_eth_txq *txq = &p->ethtxq[idx];

	memset(&rxq->stats, 0, sizeof(rxq->stats));
	rxq->fl.alloc_failed = rxq->fl.large_alloc_failed = 0;
	rxq->fl.starving = 0;

	txq->tso = txq->tx_cso = txq->vlan_ins = 0;
	txq->q.stops = txq->q.restarts = 0;
	txq->mapping_err = 0;
}

/* clear statistics for the Ethernet queues associated with the given port */
static void clear_port_qstats(struct adapter *adap, const struct port_info *pi)
{
	int i;

	for (i = 0; i < pi->nqsets; i++)
		clear_ethq_stats(&adap->sge, pi->first_qset + i);
}

static void cxgb4_cxgbtool_tp_get_cpl_stats(struct adapter *adap,
					    struct port_info *pi)
{
	struct tp_cpl_stats cpl_stats;

	t4_tp_get_cpl_stats(adap, &cpl_stats, true);

	adap->tp_cpl_stats_base.req[pi->lport] = cpl_stats.req[pi->lport];
	adap->tp_cpl_stats_base.rsp[pi->lport] = cpl_stats.rsp[pi->lport];
}

static void cxgb4_cxgbtool_tp_get_err_stats(struct adapter *adap,
					    struct port_info *pi)
{
	struct tp_err_stats err_stats;

	t4_tp_get_err_stats(adap, &err_stats, true);

	adap->tp_err_stats_base.mac_in_errs[pi->lport] =
		err_stats.mac_in_errs[pi->lport];
	adap->tp_err_stats_base.hdr_in_errs[pi->lport] =
		err_stats.hdr_in_errs[pi->lport];
	adap->tp_err_stats_base.tcp_in_errs[pi->lport] =
		err_stats.tcp_in_errs[pi->lport];
	adap->tp_err_stats_base.tnl_cong_drops[pi->lport] =
		err_stats.tnl_cong_drops[pi->lport];
	adap->tp_err_stats_base.ofld_chan_drops[pi->lport] =
		err_stats.ofld_chan_drops[pi->lport];
	adap->tp_err_stats_base.tnl_tx_drops[pi->lport] =
		err_stats.tnl_tx_drops[pi->lport];
	adap->tp_err_stats_base.ofld_vlan_drops[pi->lport] =
		err_stats.ofld_vlan_drops[pi->lport];
	adap->tp_err_stats_base.tcp6_in_errs[pi->lport] =
		err_stats.tcp6_in_errs[pi->lport];
	adap->tp_err_stats_base.ofld_no_neigh = err_stats.ofld_no_neigh;
	adap->tp_err_stats_base.ofld_cong_defer = err_stats.ofld_cong_defer;
}

/**
 *	cxgb4_cxgbtool_get_desc - dump an SGE descriptor for debugging purposes
 *	@p: points to the sge structure for the adapter
 *	@category: the type of queue
 *	@qid: the absolute SGE QID of the specific queue within the category
 *	@idx: the descriptor index in the queue
 *	@data: where to dump the descriptor contents
 *
 *	Dumps the contents of a HW descriptor of an SGE queue.  Returns the
 *	size of the descriptor or a negative error.
 */
static int cxgb4_cxgbtool_get_qdesc(struct sge *p, int category,
				    unsigned int qid, unsigned int idx,
				    unsigned char *data)
{
	int i, len = sizeof(struct tx_desc);

	/*
	 * For Tx queues allow reading the status entry too.
	 */
	if (category == SGE_QTYPE_TX_ETH) {
		const struct sge_eth_txq *q = p->ethtxq;

		for (i = 0; i < ARRAY_SIZE(p->ethtxq); i++, q++)
			if (q->q.cntxt_id == qid && q->q.desc &&
			    idx <= q->q.size) {
				memcpy(data, &q->q.desc[idx], len);
				return len;
			}
	}
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (category == SGE_QTYPE_TX_OFLD) {
		struct adapter *adap = container_of(p, struct adapter, sge);
		int ret;

		ret = cxgb4_uld_txq_get_desc(adap, CXGB4_ULD_TYPE_TOE,
					     qid, data, idx, len);
		if (!ret)
			return len;
	}
	if (category == SGE_QTYPE_TX_CRYPTO) {
		struct adapter *adap = container_of(p, struct adapter, sge);
		int ret;

		ret = cxgb4_uld_txq_get_desc(adap, CXGB4_ULD_TYPE_CRYPTO,
					     qid, data, idx, len);
		if (!ret)
			return len;
	}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	if (category == SGE_QTYPE_TX_CTRL) {
		const struct sge_ctrl_txq *q = p->ctrlq;

		for (i = 0; i < ARRAY_SIZE(p->ctrlq); i++, q++)
			if (q->q.cntxt_id == qid && q->q.desc &&
			    idx <= q->q.size) {
				memcpy(data, &q->q.desc[idx], len);
				return len;
			}
	}
	if (category == SGE_QTYPE_FL) {
		const struct sge_fl *q = NULL;

		if (qid >= p->egr_start &&
		    qid < p->egr_start + p->egr_sz)
			q = cxgb4_sge_egr_map_get(&p->egr_map, qid);
		if (q && q >= &p->ethrxq[0].fl && idx < q->size) {
			*(__be64 *)data = q->desc[idx];
			return sizeof(u64);
		}
	}
	if (category == SGE_QTYPE_RSP) {
		const struct sge_rspq *q = NULL;

		if (qid >= p->ingr_start &&
		    qid < p->ingr_start + p->ingr_sz)
			q = p->ingr_map[qid - p->ingr_start];
		if (q && idx < q->size) {
			len = q->iqe_len;
			idx *= len / sizeof(u64);
			memcpy(data, &q->desc[idx], len);
			return len;
		}
	}
	return -EINVAL;
}

/*
 * Retrieve a list of bypass ports.
 */
static int get_bypass_ports(struct adapter *adapter, 
				struct ch_bypass_ports *cba)
{
	const struct net_device *dev;
	int i = 0;

	for_each_port(adapter, i) {
		dev = adapter->port[i];
		strncpy(cba->ba_if[i].if_name, dev->name, IFNAMSIZ);
	}
	cba->port_count = adapter->params.nports;

	return 0;
}

/*
 *  Helper function to set Ethernet Queue Sets
 */
static int set_eth_qsets(struct net_device *dev, int nqueues)
{

	struct adapter *adapter = netdev2adap(dev);
	struct port_info *pi = netdev_priv(dev);
	int port, first_qset, other_queues, ncpus;

	/*
	 * Check legitimate range for number of Queue Sets.  We need
	 * at least one Queue Set and we can't have more that
	 * max_ethqsets.  (Note that the incoming value from User
	 * Space is an unsigned 32-bit value.  Since that includes
	 * 0xffff == (u32)-1, if we depend solely on the test below
	 * for "edata.val + other_qsets > adapter->sge.max_ethqsets",
	 * then we'll miss such bad values because of wrap-around
	 * arithmetic.)
	 */
	if (nqueues < 1 || nqueues > adapter->sge.max_ethqsets)
		return -EINVAL;

	/*
	 * For Ethernet Queue Sets, it doesn't make sense to have more than
	 * the number of CPUs.
	 */
	ncpus   = num_online_cpus();
	if (nqueues > ncpus)
		nqueues = ncpus;

	other_queues = adapter->sge.ethqsets - pi->nqsets;
	if (nqueues + other_queues > adapter->sge.max_ethqsets ||
			nqueues > pi->rss_size)
		return -EINVAL;

	pi->nqsets = nqueues;
	netif_set_real_num_tx_queues(dev, pi->nqsets);
	netif_set_real_num_rx_queues(dev, pi->nqsets);
	adapter->sge.ethqsets = other_queues + pi->nqsets;

	first_qset = 0;
	for_each_port(adapter, port)
		if (adapter->port[port]) {
			pi = adap2pinfo(adapter, port);
			pi->first_qset = first_qset;
			first_qset += pi->nqsets;
		}
	return 0;
}


/*
 * Translate the Firmware FEC value into the cxgbtool enum value.
 */
static inline unsigned int fw_to_cx_fec(unsigned int fw_fec)
{
	unsigned int cx_fec = 0;

	if (fw_fec & FW_PORT_CAP32_FEC_RS)
		cx_fec |= FEC_TYPE_RS;
	if (fw_fec & FW_PORT_CAP32_FEC_BASER_RS)
		cx_fec |= FEC_TYPE_BASER_RS;

	/* if nothing is set, then FEC is off */
	if (!cx_fec)
		cx_fec = FEC_TYPE_OFF;

	return cx_fec;
}

/*
 * Translate Common Code FEC value into cxgbtool enum value.
 */
static inline unsigned int cc_to_cx_fec(unsigned int cc_fec)
{
	unsigned int cx_fec = 0;

	if (cc_fec & FEC_AUTO)
		cx_fec |= FEC_TYPE_AUTO;
	if (cc_fec & FEC_RS)
		cx_fec |= FEC_TYPE_RS;
	if (cc_fec & FEC_BASER_RS)
		cx_fec |= FEC_TYPE_BASER_RS;

	/* if nothing is set, then FEC is off */
	if (!cx_fec)
		cx_fec = FEC_TYPE_OFF;

	return cx_fec;
}

/*
 * Translate cxgbtool enum FEC value into Common Code value.
 */
static inline unsigned int cx_to_cc_fec(unsigned int cx_fec)
{
	unsigned int cc_fec = 0;

	cc_fec |= FEC_FORCE;

	if (cx_fec & FEC_TYPE_OFF)
		return cc_fec;

	if (cx_fec & FEC_TYPE_AUTO)
		cc_fec |= FEC_AUTO;
	if (cx_fec & FEC_TYPE_RS)
		cc_fec |= FEC_RS;
	if (cx_fec & FEC_TYPE_BASER_RS)
		cc_fec |= FEC_BASER_RS;

	return cc_fec;
}

/*
 * Translate a Firmware Port Capabilities FEC value into a cxgbtool enum value.
 */
static inline unsigned int fwcap_to_cx_fec(fw_port_cap32_t fwcaps)
{
	unsigned int cx_fec = 0;

	if (fwcaps & FW_PORT_CAP32_FEC_RS)
		cx_fec |= FEC_TYPE_RS;
	if (fwcaps & FW_PORT_CAP32_FEC_BASER_RS)
		cx_fec |= FEC_TYPE_BASER_RS;

	return cx_fec;
}

/*
 * Simple predicate to vet incoming Chelsio ioctl() parameters to make sure
 * they are either not set (value < 0) or within the indicated range.
 */
static int cxgb4_in_range(int val, int lo, int hi)
{
	return val < 0 || (val <= hi && val >= lo);
}

static int cxgb4_cxgbtool_get_mps_trace_filter(struct net_device *dev,
					       void __user *useraddr)
{
	struct adapter *adapter = netdev2adap(dev);
	struct ch_mps_trace_filter *t;
	struct trace_params *tp;
	int enable, ret = 0;
	char *p;
	u32 i;

	tp = t4_os_alloc(sizeof(*tp));
	if (!tp)
		return -ENOMEM;
	t = t4_os_alloc(sizeof(*t));
	if (!t) {
		t4_os_free(tp);
		return -ENOMEM;
	}

	if (!(adapter->flags & FULL_INIT_DONE)) {
		ret = -EAGAIN;
		goto out_free; /* uP and SGE must be running */
	}

	if (copy_from_user(t, useraddr, sizeof(*t))) {
		ret = -EFAULT;
		goto out_free;
	}

	if (t->index > MAX_NPORTS) {
		ret = -ERANGE;
		goto out_free;
	}

	if (sizeof(tp->data) > sizeof(t->data) ||
	    sizeof(tp->mask) > sizeof(t->mask)) {
		ret = -ERANGE;
		goto out_free;
	}
	t4_get_trace_filter(adapter, tp, t->index, &enable);

	if (!enable) {
		t->mps_op = CH_MPS_TRACE_FILTER_OP_DISABLE;
		goto done_mps_trace_filter;
	} else if (tp->port >= 8) {
		t->mps_op = CH_MPS_TRACE_FILTER_OP_LOOPBACK;
		t->loopback = tp->port - 8;
	} else if (tp->port >= 4) {
		t->mps_op = CH_MPS_TRACE_FILTER_OP_TX;
		t->tx = tp->port - 4;
	} else {
		t->mps_op = CH_MPS_TRACE_FILTER_OP_RX;
		t->rx = tp->port;
	}

	t->invert = tp->invert;
	t->snap_len = tp->snap_len;
	t->min_len = tp->min_len;
	t->skip_offset = tp->skip_ofst;
	t->skip_len = tp->skip_len;
	p = (char *)tp->mask;
	for (i = 0; i < sizeof(tp->mask); i++) {
		if (p[i]) {
			t->data_size = sizeof(tp->data);
			t->mask_size = sizeof(tp->mask);
			break;
		}
	}

	if (t->mask_size) {
		u8 done = 0;
		u32 j;
		int k;

		for (i = 0, j = 0; i < sizeof(tp->data); i++) {
			for (k = 3; k >= 0; k--, j++) {
				t->data[j] = (tp->data[i] >> (k * 8) & 0xff);
				t->mask[j] = (tp->mask[i] >> (k * 8) & 0xff);
				if (j >= t->mask_size - 1) {
					done = 1;
					break;
				}
			}

			if (done)
				break;
		}
	}

done_mps_trace_filter:
	if (copy_to_user(useraddr, t, sizeof(*t)))
		ret = -EFAULT;
out_free:
	if (tp)
		t4_os_free(tp);
	if (t)
		t4_os_free(t);
	return ret;
}

static int cxgb4_cxgbtool_set_mps_trace_filter(struct net_device *dev,
					       void __user *useraddr)
{
	struct adapter *adapter = netdev2adap(dev);
	struct ch_mps_trace_filter *t;
	struct trace_params *tp;
	bool enable = true;
	int ret = 0;

	tp = t4_os_alloc(sizeof(*tp));
	if (!tp)
		return -ENOMEM;
	t = t4_os_alloc(sizeof(*t));
	if (!t) {
		t4_os_free(tp);
		return -ENOMEM;
	}

	if (!(adapter->flags & FULL_INIT_DONE)) {
		ret = -EAGAIN;
		goto out_free; /* uP and SGE must be running */
	}

	if (copy_from_user(t, useraddr, sizeof(*t))) {
		ret = -EFAULT;
		goto out_free;
	}

	if (t->index > MAX_NPORTS) {
		ret = -ERANGE;
		goto out_free;
	}

	if (t->data_size > sizeof(tp->data) ||
	    t->mask_size > sizeof(tp->mask)) {
		ret = -ERANGE;
		goto out_free;
	}

	if (t->mask_size > t->data_size) {
		ret = -EINVAL;
		goto out_free;
	}

	switch (t->mps_op) {
	case CH_MPS_TRACE_FILTER_OP_DISABLE:
		enable = false;
		goto apply_mps_trace_filter;
	case CH_MPS_TRACE_FILTER_OP_RX:
		if (t->rx > MAX_NPORTS) {
			ret = -ERANGE;
			goto out_free;
		}
		tp->port = t->rx;
		break;
	case CH_MPS_TRACE_FILTER_OP_TX:
		if (t->tx > MAX_NPORTS) {
			ret = -ERANGE;
			goto out_free;
		}
		tp->port = t->tx + 4;
		break;
	case CH_MPS_TRACE_FILTER_OP_LOOPBACK:
		if (t->loopback > MAX_NPORTS) {
			ret = -ERANGE;
			goto out_free;
		}
		tp->port = t->loopback + 8;
		break;
	default:
		ret = -EOPNOTSUPP;
		goto out_free;
	}

	tp->invert = t->invert;
	tp->snap_len = t->snap_len;
	tp->min_len = t->min_len;
	tp->skip_ofst = t->skip_offset;
	tp->skip_len = t->skip_len;
	if (t->mask_size) {
		u8 done = 0;
		u32 i, j;
		int k;

		for (i = 0, j = 0; i < sizeof(tp->data); i++) {
			for (k = 3; k >= 0; k--, j++) {
				tp->data[i] |= t->data[j] << (k * 8);
				tp->mask[i] |= t->mask[j] << (k * 8);

				if (j >= t->mask_size - 1) {
					done = 1;
					break;
				}
			}

			if (done)
				break;
		}
	}

apply_mps_trace_filter:
	ret = t4_set_trace_filter(adapter, tp, t->index, enable);

out_free:
	if (tp)
		t4_os_free(tp);
	if (t)
		t4_os_free(t);

	return ret;
}

u32 cxgb4_cxgbtool_filter_id_to_ftid(struct adapter *adap, u32 filter_id,
				     struct ch_filter_specification *fs)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	if (CHELSIO_CHIP_VERSION(adap->params.chip) > CHELSIO_T5 && fs->prio)
		return filter_id + t->hpftids.start;

	return filter_id + t->ftids.start - t->hpftids.size;
}
EXPORT_SYMBOL(cxgb4_cxgbtool_filter_id_to_ftid);

u32 cxgb4_cxgbtool_ftid_to_filter_id(struct adapter *adap, u32 ftid,
				     struct ch_filter_specification *fs)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	if (CHELSIO_CHIP_VERSION(adap->params.chip) > CHELSIO_T5 && fs->prio)
		return ftid - t->hpftids.start;

	return ftid - t->ftids.start + t->hpftids.size;
}
EXPORT_SYMBOL(cxgb4_cxgbtool_ftid_to_filter_id);

int cxgb_extension_ioctl(struct net_device *dev, void __user *useraddr)
{
	struct adapter *adapter = netdev2adap(dev);
	struct sge *s = &adapter->sge;
	int ret = 0;
	u32 cmd;

	if (copy_from_user(&cmd, useraddr, sizeof(cmd)))
		return -EFAULT;

	switch (cmd) {
	case CHELSIO_SETREG: {
		struct ch_reg edata;

		if (!allow_nonroot_ioctl && !capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if ((edata.addr & 3) != 0 ||
		    edata.addr >= cxgb4_common_resource_size(adapter, 0))
			return -EINVAL;
		t4_write_reg(adapter, edata.addr, edata.val);
		break;
	}
	case CHELSIO_GETREG: {
		struct ch_reg edata;

		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if ((edata.addr & 3) != 0 ||
		    edata.addr >= cxgb4_common_resource_size(adapter, 0))
			return -EINVAL;
		edata.val = t4_read_reg(adapter, edata.addr);
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_I2C_DATA: {
		struct ch_i2c_data edata;
		u8 *i2c_data;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if (!edata.len)
			return -EINVAL;

		i2c_data = t4_alloc_mem(edata.len);
		if (!i2c_data)
			return -ENOMEM;

		ret = t4_i2c_rd(adapter, adapter->mbox,
				(edata.port == ~0 ? -1 : edata.port),
				edata.devid, edata.offset, edata.len,
				i2c_data);
		if (!ret)
			if (copy_to_user(useraddr + sizeof edata,
					 i2c_data, edata.len))
				ret = -EFAULT;

		t4_free_mem(i2c_data);
		break;
	}
	case CHELSIO_SET_I2C_DATA: {
		struct ch_i2c_data edata;
		u8 *i2c_data;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if (!edata.len)
			return -EINVAL;

		i2c_data = t4_alloc_mem(edata.len);
		if (!i2c_data)
			return -ENOMEM;

		if (copy_from_user(i2c_data, useraddr + sizeof edata,
				   edata.len))
			ret = -EFAULT;
		else
			ret = t4_i2c_wr(adapter, adapter->mbox,
					(edata.port == ~0 ? -1 : edata.port),
					edata.devid, edata.offset, edata.len,
					i2c_data);

		t4_free_mem(i2c_data);
		break;
	}
	case CHELSIO_GET_TCB: {
		struct ch_tcb edesc;
		
		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&edesc, useraddr, sizeof(edesc)))
			return -EFAULT;
		if (edesc.tcb_index >= (adapter->tidinfo.tids.start +
					adapter->tidinfo.tids.size))
			return -ERANGE;

		spin_lock(&adapter->win0_lock);
		ret = t4_read_tcb(adapter, MEMWIN_NIC, edesc.tcb_index,
				  edesc.tcb_data);
		spin_unlock(&adapter->win0_lock);
		if (ret)
			return ret;

		if (copy_to_user(useraddr, &edesc, sizeof(edesc)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_SGE_CTXT: {
		u32 buf[SGE_CTXT_SIZE_T7 / 4];
		u8 size = SGE_CTXT_SIZE;
		struct ch_mem_range t;

		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.len < SGE_CTXT_SIZE || t.addr > M_CTXTQID)
			return -EINVAL;
		if (CHELSIO_CHIP_VERSION(adapter->params.chip) >= CHELSIO_T7) {
			if (t.len < SGE_CTXT_SIZE_T7)
				return -EINVAL;
			size = SGE_CTXT_SIZE_T7;
		}

		if (t.mem_id == CNTXT_TYPE_RSP || t.mem_id == CNTXT_TYPE_CQ)
			ret = CTXT_INGRESS;
		else if (t.mem_id == CNTXT_TYPE_EGRESS)
			ret = CTXT_EGRESS;
		else if (t.mem_id == CNTXT_TYPE_FL)
			ret = CTXT_FLM;
		else if (t.mem_id == CNTXT_TYPE_CONG)
			ret = CTXT_CNM;
		else
			return -EINVAL;

		if ((adapter->flags & FW_OK) && !adapter->use_bd)
			ret = t4_sge_ctxt_rd(adapter, adapter->mbox, t.addr,
					     ret, buf);
		else
			ret = t4_sge_ctxt_rd_bd(adapter, t.addr, ret, buf);
		if (ret)
			return ret;

		t.version = mk_adap_vers(adapter);
		if (copy_to_user(useraddr + sizeof(t), buf, size) ||
		    copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_SGE_DESC2: {
		unsigned char buf[128];
		struct ch_mem_range edesc;

		if (copy_from_user(&edesc, useraddr, sizeof(edesc)))
			return -EFAULT;
		/*
		 * Upper 8 bits of mem_id is the queue type, the rest the qid.
		 */
		ret = cxgb4_cxgbtool_get_qdesc(&adapter->sge,
					       edesc.mem_id >> 24,
					       edesc.mem_id & 0xffffff,
					       edesc.addr, buf);
		if (ret < 0)
			return ret;
		if (edesc.len < ret)
			return -EINVAL;

		edesc.len = ret;
		edesc.version = mk_adap_vers(adapter);
		if (copy_to_user(useraddr + sizeof(edesc), buf, edesc.len) ||
		    copy_to_user(useraddr, &edesc, sizeof(edesc)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_FEC: {
		const struct port_info *pi = netdev_priv(dev);
		const struct link_config *lc = &pi->link_cfg;
		struct ch_fec_config t;

		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		/*
		 * Translate the Firmware FEC Support into the cxgbtool
		 * enum value.  We always support IEEE 802.3 "automatic"
		 * selection of Link FEC type if any FEC is supported.
		 */
		t.supported_fec = fw_to_cx_fec(lc->pcaps);
		if (t.supported_fec != FEC_TYPE_OFF)
			t.supported_fec |= FEC_TYPE_AUTO;

		/*
		 * Translate the current internal FEC parameters into the
		 * cxgbtool enum values.
		 */
		t.auto_fec      = fwcap_to_cx_fec(lc->def_acaps);
		t.requested_fec = cc_to_cx_fec(lc->admin_fec);
		t.actual_fec    = cc_to_cx_fec(lc->fec);

		if (copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;
		break;
	}
	case CHELSIO_SET_FEC: {
		struct port_info *pi = netdev_priv(dev);
		struct link_config *lc = &pi->link_cfg;
		struct link_config old_lc;
		struct ch_fec_config t;

		/*
		 * There are a large number of ways we can fail even before
		 * trying to do an L1 Configure ...
		 */
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		if (t.requested_fec & ~FEC_TYPE_MASK)
			return -EINVAL;

		/* "auto" and "off" must be supplied solo */
		if (((t.requested_fec & FEC_TYPE_AUTO) &&
		     (t.requested_fec & ~FEC_TYPE_AUTO)) ||
		    ((t.requested_fec & FEC_TYPE_OFF) &&
		     (t.requested_fec & ~FEC_TYPE_OFF)))
			return -EINVAL;

		/*
		 * Save old Link Configuration in case the L1 Configure below
		 * fails.
		 */
		old_lc = *lc;

		/*
		 * Try to perform the L1 Configure and return the result of
		 * that effort.  If it fails, revert the attempted change.
		 */
		lc->requested_fec = cx_to_cc_fec(t.requested_fec);
		ret = t4_link_l1cfg(pi->adapter, pi->adapter->mbox,
				    pi->lport, lc);
		if (ret)
			*lc = old_lc;
		else
			lc->admin_fec = cx_to_cc_fec(t.requested_fec);

		return ret;
	}
	case CHELSIO_SET_QSET_PARAMS: {
		const struct port_info *pi = netdev_priv(dev);
		struct ch_qset_params t;
		struct sge_eth_rxq *rq;
		struct sge_eth_txq *tq;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.qset_idx >= pi->nqsets)
			return -EINVAL;
		if (t.txq_size[1] >= 0 || t.txq_size[2] >= 0 ||
		    t.fl_size[1] >= 0 || t.cong_thres >= 0 || t.polling >= 0)
			return -EINVAL;
		if (//!cxgb4_in_range(t.intr_lat, 0, M_NEWTIMER) ||
		    //!cxgb4_in_range(t.cong_thres, 0, 255) ||
		    !cxgb4_in_range(t.txq_size[0], MIN_TXQ_ENTRIES,
				    MAX_TXQ_ENTRIES) ||
		    !cxgb4_in_range(t.fl_size[0], MIN_FL_ENTRIES,
				    MAX_RX_BUFFERS) ||
		    !cxgb4_in_range(t.rspq_size, MIN_RSPQ_ENTRIES,
				    MAX_RSPQ_ENTRIES))
			return -EINVAL;

		if (t.lro > 0)
			return -EINVAL;

		if (t.cong_mode &&
		    CHELSIO_CHIP_VERSION(adapter->params.chip) < CHELSIO_T5) {
			dev_err(adapter->pdev_dev,
				"Setting Congestion mode not supported in < T5");
			return -EINVAL;
		}

		if ((adapter->flags & FULL_INIT_DONE) &&
		    (t.rspq_size >= 0 || t.fl_size[0] >= 0 ||
		     t.txq_size[0] >= 0))
			return -EBUSY;

		tq = &adapter->sge.ethtxq[t.qset_idx + pi->first_qset];
		rq = &adapter->sge.ethrxq[t.qset_idx + pi->first_qset];

		if (t.cong_mode >= 0) {
			switch (t.cong_mode) {
			case CH_QSET_CONG_MODE_NONE:
				rq->rspq.cong_mode =
					X_CONMCTXT_CNGTPMODE_DISABLE;
				break;
			case CH_QSET_CONG_MODE_QUEUE:
				rq->rspq.cong_mode = X_CONMCTXT_CNGTPMODE_QUEUE;
				break;
			case CH_QSET_CONG_MODE_CHANNEL:
				rq->rspq.cong_mode =
					X_CONMCTXT_CNGTPMODE_CHANNEL;
				break;
			case CH_QSET_CONG_MODE_QUEUE_AND_CHANNEL:
				rq->rspq.cong_mode = X_CONMCTXT_CNGTPMODE_BOTH;
				break;
			default:
				dev_err(adapter->pdev_dev,
					"Congestion mode %u not supported\n",
					t.cong_mode);
				return -EOPNOTSUPP;
			}

			if (rq->rspq.cntxt_id) {
				int cong = t4_get_tp_ch_map(adapter, pi->lport);

				ret = t4_sge_set_conm_context(adapter,
							      &rq->rspq,
							      cong);
				if (ret)
					return ret;
			}
		}

		if (t.rspq_size >= 0)
			rq->rspq.size = t.rspq_size;
		if (t.fl_size[0] >= 0)
			rq->fl.size = t.fl_size[0] + 8; /* need an empty desc */
		if (t.txq_size[0] >= 0)
			tq->q.size = t.txq_size[0];
		if (t.intr_lat >= 0) {
			int timer = cxgb4_closest_timer(&adapter->sge,
							t.intr_lat);

			rq->rspq.intr_params =
				(rq->rspq.intr_params &
				 ~V_QINTR_TIMER_IDX(M_QINTR_TIMER_IDX)) |
				V_QINTR_TIMER_IDX(timer);
		}
		break;
	}
	case CHELSIO_GET_QSET_PARAMS: {
		struct sge_eth_rxq *rq;
		struct sge_eth_txq *tq;
		struct ch_qset_params t;
		const struct port_info *pi = netdev_priv(dev);

		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.qset_idx >= pi->nqsets)
			return -EINVAL;

		tq = &adapter->sge.ethtxq[t.qset_idx + pi->first_qset];
		rq = &adapter->sge.ethrxq[t.qset_idx + pi->first_qset];
		t.rspq_size   = rq->rspq.size;
		t.txq_size[0] = tq->q.size;
		t.txq_size[1] = 0;
		t.txq_size[2] = 0;
		t.fl_size[0]  = rq->fl.size - 8; /* sub unused descriptor */
		t.fl_size[1]  = 0;
		t.polling     = 1;
		t.lro         = ((dev->features & NETIF_F_GRO) != 0);
		t.intr_lat    = rspq_intr_timer(s, &rq->rspq);
		t.cong_thres  = 0;

		switch (rq->rspq.cong_mode) {
		case X_CONMCTXT_CNGTPMODE_DISABLE:
			t.cong_mode = CH_QSET_CONG_MODE_NONE;
			break;
		case X_CONMCTXT_CNGTPMODE_QUEUE:
			t.cong_mode = CH_QSET_CONG_MODE_QUEUE;
			break;
		case X_CONMCTXT_CNGTPMODE_CHANNEL:
			t.cong_mode = CH_QSET_CONG_MODE_CHANNEL;
			break;
		case X_CONMCTXT_CNGTPMODE_BOTH:
			t.cong_mode = CH_QSET_CONG_MODE_QUEUE_AND_CHANNEL;
			break;
		default:
			t.cong_mode = -1;
			break;
		}

		if (adapter->flags & USING_INTR_MULTI)
			t.vector = adapter->msix_info[pi->first_qset +
						      t.qset_idx + 2].vec;
		else
			t.vector = adapter->msix_info[0].vec;

		if (copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;
		break;
	}
	case CHELSIO_SET_QUEUE_INTR_PARAMS: {
		struct ch_queue_intr_params op;
		struct sge_rspq *rq;
		unsigned int cur_us, cur_cnt;
		unsigned int new_us, new_cnt;
		struct sge *s = &adapter->sge;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&op, useraddr, sizeof(op)))
			return -EFAULT;
		if (op.qid < s->ingr_start ||
		    op.qid >= s->ingr_start + s->ingr_sz)
			return -EINVAL;
		rq = s->ingr_map[op.qid - s->ingr_start];
		if (rq == NULL)
			return -EINVAL;

		cur_us = rspq_intr_timer(s, rq);
		cur_cnt = rspq_intr_pktcnt(s, rq);

		new_us = op.timer >= 0 ? op.timer : cur_us;
		new_cnt  = op.count >= 0 ? op.count : cur_cnt;
		ret = cxgb4_set_rspq_intr_params(rq, new_us, new_cnt);

		break;

	}
	case CHELSIO_GET_QUEUE_INTR_PARAMS: {
		struct ch_queue_intr_params op;
		struct sge_rspq *rq;
		struct sge *s = &adapter->sge;

		if (copy_from_user(&op, useraddr, sizeof(op)))
			return -EFAULT;
		if (op.qid < s->ingr_start ||
		    op.qid >= s->ingr_start + s->ingr_sz)
			return -EINVAL;
		rq = s->ingr_map[op.qid - s->ingr_start];
		if (rq == NULL)
			return -EINVAL;

		op.timer = rspq_intr_timer(s, rq);
		op.count = rspq_intr_pktcnt(s, rq);
		if (copy_to_user(useraddr, &op, sizeof(op)))
			return -EFAULT;

		break;
	}
#ifndef CONFIG_CXGB4_DCB
	/*
	 * Not allowed to change the number of Ethernet Queue Sets if we're
	 * configured for Data Center Bridging.
	 */
	case CHELSIO_SET_QSET_NUM: {
		struct ch_reg edata;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (adapter->flags & FULL_INIT_DONE)
			return -EBUSY;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;

		return set_eth_qsets(dev, edata.val);
	}
#endif /* !CONFIG_CXGB4_DCB */
	case CHELSIO_GET_QSET_NUM: {
		struct ch_reg edata;
		struct port_info *pi = netdev_priv(dev);

		edata.cmd = CHELSIO_GET_QSET_NUM;
		edata.val = pi->nqsets;
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		break;
	}
	/* Allow to configure the various Queue Types */
	case CHELSIO_SET_QTYPE_NUM: {
		struct ch_qtype_num edata;
		uint16_t qtype_max[QTYPE_MAX]  = {
			[QTYPE_OFLD]  = MAX_OFLD_QSETS,
			[QTYPE_RCIQ]  = MAX_RDMA_CIQS,
			[QTYPE_ISCSI] = MAX_ISCSI_QUEUES,
			[QTYPE_ISCSIT] = MAX_ISCSIT_QUEUES,
			[QTYPE_NVMEH] = MAX_NVMEH_QUEUES,
			[QTYPE_NVMET] = MAX_NVMET_QUEUES,
			[QTYPE_CSTOR_CIQ] = MAX_CSTOR_CIQS,
			[QTYPE_CRYPTO] = MAX_CRYPTO_QUEUES,
		};
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		struct sge *s = &adapter->sge;
		uint16_t *ofld_qval[QTYPE_MAX] = {
			[QTYPE_OFLD]  = &s->ofldqsets,
			[QTYPE_RDMA]  = &s->rdmaqs,
			[QTYPE_RCIQ]  = &s->rdmaciqs,
			[QTYPE_ISCSI] = &s->niscsiq,
			[QTYPE_ISCSIT] = &s->niscsitq,
			[QTYPE_NVMEH] = &s->n_nvmehq,
			[QTYPE_NVMET] = &s->n_nvmetq,
			[QTYPE_CSTOR] = &s->ncstorq,
			[QTYPE_CSTOR_CIQ] = &s->ncstorciq,
			[QTYPE_CRYPTO] = &s->ncryptoq,
		};
		static const enum cxgb4_uld_type qtype_uld[QTYPE_MAX] = {
			[QTYPE_OFLD] = CXGB4_ULD_TYPE_TOE,
			[QTYPE_RDMA] = CXGB4_ULD_TYPE_RDMA,
			[QTYPE_RCIQ] = CXGB4_ULD_TYPE_RDMA,
			[QTYPE_ISCSI] = CXGB4_ULD_TYPE_ISCSI,
			[QTYPE_ISCSIT] = CXGB4_ULD_TYPE_ISCSIT,
			[QTYPE_NVMEH] = CXGB4_ULD_TYPE_NVME_TCP_HOST,
			[QTYPE_NVMET] = CXGB4_ULD_TYPE_NVME_TCP_TARGET,
			[QTYPE_CSTOR] = CXGB4_ULD_TYPE_CSTOR,
			[QTYPE_CSTOR_CIQ] = CXGB4_ULD_TYPE_CSTOR,
			[QTYPE_CRYPTO] = CXGB4_ULD_TYPE_CRYPTO,
		};
		int qpp, nqueues, other_queues, qtype;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

		/* RDMA Queues are limited to one per port */
		qtype_max[QTYPE_RDMA] = adapter->params.nports;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (adapter->flags & FULL_INIT_DONE)
			return -EBUSY;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;

		/* Sanity chedk for reasonalbe values */
		if (edata.val == 0 || edata.qtype >= QTYPE_MAX)
			return -EINVAL;

		/*
		 * Ethernet Queue Sets have their own rules.  We just like
		 * providing a single API entrance point to allow any type
		 * of queue to be managed ...
		 */
		if (edata.qtype == QTYPE_ETH)
			return set_eth_qsets(dev, edata.val);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		if (cxgb4_uld_is_registered(adapter, qtype_uld[edata.qtype])) {
			netdev_err(dev,
				   "ULD %s is already registered. Can't change number of queues\n",
				   cxgb4_uld_type_to_name(qtype_uld[edata.qtype]));
			return -EBUSY;
		}

		/*
		 * For Offload Ingress Queues, the code assumes that we have
		 * exactly the same number for all ports, so we need to round
		 * the requested value up to a multiple of the number of
		 * ports.  It doesn't really make sense to have more per port
		 * than the number of CPUs, so we silently limit the number of
		 * Offload Queues/Port to nCPUs.
		 */
		qpp = edata.val;
		if (qpp > num_online_cpus())
			qpp = num_online_cpus();
		nqueues = qpp * adapter->params.nports;
		if (nqueues > qtype_max[edata.qtype])
			return -ERANGE;

		for (qtype = 0, other_queues = 0; qtype < QTYPE_MAX; qtype++)
			if (qtype != edata.qtype && qtype != QTYPE_ETH)
				other_queues += *ofld_qval[qtype];

		if (nqueues + other_queues > s->max_ofldqsets)
			return -EINVAL;

		*ofld_qval[edata.qtype] = nqueues;
		return 0;
#else
		netdev_err(dev, "ULD support not compiled-in\n");
		return -EOPNOTSUPP;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	}
	case CHELSIO_GET_QTYPE_NUM: {
		struct port_info *pi = netdev_priv(dev);
		struct sge *s = &adapter->sge;
		struct ch_qtype_num edata;
		uint16_t *ofld_qval[QTYPE_MAX] = {
			[QTYPE_ETH]   = &s->ethqsets,
			[QTYPE_OFLD]  = &s->ofldqsets,
			[QTYPE_RDMA]  = &s->rdmaqs,
			[QTYPE_RCIQ]  = &s->rdmaciqs,
			[QTYPE_ISCSI] = &s->niscsiq,
			[QTYPE_ISCSIT] = &s->niscsitq,
			[QTYPE_NVMEH] = &s->n_nvmehq,
			[QTYPE_NVMET] = &s->n_nvmetq,
			[QTYPE_CSTOR] = &s->ncstorq,
			[QTYPE_CSTOR_CIQ] = &s->ncstorciq,
			[QTYPE_CRYPTO] = &s->ncryptoq,
		};
		int nports = adapter->params.nports;

		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if (edata.qtype >= QTYPE_MAX)
			return -EINVAL;
		if (edata.qtype == QTYPE_ETH)
			edata.val = pi->nqsets;
		else
			edata.val = *ofld_qval[edata.qtype]/nports;
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		break;
	}
#ifdef CXGB4_DEBUG
	/*
	 * This is an incredibly dangerous ioctl().  It allows an arbitrary
	 * Work Request to be sent on an arbitrary TOE TX or Control Queue.
	 * You'll probably crash the adapter if you use it, maybe even the
	 * system.  Firestorms and Rains of Toads are possibilities.  Really,
	 * don't use it.
	 */
	case CHELSIO_SEND_WORKREQ: {
		bool is_offload_queue = false;
		bool is_control_queue = false;
		struct sge_ctrl_txq *ctrl_txq;
		struct sge *s = &adapter->sge;
		struct ch_workreq edata;
		struct sk_buff *skb;
		void *egr_queue;
		u8 uld, port;
		int egr_qid;
		int txq_idx;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		struct cxgb4_uld_txq *txq;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EBUSY;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;

		/*
		 * Get a pointer to the Egress Queue associated with the Queue
		 * ID.
		 */
		egr_qid = edata.qid;
		if (egr_qid < 0)
			return -EINVAL;
		egr_queue = cxgb4_sge_egr_map_get(&s->egr_map, egr_qid);
		if (egr_queue == NULL)
			return -EINVAL;

		/*
		 * Figure out what kind of Egress Queue it is -- we only allow
		 * Offload TX and Control TX.
		 */
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		for_each_port(adapter, port) {
			struct net_device *dev = adapter->port[port];

			for (uld = 0; uld < CXGB4_ULD_TYPE_MAX; uld++) {
				txq = cxgb4_uld_txq_get_by_qid(dev, uld,
							       egr_qid);
				if (!txq)
					continue;

				is_offload_queue = true;
				txq_idx = txq->ofldtxq->q.cntxt_id;
				break;
			}

			if (is_offload_queue)
				break;
		}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
		is_control_queue =
			(egr_queue >= (void *)&s->ctrlq[0] &&
			 egr_queue < (void *)&s->ctrlq[MAX_CTRL_QUEUES]);
		if (!is_offload_queue && !is_control_queue)
			return -EINVAL;

		if (is_control_queue) {
			ctrl_txq = egr_queue;
			if (ctrl_txq->q.cntxt_id != edata.qid)
				return -ENXIO;
			txq_idx = ctrl_txq - &s->ctrlq[0];
		}

		/*
		 * Perform only the most brutally minimal checking on the CPL
		 * message itself ...
		 */
		if (edata.len == 0 || edata.len > MAX_WORKREQ)
			return -EINVAL;

		/*
		 * Allocate a new network buffer and copy the CPL Message data
		 * into it.
		 */
		skb = alloc_skb(edata.len, GFP_KERNEL);
		if (skb == NULL)
			return -ENOMEM;
		skb_put(skb, edata.len);
		skb_copy_to_linear_data(skb, edata.workreq, edata.len);

		/*
		 * Indicate which TX Queue needs to be used.
		 */
		set_wr_txq(skb, is_control_queue, txq_idx);

		/*
		 * And start the actual dammage ...
		 */
		return cxgb4_uld_xmit(dev, skb);

		break;
	}
#endif /* CXGB4_DEBUG */
	case CHELSIO_LOAD_FW: {
		u8 *fw_data;
		struct ch_mem_range t;
		unsigned int mbox = M_PCIE_FW_MASTER + 1;
		u32 pcie_fw;
		unsigned int master;
		u8 master_vld = 0;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (!t.len)
			return -EINVAL;

		pcie_fw = t4_read_reg(adapter, A_PCIE_FW);
		master = G_PCIE_FW_MASTER(pcie_fw);
		if (pcie_fw & F_PCIE_FW_MASTER_VLD)
			master_vld = 1;
		/* if csiostor is the master return */
		if (master_vld && (master != adapter->pf)) {
			dev_warn(adapter->pdev_dev,
				 "cxgb4 driver needs to be loaded as MASTER to support FW flash\n");
			return -EOPNOTSUPP;
		}

		fw_data = t4_alloc_mem(t.len);
		if (!fw_data)
			return -ENOMEM;

		if (copy_from_user(fw_data, useraddr + sizeof(t), t.len)) {
			t4_free_mem(fw_data);
			return -EFAULT;
		}

		/*
		 * If the adapter has been fully initialized then we'll go
		 * ahead and try to get the firmware's cooperation in
		 * upgrading to the new firmware image otherwise we'll try to
		 * do the entire job from the host ... and we always "force"
		 * the operation in this path.
		 */
		if ((adapter->flags & FULL_INIT_DONE) && fw_attach)
			mbox = adapter->mbox;

		ret = t4_fw_upgrade(adapter, mbox,
				    fw_data, t.len, /*force=*/true);
		t4_free_mem(fw_data);
		if (ret)
			return ret;
		break;
	}
#ifdef CHELSIO_T4_DIAGS
	case CHELSIO_CLEAR_FLASH: {
		ret = t4_erase_sf(adapter);

		if (ret)
			return ret;
		break;
	}
	case CHELSIO_DIAG_MEMTEST: {
		struct ch_diag_memtest p;
		u8 op, status = 0;
		u32 duration;
		u16 size;

		if (copy_from_user(&p, useraddr, sizeof(p)))
			return -EFAULT;

		switch (p.op) {
		case CH_DIAG_MEMTEST_OP_START:
			op = FW_DIAG_CMD_MEMDIAG_TEST_START;
			break;
		case CH_DIAG_MEMTEST_OP_STOP:
			op = FW_DIAG_CMD_MEMDIAG_TEST_STOP;
			break;
		case CH_DIAG_MEMTEST_OP_STATUS:
			op = FW_DIAG_CMD_MEMDIAG_TEST_STATUS;
			break;
		default:
			return -EOPNOTSUPP;
		}

		size = p.size;
		duration = p.duration;
		ret = t4_diag_memtest(adapter, op, &duration, &size, &status);
		if (ret)
			return ret;

		memset(&p, 0, sizeof(p));
		p.op = op;
		p.size = size;
		p.duration = duration;

		switch (status) {
		case FW_DIAG_CMD_MEMDIAG_STATUS_NONE:
			p.status = CH_DIAG_MEMTEST_STATUS_IDLE;
			break;
		case FW_DIAG_CMD_MEMDIAG_STATUS_RUNNING:
			p.status = CH_DIAG_MEMTEST_STATUS_RUNNING;
			break;
		case FW_DIAG_CMD_MEMDIAG_STATUS_FAILED:
			p.status = CH_DIAG_MEMTEST_STATUS_FAILED;
			break;
		case FW_DIAG_CMD_MEMDIAG_STATUS_PASSED:
			p.status = CH_DIAG_MEMTEST_STATUS_PASSED;
			break;
		default:
			break;
		}

		if (copy_to_user(useraddr, &p, sizeof(p)))
			return -EFAULT;

		break;
	}
#endif
	case CHELSIO_LOAD_BOOT: {
		u8 *boot_data;
		struct ch_mem_range t;
		unsigned int pcie_pf_exprom_ofst, offset;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		/*
		 * Check if user selected a valid PF index or offset
		 * mem_id:	type of access 0: PF index, 1: offset
		 * addr: 	pf index or offset
		 */
		if (t.mem_id == 0) {
			/*
			 * Flash boot image to the offset defined by the PFs
			 * EXPROM_OFST defined in the serial configuration file.
			 * Read PCIE_PF_EXPROM_OFST register
		 	 */

			/*
			 * Check PF index
			 */
			if (t.addr > 7 || t.addr < 0) {
				CH_ERR(adapter, "PF index is too small/large\n");
				return EFAULT;
			}

			pcie_pf_exprom_ofst = t4_read_reg(adapter,
					PF_REG(t.addr, A_PCIE_PF_EXPROM_OFST));
			offset = G_OFFSET(pcie_pf_exprom_ofst);

		} else if (t.mem_id == 1) {
			/*
			 * Flash boot image to offset specified by the user.
			 */
			offset = G_OFFSET(t.addr);

		} else
			return -EINVAL;

		/*
		 * If a length of 0 is supplied that implies the desire to
		 * clear the FLASH area associated with the option ROM
		 */
		if (t.len == 0)
			ret = t4_load_boot(adapter, NULL, offset, 0);
		else {
			boot_data = t4_alloc_mem(t.len);
			if (!boot_data)
				return -ENOMEM;

			if (copy_from_user(boot_data, useraddr + sizeof(t),
						t.len)) {
				t4_free_mem(boot_data);
				return -EFAULT;
			}

			ret = t4_load_boot(adapter, boot_data, offset, t.len);
			t4_free_mem(boot_data);
		}
		if (ret)
			return ret;
		break;
	}

	case CHELSIO_LOAD_BOOTCFG: {
		u8 *cfg_data;
		struct struct_load_cfg t;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		if (t.len == 0)
			ret = t4_load_bootcfg(adapter, NULL, 0);
		else {
			cfg_data = t4_alloc_mem(t.len);
			if (!cfg_data)
				return -ENOMEM;

			if (copy_from_user(cfg_data, useraddr + sizeof(t), t.len)) {
				t4_free_mem(cfg_data);
				return -EFAULT;
			}
			ret = t4_load_bootcfg(adapter, cfg_data, t.len);
			t4_free_mem(cfg_data);
		}	

		if (ret)
			return ret;
		break;
	}

	case CHELSIO_READ_BOOTCFG: {
		struct struct_load_cfg t = {};
		u8 *cfg_data;
		int len;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		if (!t.len)
			return -EINVAL;

		/* length must be a multiple of 4 */
		len = (t.len + 4 - 1) & ~3;

		cfg_data = t4_alloc_mem(len);
		if (!cfg_data)
			return -ENOMEM;

		t.nports = adapter->params.nports; 
		ret = t4_read_bootcfg(adapter, cfg_data, len);
		if (!ret) {
			if (copy_to_user(useraddr, &t, sizeof(t)))
				ret = -EFAULT;
			if (copy_to_user(useraddr + sizeof(t), cfg_data, t.len))
				ret = -EFAULT;
		}
		t4_free_mem(cfg_data);
		break;
	}

        case CHELSIO_LOAD_CFG: {
                u8 *cfg_data;
		struct struct_load_cfg t;
		

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
                if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		/*
		 * If a length of 0 is supplied that implies the desire to
		 * clear the FLASH area associated with the Firmware
		 * Configuration File.
		 */
		if (t.len == 0)
			ret = t4_load_cfg(adapter, NULL, 0);
		else {
			cfg_data = t4_alloc_mem(t.len);
			if (!cfg_data)
				return -ENOMEM;

			if (copy_from_user(cfg_data, useraddr + sizeof(t), t.len)) {
				t4_free_mem(cfg_data);
				return -EFAULT;
			}
			ret = t4_load_cfg(adapter, cfg_data, t.len);
			t4_free_mem(cfg_data);
		}
		if (ret)
			return ret;
		break;
        }
#ifdef CHELSIO_T4_DIAGS
	case CHELSIO_LOAD_PHY_FW: {
		u8 *phy_data;
		struct ch_mem_range t;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		phy_data = t4_alloc_mem(t.len);
		if (!phy_data)
			return -ENOMEM;

		if (copy_from_user(phy_data, useraddr + sizeof(t), t.len)) {
			t4_free_mem(phy_data);
			return -EFAULT;
		}

		/*
		 * Execute loading of PHY firmware.  We have to RESET the
		 * chip/firmware because we need the chip in uninitialized
		 * state for loading new PHY firmware.
		 */
		ret = t4_fw_reset(adapter, adapter->mbox,
				  F_PIORSTMODE | F_PIORST);
		if (!ret)
			ret = t4_load_phy_fw(adapter, MEMWIN_NIC, &adapter->win0_lock,
					     NULL, phy_data, t.len);
		t4_free_mem(phy_data);
		if (ret)
			return ret;
		break;
	}
#endif /* CHELSIO_T4_DIAGS */
	case CHELSIO_SET_FILTER: {
		struct filter_ctx ctx;
		struct ch_filter t;
		u32 fid;

		/*
		 * Vet the filter specification against our hardware filter
		 * configuration and capabilities.
		 */

		if (!allow_nonroot_ioctl && !capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!cxgb4_filter_num_tids(adapter))
			return -EOPNOTSUPP;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;  /* can still change nfilters */
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.filter_ver != CH_FILTER_SPECIFICATION_ID)
			return -EINVAL;

		/* Filter ID from cxgbtool is only 28 bits. So, user
		 * can't send a full CXGB4_FILTER_ID_ANY. We manually
		 * set it here.
		 */
		fid = t.filter_id;
		if (fid == (CXGB4_FILTER_ID_ANY & 0x0fffffff))
			fid = CXGB4_FILTER_ID_ANY;

		if (!t.fs.cap) {
			if (fid != CXGB4_FILTER_ID_ANY)
				fid = cxgb4_cxgbtool_filter_id_to_ftid(adapter,
								       fid,
								       &t.fs);

			ret = cxgb4_filter_create(dev, fid, &t.fs, NULL,
						  GFP_KERNEL);
			if (ret < 0)
				return ret;

			t.filter_id = cxgb4_cxgbtool_ftid_to_filter_id(adapter,
								       ret,
								       &t.fs);
			return copy_to_user(useraddr, &t, sizeof(t));
		}

		init_completion(&ctx.completion);
		ret = cxgb4_filter_create(dev, fid, &t.fs, &ctx, GFP_KERNEL);
		if (!ret) {
			ret = wait_for_completion_timeout(&ctx.completion,
							  10 * HZ);
			if (!ret) {
				dev_err(adapter->pdev_dev,
					"%s: filter creation timed out\n",
					__func__);
				return ret;
			}

			ret = ctx.result;
			t.filter_id = ctx.tid;

			if (copy_to_user(useraddr, &t, sizeof(t)))
				return -EFAULT;
		}
		break;
	}
	case CHELSIO_DEL_FILTER: {
		struct filter_ctx ctx;
		struct ch_filter t;
		u32 fid;

		if (!allow_nonroot_ioctl && !capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!cxgb4_filter_num_tids(adapter))
			return -EOPNOTSUPP;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;  /* can still change nfilters */
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.filter_ver != CH_FILTER_SPECIFICATION_ID)
			return -EINVAL;
		if (!t.fs.cap) {
			fid = cxgb4_cxgbtool_filter_id_to_ftid(adapter,
							       t.filter_id,
							       &t.fs);
			return cxgb4_filter_delete(dev, fid, &t.fs, NULL,
						   GFP_KERNEL);
		}

		init_completion(&ctx.completion);
		ret = cxgb4_filter_delete(dev, t.filter_id, &t.fs, &ctx,
					  GFP_KERNEL);
		if (!ret) {
			ret = wait_for_completion_timeout(&ctx.completion,
							  10 * HZ);
			if (!ret) {
				dev_err(adapter->pdev_dev,
					"%s: filter deletion timed out\n",
					__func__);
				return ret;
			}

			return ctx.result;
		}
		break;
	}
	case CHELSIO_GET_FILTER: {
		struct filter_entry *f = NULL;
		struct ch_filter t;
		u32 fid;

		if (!allow_nonroot_ioctl && !capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!cxgb4_filter_num_tids(adapter))
			return -EOPNOTSUPP;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;  /* can still change nfilters */
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.filter_ver != CH_FILTER_SPECIFICATION_ID)
			return -EINVAL;

		fid = cxgb4_cxgbtool_filter_id_to_ftid(adapter, t.filter_id,
						       &t.fs);
		if (!cxgb4_hpftid_out_of_range(adapter, fid) ||
		    !cxgb4_ftid_out_of_range(adapter, fid))
			f = cxgb4_ftid_lookup(adapter, fid);
		else if (!cxgb4_hashtid_out_of_range(adapter, t.filter_id))
			f = cxgb4_hashtid_lookup(adapter, t.filter_id);
		if (!f)
			return -ENOENT;

		if (f->pending)
			return -EBUSY;
		if (!f->valid)
			return -ENOENT;

		t.fs = f->fs;
		if (copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_FILTER_COUNT: {
		struct ch_filter_count count;

		if (copy_from_user(&count, useraddr, sizeof(count)))
			return -EFAULT;
		if (!cxgb4_filter_num_tids(adapter))
			return -EOPNOTSUPP;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;  /* can still change nfilters */

		ret = cxgb4_filter_get_count(adapter, count.filter_id,
					     &count.pkt_count, 0, false);
		if (ret < 0)
			return ret;

		if (copy_to_user(useraddr, &count, sizeof(count)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_FREE_FILTER_ID: {
		struct ch_filter_id t;

		if (!allow_nonroot_ioctl && !capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!cxgb4_filter_num_tids(adapter))
			return -EOPNOTSUPP;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;  /* can still change nfilters */
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		t.filter_id = CXGB4_FILTER_ID_ANY & 0x0fffffff;
		if (copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_BYPASS_PORTS: {
		struct ch_bypass_ports cbp;

		if (!is_bypass(adapter))
			return -EINVAL;

		get_bypass_ports(adapter, &cbp);

		if (copy_to_user(useraddr, &cbp, sizeof(cbp)))
			return -EFAULT;
		break;
	}
	case CHELSIO_CLEAR_STATS: {
		struct ch_reg edata;
		struct port_info *pi = netdev_priv(dev);

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if ((edata.val & STATS_QUEUE) && edata.addr != -1 &&
		    edata.addr >= pi->nqsets)
			return -EINVAL;
		if (edata.val & STATS_PORT) {
			/*
			 * T4 can't reliably clear its statistics registers
			 * while traffic is running, so we just snapshot the
			 * statistics registers and then subtract off this
			 * Base Offset for future statistics reports ...
			 */
			if (is_t4(adapter->params.chip))
				t4_get_port_stats(adapter, pi->lport,
						  &pi->stats_base);
			else
				t4_clr_port_stats(adapter, pi->lport);
			clear_sge_port_stats(adapter, pi);

			/*
			 * For T5 and later we also want to clear out any SGE
			 * statistics which may be being gathered ...
			 */
			if (!is_t4(adapter->params.chip)) {
				u32 cfg = t4_read_reg(adapter, A_SGE_STAT_CFG);
				t4_write_reg(adapter, A_SGE_STAT_CFG, 0);
				t4_write_reg(adapter, A_SGE_STAT_CFG, cfg);
			}

			/*
			 * Snapshot new base for various statistics registers
			 * which are either difficult or impossible to clear
			 * while the adapter/traffic is running ...
			 */
			cxgb4_cxgbtool_tp_get_cpl_stats(adapter, pi);
			cxgb4_cxgbtool_tp_get_err_stats(adapter, pi);
			t4_get_fcoe_stats(adapter, pi->port_id,
					  &pi->fcoe_stats_base, true);
			t4_get_lb_stats(adapter, pi->port_id, &pi->lb_port_stats_base);
		}
		if (edata.val & STATS_QUEUE) {
			if (edata.addr == -1)
				clear_port_qstats(adapter, pi);
			else
				clear_ethq_stats(&adapter->sge,
						 pi->first_qset + edata.addr);
		}
		break;
	}
#if 0
	case CHELSIO_DEVUP:
		if (!is_offload(adapter))
			return -EOPNOTSUPP;
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return activate_offload(&adapter->tdev);
#endif
	case CHELSIO_GET_SCHED_CLASS: {
		struct ch_sched_params p;
		int level, mode, type, rateunit;
		int minrate, maxrate, weight, pktsize, burstsize;
		const int fw_to_ch_type[] = {
			[FW_SCHED_TYPE_PKTSCHED] = SCHED_CLASS_TYPE_PACKET,
			[FW_SCHED_TYPE_STREAMSCHED] = SCHED_CLASS_TYPE_STREAM,
		};
		const int fw_to_ch_level[] = {
			[FW_SCHED_PARAMS_LEVEL_CL_RL] = SCHED_CLASS_LEVEL_CL_RL,
			[FW_SCHED_PARAMS_LEVEL_CL_WRR] = SCHED_CLASS_LEVEL_CL_WRR,
			[FW_SCHED_PARAMS_LEVEL_CH_RL] = SCHED_CLASS_LEVEL_CH_RL,
			/* [FW_SCHED_PARAMS_LEVEL_CH_WRR] doesn't exist ... */
		};
		const int fw_to_ch_mode[] = {
			[FW_SCHED_PARAMS_MODE_CLASS] = SCHED_CLASS_MODE_CLASS,
			[FW_SCHED_PARAMS_MODE_FLOW] = SCHED_CLASS_MODE_FLOW,
		};
		const int fw_to_ch_rateunit[] = {
			[FW_SCHED_PARAMS_UNIT_BITRATE] = SCHED_CLASS_RATEUNIT_BITS,
			[FW_SCHED_PARAMS_UNIT_PKTRATE] = SCHED_CLASS_RATEUNIT_PKTS,
		};

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!adapter->flags & FULL_INIT_DONE)
			return -EAGAIN;        /* uP and SGE must be running */
		if (copy_from_user(&p, useraddr, sizeof(p)))
			return -EFAULT;
		if (!cxgb4_in_range(p.u.params.channel, 0,
				    adapter->params.arch.nchan - 1) ||
		    !cxgb4_in_range(p.u.params.class, 0,
				    adapter->params.nsched_cls - 1))
			return -EINVAL;

		/* channel value must not be less than 0 */
		if (p.u.params.channel < 0)
			return -EINVAL;
		/* Reset the value of class  to 0 if it is less than 0 */ 
		if (p.u.params.class < 0)
			p.u.params.class = 0;

		if (p.subcmd != SCHED_CLASS_SUBCMD_CONFIG &&
		    p.subcmd != SCHED_CLASS_SUBCMD_PARAMS)
			return -EINVAL;
		if (p.subcmd != SCHED_CLASS_SUBCMD_PARAMS)
			return -ENOTSUPP;

		ret = t4_read_sched_params(adapter,
					   p.u.params.channel, p.u.params.class,
					   &level, &mode, &type,
					   &rateunit, &minrate,
					   &maxrate, &weight,
					   &pktsize, &burstsize);
		if (ret) {
			dev_err(adapter->pdev_dev,
				"Scheduler params read failed, err %d\n", ret);
			return ret;
		}

		p.type = fw_to_ch_type[type];
		p.u.params.level = fw_to_ch_level[level];
		p.u.params.mode = fw_to_ch_mode[mode];
		p.u.params.rateunit = fw_to_ch_rateunit[rateunit];
		p.u.params.minrate = minrate;
		p.u.params.maxrate = maxrate;
		p.u.params.weight = weight;
		p.u.params.pktsize = pktsize;
		p.u.params.burstsize = burstsize;

		if (copy_to_user(useraddr, &p, sizeof(p)))
			return -EFAULT;

		break;
	}
	case CHELSIO_SET_SCHED_CLASS: {
		struct ch_sched_params p;
		int fw_subcmd, fw_type;
		ret = -EINVAL;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!adapter->flags & FULL_INIT_DONE)
			return -EAGAIN;        /* uP and SGE must be running */
		if (copy_from_user(&p, useraddr, sizeof(p)))
			return -EFAULT;

		/*
		 * Translate the cxgbtool parameters into T4 firmware
		 * parameters.  (The sub-command and type are in common
		 * locations.)
		 */
		if (p.subcmd == SCHED_CLASS_SUBCMD_CONFIG)
			fw_subcmd = FW_SCHED_SC_CONFIG;
		else if (p.subcmd == SCHED_CLASS_SUBCMD_PARAMS)
			fw_subcmd = FW_SCHED_SC_PARAMS;
		else
			return -EINVAL;
		if (p.type == SCHED_CLASS_TYPE_PACKET)
			fw_type = FW_SCHED_TYPE_PKTSCHED;
		else if (p.type == SCHED_CLASS_TYPE_STREAM)
			fw_type = FW_SCHED_TYPE_STREAMSCHED;
		else
			return -EINVAL;

		if (fw_subcmd == FW_SCHED_SC_CONFIG) {
			/*
			 * Vet our parameters ...
			 */
			if (p.u.config.minmax < 0)
				return -EINVAL;

			/*
			 * The Min/Max Mode can only be enabled _before_ the
			 * FW_INITIALIZE_CMD is issued and there's no real way
			 * to do that in this driver's architecture ...
			 */
			if (p.u.config.minmax)
				return -EINVAL;

			/*
			 * And pass the request to the firmware ...
			 */
			return t4_sched_config(adapter,
					       fw_type,
					       p.u.config.minmax);
		}

		if (fw_subcmd == FW_SCHED_SC_PARAMS) {
			int fw_level;
			int fw_mode;
			int fw_rateunit;
			int fw_ratemode;

			if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL)
				fw_level = FW_SCHED_PARAMS_LEVEL_CL_RL;
			else if (p.u.params.level == SCHED_CLASS_LEVEL_CL_WRR)
				fw_level = FW_SCHED_PARAMS_LEVEL_CL_WRR;
			else if (p.u.params.level == SCHED_CLASS_LEVEL_CH_RL)
				fw_level = FW_SCHED_PARAMS_LEVEL_CH_RL;
			else
				return -EINVAL;

			if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL) {
				if (p.u.params.mode == SCHED_CLASS_MODE_CLASS)
					fw_mode = FW_SCHED_PARAMS_MODE_CLASS;
				else if (p.u.params.mode == SCHED_CLASS_MODE_FLOW)
					fw_mode = FW_SCHED_PARAMS_MODE_FLOW;
				else
					return -EINVAL;
			} else
				fw_mode = 0;

			if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
			    p.u.params.level == SCHED_CLASS_LEVEL_CH_RL) {
				if (p.u.params.rateunit == SCHED_CLASS_RATEUNIT_BITS)
					fw_rateunit = FW_SCHED_PARAMS_UNIT_BITRATE;
				else if (p.u.params.rateunit == SCHED_CLASS_RATEUNIT_PKTS)
					fw_rateunit = FW_SCHED_PARAMS_UNIT_PKTRATE;
				else
					return -EINVAL;
			} else
				fw_rateunit = 0;

			if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
			    p.u.params.level == SCHED_CLASS_LEVEL_CH_RL) {
				if (p.u.params.ratemode == SCHED_CLASS_RATEMODE_REL)
					fw_ratemode = FW_SCHED_PARAMS_RATE_REL;
				else if (p.u.params.ratemode == SCHED_CLASS_RATEMODE_ABS)
					fw_ratemode = FW_SCHED_PARAMS_RATE_ABS;
				else
					return -EINVAL;
			} else
				fw_ratemode = 0;

			/*
			 * Vet our parameters ...
			 */
			if (!cxgb4_in_range(p.u.params.channel, 0,
					    adapter->params.arch.nchan - 1) ||
			    ((p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
			      p.u.params.level == SCHED_CLASS_LEVEL_CL_WRR) &&
			      !cxgb4_in_range(p.u.params.class, 0,
					      adapter->params.nsched_cls-1)) ||
			    ((p.u.params.ratemode == SCHED_CLASS_RATEMODE_ABS ||
			      p.u.params.ratemode == SCHED_CLASS_RATEMODE_REL) &&
			     (!cxgb4_in_range(p.u.params.minrate, 0, 100000000) ||
			      !cxgb4_in_range(p.u.params.maxrate, 1, 100000000))) ||
			    !cxgb4_in_range(p.u.params.weight, 0, 100))
				return -ERANGE;
			if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL &&
			    (p.u.params.minrate > p.u.params.maxrate))
				return -EINVAL;

			/*
			 * Translate any unset parameters into the firmware's
			 * nomenclature and/or fail the call if the parameters
			 * are required ...
			 */
			if (p.u.params.channel < 0)
				return -EINVAL;
			if (p.u.params.rateunit < 0 || p.u.params.ratemode < 0) {
				if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
				    p.u.params.level == SCHED_CLASS_LEVEL_CH_RL)
					return -EINVAL;
				else {
					p.u.params.rateunit = 0;
					p.u.params.ratemode = 0;
				}
			}
			if (p.u.params.class < 0) {
				if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
				    p.u.params.level == SCHED_CLASS_LEVEL_CL_WRR)
					return -EINVAL;
				else
					p.u.params.class = 0;
			}
			if (p.u.params.minrate < 0)
				p.u.params.minrate = 0;
			if (p.u.params.maxrate < 0) {
				if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
				    p.u.params.level == SCHED_CLASS_LEVEL_CH_RL)
					return -EINVAL;
				else
					p.u.params.maxrate = 0;
			}
			if (p.u.params.weight < 0) {
				if (p.u.params.level == SCHED_CLASS_LEVEL_CL_WRR)
					return -EINVAL;
				else
					p.u.params.weight = 0;
			}
			if (p.u.params.pktsize < 0) {
				if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL)
					return -EINVAL;
				else
					p.u.params.pktsize = 0;
			}
			/* burst size can be either not set (value < 0) or
			 * with in the range 'pktsize < burstsize < MAX_BURST_SIZE'
			 */
			if (p.u.params.burstsize < 0)
				p.u.params.burstsize = 0;
			else if (p.u.params.mode != SCHED_CLASS_MODE_FLOW)
				return -EINVAL;
			else if (!cxgb4_in_range(p.u.params.burstsize,
						 p.u.params.pktsize + 1,
						 MAX_BURST_SIZE))
				return -ERANGE;

			/*
			 * See what the firmware thinks of the request ...
			 */
			return t4_sched_params(adapter,
					       p.u.params.channel,
					       p.u.params.class,
					       fw_level,
					       fw_mode,
					       fw_type,
					       fw_rateunit,
					       fw_ratemode,
					       p.u.params.minrate,
					       p.u.params.maxrate,
					       p.u.params.weight,
					       p.u.params.pktsize,
					       p.u.params.burstsize);
		}

		return -EINVAL;
	}
	case CHELSIO_SET_SCHED_QUEUE: {
		struct ch_sched_queue p;
		struct port_info *pi = netdev_priv(dev);
		struct sge_eth_txq *txq;
		u32 fw_mnem, fw_queue, fw_class;
		int err, q;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!adapter->flags & FULL_INIT_DONE)
			return -EAGAIN;        /* uP and SGE must be running */
		if (copy_from_user(&p, useraddr, sizeof(p)))
			return -EFAULT;

		if (!cxgb4_in_range(p.queue, 0, pi->nqsets - 1) ||
		    !cxgb4_in_range(p.class, 0,
				    adapter->params.nsched_cls - 1))
			return -EINVAL;

		/*
		 * Create a template for the FW_PARAMS_CMD mnemonic and
		 * value (TX Scheduling Class in this case).
		 */
		fw_mnem = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
			   V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_EQ_SCHEDCLASS_ETH));
		fw_class = p.class < 0 ? 0xffffffff : p.class;

		/*
		 * If op.queue is non-negative, then we're only changing the
		 * scheduling on a single specified TX queue.
		 */
		if (p.queue >= 0) {
			txq = &adapter->sge.ethtxq[pi->first_qset + p.queue];
			fw_queue = (fw_mnem |
				    V_FW_PARAMS_PARAM_YZ(txq->q.cntxt_id));
			err = t4_set_params(adapter, adapter->mbox,
					    adapter->pf, 0, 1,
					    &fw_queue, &fw_class);
			return err;
		}

		/*
		 * Change the scheduling on all the TX queues for the
		 * interface.
		 */
		txq = &adapter->sge.ethtxq[pi->first_qset];
		for (q = 0; q < pi->nqsets; q++, txq++) {
			fw_queue = (fw_mnem |
				    V_FW_PARAMS_PARAM_YZ(txq->q.cntxt_id));
			err = t4_set_params(adapter, adapter->mbox,
					    adapter->pf, 0, 1,
					    &fw_queue, &fw_class);
			if (err)
				return err;
		}

		return 0;
	}
	case CHELSIO_SET_SCHED_PFVF: {
		struct ch_sched_pfvf p;
		u32 fw_pfvf, fw_class;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!adapter->flags & FULL_INIT_DONE)
			return -EAGAIN;        /* uP and SGE must be running */
		if (copy_from_user(&p, useraddr, sizeof(p)))
			return -EFAULT;
		if (!cxgb4_in_range(p.class, 0, adapter->params.nsched_cls - 1))
			return -EINVAL;

		fw_pfvf = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) |
			   V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_SCHEDCLASS_ETH));
		fw_class = p.class < 0 ? 0xffffffff : p.class;
		return t4_set_params(adapter, adapter->mbox,
				     p.pf, p.vf, 1,
				     &fw_pfvf, &fw_class);
	}
	case CHELSIO_SET_MPS: {
		struct port_info *pi = netdev_priv(dev);
		struct ch_mps p;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!adapter->flags & FULL_INIT_DONE)
			return -EAGAIN;        /* uP and SGE must be running */
		if (copy_from_user(&p, useraddr, sizeof(p)))
			return -EFAULT;

		return t4_alloc_raw_mac_filt(adapter, pi->viid,
					    p.mac, p.mac_mask, p.idx,
					    p.lookup_type, pi->port_id, true);
	}
#ifdef CONFIG_CUDBG
	case CHELSIO_GET_CUDBG_LOG:
		ret = cxgb4_cudbg_ioctl(adapter, useraddr);
		break;
#endif
	case CHELSIO_GET_MPS_TRACE_FILTER: {
		ret = cxgb4_cxgbtool_get_mps_trace_filter(dev, useraddr);
		break;
	}
	case CHELSIO_SET_MPS_TRACE_FILTER: {
		ret = cxgb4_cxgbtool_set_mps_trace_filter(dev, useraddr);
		break;
	}
	case CHELSIO_LOAD_UBOOT: {
		struct ch_mem_range t;
		u8 *uboot_data;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		/* If a length of 0 is supplied that implies the desire to
		 * clear the FLASH area associated with the U-Boot Binary.
		 */
		if (t.len == 0)
			return t4_load_uboot(adapter, NULL, 0);

		uboot_data = t4_alloc_mem(t.len);
		if (!uboot_data)
			return -ENOMEM;

		if (copy_from_user(uboot_data, useraddr + sizeof(t), t.len)) {
			t4_free_mem(uboot_data);
			return -EFAULT;
		}

		ret = t4_load_uboot(adapter, uboot_data, t.len);
		t4_free_mem(uboot_data);

		if (ret)
			return ret;
		break;
	}
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	case CHELSIO_SET_OFLD_POLICY: {
		struct ch_mem_range t;
		struct ofld_policy_file *opf;
		struct cxgb4_uld_info *toe_uld = &cxgb4_ulds[CXGB4_ULD_TYPE_TOE];
		void *toe_handle = adapter->uld_handle[CXGB4_ULD_TYPE_TOE];

		if (!test_bit(OFFLOAD_DEVMAP_BIT,
			      &adapter->registered_device_map))
			return -EOPNOTSUPP;
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (!toe_uld->control || !TOEDEV(dev))
			return -EOPNOTSUPP;

		/* len == 0 removes any existing policy */
		if (t.len == 0) {
			toe_uld->control(toe_handle,
					 CXGB4_CONTROL_SET_OFFLOAD_POLICY,
					 NULL, 0);
			break;
		}

		opf = t4_alloc_mem(t.len);
		if (!opf)
			return -ENOMEM;

		if (copy_from_user(opf, useraddr + sizeof(t), t.len)) {
			t4_free_mem(opf);
			return -EFAULT;
		}

		ret = validate_offload_policy(dev, opf, t.len);
		if (!ret)
			ret = validate_policy_settings(dev, adapter, opf);
		if (!ret)
			ret = toe_uld->control(toe_handle,
					       CXGB4_CONTROL_SET_OFFLOAD_POLICY,
					       opf, t.len);
		t4_free_mem(opf);
		return ret;
	}
#endif
	default:
		return -EOPNOTSUPP;
	}
	return ret;
}

