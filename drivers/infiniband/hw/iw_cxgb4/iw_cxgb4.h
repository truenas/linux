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
#ifndef __IW_CXGB4_H__
#define __IW_CXGB4_H__
#include <linux/kconfig.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/inet.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/timer.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/time.h>
#include <linux/workqueue.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <asm/byteorder.h>

#include <net/net_namespace.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/iw_cm.h>
#include <rdma/restrack.h>

#include "l2t.h"
#include "t4_msg.h"
#include "cxgb4_ctl_defs.h"
#include "cxgb4_rdma_resource.h"
#include "user.h"

#define DRV_NAME "iw_cxgb4"
#define MOD DRV_NAME ":"

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "t4.h"

#define PBL_OFF(rdev_p, a) ((a) - (rdev_p)->lldi.vr->pbl.start)
#define RQT_OFF(rdev_p, a) ((a) - (rdev_p)->lldi.vr->rq.start)

static inline void *cplhdr(struct sk_buff *skb)
{
	return skb->data;
}

#define T6_MAX_PAGE_SIZE 0x8000000

#define ESP_HDR_LEN 16

struct chrd_resource {
	struct cxgb4_id_table tpt_table;
};

enum chrd_rdev_flags {
	T4_FATAL_ERROR = (1<<0),
	T4_STATUS_PAGE_DISABLED = (1<<1),
};

struct chrd_stats {
	struct mutex lock;
	struct cxgb4_rdma_stat stag;
	struct cxgb4_rdma_stat pbl;
	struct cxgb4_rdma_stat rrqt;
	struct cxgb4_rdma_stat ocqp;
	u64  db_full;
	u64  db_empty;
	u64  db_drop;
	u64  db_state_transitions;
	u64  db_fc_interruptions;
	u64  tcam_full;
	u64  act_ofld_conn_fails;
	u64  pas_ofld_conn_fails;
	u64  neg_adv;
};

struct chrd_hw_queue {
	int t4_eq_status_entries;
	int t4_max_eq_size;
	int t4_max_iq_size;
	int t4_max_rq_size;
	int t4_max_sq_size;
	int t4_max_qp_depth;
	int t4_max_cq_depth;
	int t4_stat_len;
};

struct wr_log_entry {
	ktime_t post_host_time;
	ktime_t poll_host_time;
	u64 post_sge_ts;
	u64 cqe_sge_ts;
	u64 poll_sge_ts;
	u16 qid;
	u16 wr_id;
	u8 opcode;
	u8 valid;
};

struct chrd_rdev {
	struct chrd_resource resource;
	struct cxgb4_rdma_resource *rdma_res;
	struct cxgb4_dev_ucontext uctx;
	struct gen_pool *rrqt_pool;
	struct gen_pool *pbl_pool;
	struct gen_pool *ocqp_pool;
	u32 flags;
	struct cxgb4_lld_info lldi;
	unsigned long bar2_pa;
	void __iomem *bar2_kva;
	unsigned long oc_mw_pa;
	void __iomem *oc_mw_kva;
	unsigned long *fids;
	int nfids;
	struct chrd_stats stats;
	struct chrd_hw_queue hw_queue;
	struct t4_dev_status_page *status_page;
	dma_addr_t daddr;
	atomic_t wr_log_idx;
	struct wr_log_entry *wr_log;
	int wr_log_size;
	u8 gsi_qp_inuse;
	struct chrd_qp *gsi_qp;
	struct chrd_cq *gsi_scq;
	struct chrd_cq *gsi_rcq;
	struct list_head blocker_list;
	struct mutex blocker_lock;
	struct list_head ep_glist;
	struct mutex ep_glist_lock;
	struct workqueue_struct *free_workq;
	struct completion rrqt_compl;
	struct completion rqt_compl;
	struct completion pbl_compl;
	struct kref rrqt_kref;
	struct kref rqt_kref;
	struct kref pbl_kref;
};

static inline int chrd_onchip_pa(struct chrd_rdev *rdev, u64 pa)
{
	return pa >= rdev->oc_mw_pa &&
	       pa < rdev->oc_mw_pa + rdev->lldi.vr->ocq.size;
}

struct t4_fl_sw_desc {
	void *buf;
	dma_addr_t dma_addr;
};

static inline int chrd_fatal_error(struct chrd_rdev *rdev)
{
	return rdev->flags & T4_FATAL_ERROR;
}

static inline int chrd_num_stags(struct chrd_rdev *rdev)
{
	return (int)(rdev->lldi.vr->stag.size >> 5);
}

static inline int t4_max_fr_depth(struct chrd_rdev *rdev, bool use_dsgl)
{
	if (rdev->lldi.ulptx_memwrite_dsgl && use_dsgl)
		return rdev->lldi.dev_512sgl_mr ? T4_MAX_FR_FW_DSGL_DEPTH : T4_MAX_FR_DSGL_DEPTH;
	else
		return T4_MAX_FR_IMMD_DEPTH;
}

#define CHRD_WR_TO (60*HZ)

struct chrd_wr_wait {
	struct completion completion;
	int ret;
	struct kref kref;
	struct list_head blist_entry;
};

void _chrd_free_wr_wait(struct kref *kref);

static inline void chrd_put_wr_wait(struct chrd_wr_wait *wr_waitp)
{
	pr_debug("wr_wait %p ref before put %u\n", wr_waitp,
		 kref_read(&wr_waitp->kref));
	WARN_ON(kref_read(&wr_waitp->kref) == 0);
	kref_put(&wr_waitp->kref, _chrd_free_wr_wait);
}

static inline void chrd_get_wr_wait(struct chrd_wr_wait *wr_waitp)
{
	pr_debug("wr_wait %p ref before get %u\n", wr_waitp,
		 kref_read(&wr_waitp->kref));
	WARN_ON(kref_read(&wr_waitp->kref) == 0);
	kref_get(&wr_waitp->kref);
}

static inline void chrd_init_wr_wait(struct chrd_wr_wait *wr_waitp)
{
	wr_waitp->ret = 0;
	init_completion(&wr_waitp->completion);
	INIT_LIST_HEAD(&wr_waitp->blist_entry);
}

static inline void _chrd_wake_up(struct chrd_wr_wait *wr_waitp, int ret,
				 bool deref)
{
	wr_waitp->ret = ret;
	complete(&wr_waitp->completion);
	if (deref)
		chrd_put_wr_wait(wr_waitp);
}

static inline void chrd_wake_up_noref(struct chrd_wr_wait *wr_waitp, int ret)
{
	_chrd_wake_up(wr_waitp, ret, false);
}

static inline void chrd_wake_up_deref(struct chrd_wr_wait *wr_waitp, int ret)
{
	_chrd_wake_up(wr_waitp, ret, true);
}

void chrd_disable_device(struct chrd_rdev *rdev, int recover);

static inline int chrd_wait(struct chrd_rdev *rdev, struct completion *c)
{
	int ret;

	if (chrd_fatal_error(rdev))
		return -EIO;

	ret = wait_for_completion_timeout(c, CHRD_WR_TO);

	/*
	 * If we timed out, then mark the device as dead and
	 * notify the LLD.  The LLD can then possibly initiate
	 * device recovery (see CXGB4_STATE_START_RECOVERY).
	 */
	if (!ret) {
		pr_err(MOD "%s: Timeout waiting for FW reply\n",
		       rdev->lldi.name);
		WARN_ON(1);
		chrd_disable_device(rdev, 0);
		cxgb4_fatal_err(rdev->lldi.ports[0]);
		return -EIO;
	}
	return 0;
}

static inline int chrd_wait_for_reply(struct chrd_rdev *rdev,
				 struct chrd_wr_wait *wr_waitp,
				 u32 hwtid, u32 qpid,
				 const char *func)
{
	int ret = 0;

	mutex_lock(&rdev->blocker_lock);
	pr_debug("add wr_waitp %p\n", wr_waitp);
	if (chrd_fatal_error(rdev))
		ret = -EIO;
	else
		list_add_tail(&wr_waitp->blist_entry, &rdev->blocker_list);
	mutex_unlock(&rdev->blocker_lock);
	if (ret) {
		wr_waitp->ret = ret;
		goto out;
	}

	ret = wait_for_completion_timeout(&wr_waitp->completion, CHRD_WR_TO);
	if (!ret) {
		pr_err("%s - Device %s not responding (disabling device) - tid %u qpid %u\n",
		       func, rdev->lldi.name, hwtid, qpid);
		rdev->flags |= T4_FATAL_ERROR;
		wr_waitp->ret = -EIO;
		goto out;
	}

	mutex_lock(&rdev->blocker_lock);
	pr_debug("delete wr_waitp %p\n", wr_waitp);
	list_del_init(&wr_waitp->blist_entry);
	mutex_unlock(&rdev->blocker_lock);

	if (wr_waitp->ret)
		pr_debug("%s: FW reply %d tid %u qpid %u\n",
			 rdev->lldi.name, wr_waitp->ret, hwtid, qpid);
out:
	return wr_waitp->ret;
}

int chrd_ofld_send(struct chrd_rdev *rdev, struct sk_buff *skb);

static inline int chrd_ref_send_wait(struct chrd_rdev *rdev,
				     struct sk_buff *skb,
				     struct chrd_wr_wait *wr_waitp,
				     u32 hwtid, u32 qpid,
				     const char *func)
{
	int ret;

	pr_debug("%s wr_wait %p hwtid %u qpid %u\n", func, wr_waitp, hwtid,
		 qpid);
	chrd_get_wr_wait(wr_waitp);
	ret = chrd_ofld_send(rdev, skb);
	if (ret) {
		chrd_put_wr_wait(wr_waitp);
		return ret;
	}
	return chrd_wait_for_reply(rdev, wr_waitp, hwtid, qpid, func);
}

enum db_state {
	NORMAL = 0,
	STOPPED = 1,
	FLOW_CONTROL = 2,
	RECOVERY = 3
};

struct chrd_dev {
	struct ib_device ibdev;
	struct chrd_rdev rdev;
	struct device_dma_parameters dma_parms;
	struct xarray cqs;
	struct xarray qps;
	struct xarray rawqps;
	struct xarray rawiqs;
	struct xarray mrs;
	spinlock_t lock;
	struct mutex db_mutex;
	struct dentry *debugfs_root;
	enum db_state db_state;
	struct xarray hwtids;
	struct xarray atids;
	struct xarray stids;
	struct xarray fids;
	struct list_head db_fc_list;
	u32 avail_ird;
	wait_queue_head_t wait;
};

struct uld_ctx {
	struct list_head entry;
	struct cxgb4_lld_info lldi;
	struct chrd_dev *dev;
	struct work_struct reg_work;
};

static inline struct chrd_dev *to_chrd_dev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct chrd_dev, ibdev);
}

static inline struct chrd_dev *rdev_to_chrd_dev(struct chrd_rdev *rdev)
{
	return container_of(rdev, struct chrd_dev, rdev);
}

static inline struct chrd_cq *get_chp(struct chrd_dev *rhp, u32 cqid)
{
	return xa_load(&rhp->cqs, cqid);
}

static inline struct chrd_qp *get_qhp(struct chrd_dev *rhp, u32 qpid)
{
	return xa_load(&rhp->qps, qpid);
}

static inline struct chrd_cq *fidx2cq(struct chrd_dev *rhp, u32 fidx)
{
	return xa_load(&rhp->fids, fidx);
}

extern uint chrd_max_read_depth;

static inline int cur_max_read_depth(struct chrd_dev *dev)
{
	return min(dev->rdev.lldi.max_ordird_qp, chrd_max_read_depth);
}

struct dst_entry *find_route6(struct chrd_dev *dev, __u8 *local_ip,
			      __u8 *peer_ip, __be16 local_port,
			      __be16 peer_port, u8 tos,
			      __u32 sin6_scope_id);
struct dst_entry *find_route(struct chrd_dev *dev, __be32 local_ip,
			     __be32 peer_ip, __be16 local_port,
			     __be16 peer_port, u8 tos);

struct chrd_xfrm_info {
	bool ipsec_en;
	bool ipsec_mode;
	bool ipv6;
	u16 ipsecidx;
	u32 local_ip_addr[4];
	u32 dest_ip_addr[4];
};

struct chrd_pd {
	struct ib_pd ibpd;
	u32 pdid;
	struct chrd_dev *rhp;
};

static inline struct chrd_pd *to_chrd_pd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct chrd_pd, ibpd);
}

struct tpt_attributes {
	u64 len;
	u64 va_fbo;
	enum fw_ri_mem_perms perms;
	u32 stag;
	u32 pdid;
	u32 qpid;
	u32 pbl_addr;
	u32 pbl_size;
	u32 state:1;
	u32 type:2;
	u32 rsvd:1;
	u32 remote_invaliate_disable:1;
	u32 zbva:1;
	u32 mw_bind_enable:1;
	u32 page_size:5;
};

struct chrd_mr {
	struct ib_mr ibmr;
	struct ib_umem *umem;
	struct chrd_dev *rhp;
	struct sk_buff *dereg_skb;
	u64 kva;
	struct tpt_attributes attr;
	u64 *mpl;
	dma_addr_t mpl_addr;
	u32 max_mpl_len;
	u32 mpl_len;
	struct chrd_wr_wait *wr_waitp;
#ifdef HAVE_PEER_MEM_SUPPORT
	atomic_t invalidated;
	struct completion invalidation_comp;
	struct mutex live_lock;
	int live;
#endif
};

static inline struct chrd_mr *to_chrd_mr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct chrd_mr, ibmr);
}

struct chrd_mw {
	struct ib_mw ibmw;
	struct chrd_dev *rhp;
	struct sk_buff *dereg_skb;
	u64 kva;
	struct tpt_attributes attr;
	struct chrd_wr_wait *wr_waitp;
#ifdef HAVE_PEER_MEM_SUPPORT
	atomic_t invalidated;
	struct completion invalidation_comp;
	struct mutex live_lock;
	int live;
#endif
};

static inline struct chrd_mw *to_chrd_mw(struct ib_mw *ibmw)
{
	return container_of(ibmw, struct chrd_mw, ibmw);
}

struct chrd_cq {
	struct ib_cq ibcq;
	struct chrd_dev *rhp;
	struct sk_buff *destroy_skb;
	struct t4_cq cq;
	u8 gsi_cq;
	spinlock_t lock;
	spinlock_t comp_handler_lock;
	atomic_t refcnt;
	wait_queue_head_t wait;
	struct chrd_wr_wait *wr_waitp;
};

static inline struct chrd_cq *to_chrd_cq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct chrd_cq, ibcq);
}

struct chrd_mpa_attributes {
	u8 initiator;
	u8 recv_marker_enabled;
	u8 xmit_marker_enabled;
	u8 crc_enabled;
	u8 enhanced_rdma_conn;
	u8 version;
	u8 p2p_type;
};

struct chrd_common_qp_attributes {
	u32 scq;
	u32 rcq;
	u32 sq_num_entries;
	u32 rq_num_entries;
	u32 sq_max_sges;
	u32 sq_max_sges_rdma_write;
	u32 rq_max_sges;
	u32 state;
	u8 enable_rdma_read;
	u8 enable_rdma_write;
	u8 enable_bind;
	u8 enable_mmid0_fastreg;
	u32 max_ord;
	u32 max_ird;
	u32 pd;
	u32 next_state;
	char terminate_buffer[52];
	u32 terminate_msg_len;
	u8 is_terminate_local;
	struct chrd_mpa_attributes mpa_attr;
	struct chrd_ep *llp_stream_handle;
	u16 sq_db_inc;
	u16 rq_db_inc;
	u8 layer_etype;
	u8 ecode;
	u8 send_term;
};

#define CHRD_ROCE_PSN_MASK 0xFFFFFF
#define CHRD_ROCE_PORT 4791
union chrd_roce_sockaddr {
	struct sockaddr_in saddr_in;
	struct sockaddr_in6 saddr_in6;
};

struct chrd_ah {
	struct ib_ah ibah;
	struct rdma_ah_attr attr;
	struct sk_buff *ah_skb;
	struct chrd_dev *rhp;
	struct chrd_pd *php;
	struct chrd_wr_wait *wr_waitp;

	/* AV */
	union chrd_roce_sockaddr sgid_addr;
	union chrd_roce_sockaddr dgid_addr;
	union ib_gid dgid;
	bool ipv4:1;
	bool insert_vlan_tag:1;
	u8 smac[ETH_ALEN];
	u8 dmac[ETH_ALEN];
	u16 src_port;
	u16 dst_port;
	u32 local_ip_addr[4];
	u32 dest_ip_addr[4];
	u32 flowlabel;
	u16 p_key;
	u32 dest_qp;
	u8 gid_index;
	u8 stat_rate;
	u8 hop_limit;
	u8 net_type;
	u16 vlan_id;
	u8 vlan_en;
	u8 tclass;
	u8 port;
	u8 sl;

	/* HW queues */
	u16 ctrlq_idx;
	u16 rss_qid;
	u16 txq_idx;

	/* add id for each ah */
	int ah_id;

	/* For route resolution */
	struct l2t_entry *l2t;
	struct dst_entry *dst;

	/* For ipsec xfrm state */
	struct chrd_xfrm_info xfrm;
#if 0
// Bhar: enable these when needed
	struct chrd_qp *qp;
	struct sk_buff_head ah_skb_list;
	enum chrd_ep_state state;
	struct kref kref;
	struct mutex mutex;
	struct chrd_wr_wait *wr_waitp;
	unsigned long flags;
	unsigned long history;
	struct list_head glist_entry;

	struct list_head entry;
	u32 snd_seq;
	u32 rcv_seq;
	struct l2t_entry *l2t;
	struct dst_entry *dst;
	u32 ird;
	u32 ord;
	u32 smac_idx;
	u32 tx_chan;
	u32 mtu;
	u16 mss;
	u16 emss;
	u16 plen;
	unsigned int retry_count;
	int snd_win;
	int rcv_win;
	u32 snd_wscale;
	u32 srqe_idx;
	u32 rx_pdu_out_cnt;
#endif
};

struct chrd_gsi_attr {
	u8 ttl;
	u8 tos;
	u32 snd_mss;
	u16 vlan_tag;
	u16 arp_idx;
	u32 flow_label;
	u8 udp_state;
	u32 psn_nxt;
	u32 lsn;
	u32 epsn;
	u32 psn_max;
	u32 psn_una;
	u32 cwnd;
	u8 rexmit_thresh;
	u8 rnr_nak_thresh;
};

struct chrd_roce_qp_attributes {
	u32 q_key;
	u16 err_rq_idx;
	u8 roce_tver;
	u8 ack_credits;
	u8 err_rq_idx_valid;
	u32 pd_id;
	u16 ord_size;
	u16 ird_size;
	u32 hwtid;
	u32 atid;
	u32 gsi_ftid;
	struct chrd_ah roce_ah;
	struct chrd_gsi_attr gsi_attr;
};

enum obj_type {
	UNKNOWN,
	RC_QP,
	RAW_QP,
	RAW_SRQ,
	BASIC_SRQ,
};

struct db_fcl {
	struct list_head db_fc_entry;
	enum obj_type type;
};

enum qp_transport_type {
	CHRD_TRANSPORT_IWARP,
	CHRD_TRANSPORT_ROCEV2,
};
enum chrd_qp_history {
	ROCE_ACT_OPEN_REQ,
	ROCE_ACT_OPEN_RPL,
	ROCE_QP_REFED,
	ROCE_QP_DEREFED,
	ROCE_RDMA_INIT,
	ROCE_RDMA_FINI
};

struct chrd_qp {
	struct ib_qp ibqp;
	struct db_fcl fcl;
	struct chrd_dev *rhp;
	struct net_device *netdev;
	struct chrd_ep *ep;
	struct chrd_common_qp_attributes attr;
	struct t4_wq wq;
	spinlock_t lock;
	struct mutex mutex;
	enum ib_qp_type qp_type;
	enum qp_transport_type qp_trans;
	int sq_sig_all;
	int mtu;
	u16 txq_id;
	struct chrd_srq *srq;
	struct ch_filter gsi_filt;
	struct chrd_roce_qp_attributes roce_attr;
	struct chrd_ucontext *ucontext;
	wait_queue_head_t wait;
	struct chrd_wr_wait *wr_waitp;
	struct completion qp_rel_comp;
	unsigned long history;
	refcount_t qp_refcnt;
};

static inline void chrd_copy_ip_ntohl(u32 *dst, __be32 *src)
{
	*dst++ = ntohl(*src++);
	*dst++ = ntohl(*src++);
	*dst++ = ntohl(*src++);
	*dst = ntohl(*src);
}

static inline struct chrd_qp *to_chrd_qp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct chrd_qp, ibqp);
}

static inline struct chrd_qp *fcl_to_chrd_qp(struct db_fcl *fcl)
{
	return container_of(fcl, struct chrd_qp, fcl);
}

struct chrd_raw_qp {
	struct ib_qp ibqp;
	struct db_fcl fcl;
	struct chrd_dev *rhp;
	struct net_device *netdev;
	struct chrd_cq *scq;
	struct chrd_cq *rcq;
	struct t4_iq iq;
	struct t4_fl fl;
	struct t4_eth_txq txq;
	int txq_idx;
	u32 state;
	struct mutex mutex;
	atomic_t refcnt;
	wait_queue_head_t wait;
	u16 vlan_pri;
	int fid;
	int nfids;
};

static inline struct chrd_raw_qp *to_chrd_raw_qp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct chrd_raw_qp, ibqp);
}

static inline struct chrd_raw_qp *fcl_to_chrd_raw_qp(struct db_fcl *fcl)
{
	return container_of(fcl, struct chrd_raw_qp, fcl);
}

struct chrd_raw_srq {
	struct ib_srq ibsrq;
	struct db_fcl fcl;
	struct chrd_dev *dev;
	struct net_device *netdev;
	struct t4_iq iq;
	struct t4_fl fl;
};

struct chrd_srq {
	struct ib_srq ibsrq;
	struct db_fcl fcl;
	struct chrd_dev *rhp;
	struct t4_srq wq;
	struct sk_buff *destroy_skb;
	u32 srq_limit;
	u32 pdid;
	int idx;
	__u32 flags;
	spinlock_t lock;
	bool armed;
	struct chrd_wr_wait *wr_waitp;
};

static inline struct chrd_srq *to_chrd_srq(struct ib_srq *ibsrq)
{
	return container_of(ibsrq, struct chrd_srq, ibsrq);
}

static inline struct chrd_raw_srq *to_chrd_raw_srq(struct ib_srq *ibsrq)
{
	return container_of(ibsrq, struct chrd_raw_srq, ibsrq);
}

static inline struct chrd_raw_srq *fcl_to_chrd_raw_srq(struct db_fcl *fcl)
{
	return container_of(fcl, struct chrd_raw_srq, fcl);
}

struct chrd_ucontext {
	struct ib_ucontext ibucontext;
	struct cxgb4_dev_ucontext uctx;
	u32 key;
	spinlock_t mmap_lock;
	struct list_head mmaps;
};

static inline struct chrd_ucontext *to_chrd_ucontext(struct ib_ucontext *c)
{
	return container_of(c, struct chrd_ucontext, ibucontext);
}

struct chrd_mm_entry {
	struct list_head entry;
	u64 addr;
	u32 key;
	void *vaddr;
	dma_addr_t dma_addr;
	unsigned len;
};

static inline struct chrd_mm_entry *remove_mmap(struct chrd_ucontext *ucontext,
						u32 key, unsigned len)
{
	struct list_head *pos, *nxt;
	struct chrd_mm_entry *mm;

	spin_lock(&ucontext->mmap_lock);
	list_for_each_safe(pos, nxt, &ucontext->mmaps) {

		mm = list_entry(pos, struct chrd_mm_entry, entry);
		if (mm->key == key && mm->len == len) {
			list_del_init(&mm->entry);
			spin_unlock(&ucontext->mmap_lock);
			pr_debug("key 0x%x addr 0x%llx len %d\n",
				 key, (unsigned long long)mm->addr, mm->len);
			return mm;
		}
	}
	spin_unlock(&ucontext->mmap_lock);
	return NULL;
}

static inline void insert_mmap(struct chrd_ucontext *ucontext,
			       struct chrd_mm_entry *mm)
{
	spin_lock(&ucontext->mmap_lock);
	pr_debug("key 0x%x addr 0x%llx len %d\n",
		 mm->key, (unsigned long long)mm->addr, mm->len);
	list_add_tail(&mm->entry, &ucontext->mmaps);
	spin_unlock(&ucontext->mmap_lock);
}

enum chrd_qp_attr_mask {
	CHRD_QP_ATTR_NEXT_STATE = 1 << 0,
	CHRD_QP_ATTR_SQ_DB = 1<<1,
	CHRD_QP_ATTR_RQ_DB = 1<<2,
	CHRD_QP_ATTR_ENABLE_RDMA_READ = 1 << 7,
	CHRD_QP_ATTR_ENABLE_RDMA_WRITE = 1 << 8,
	CHRD_QP_ATTR_ENABLE_RDMA_BIND = 1 << 9,
	CHRD_QP_ATTR_MAX_ORD = 1 << 11,
	CHRD_QP_ATTR_MAX_IRD = 1 << 12,
	CHRD_QP_ATTR_LLP_STREAM_HANDLE = 1 << 22,
	CHRD_QP_ATTR_STREAM_MSG_BUFFER = 1 << 23,
	CHRD_QP_ATTR_MPA_ATTR = 1 << 24,
	CHRD_QP_ATTR_QP_CONTEXT_ACTIVATE = 1 << 25,
	CHRD_QP_ATTR_VALID_MODIFY = (CHRD_QP_ATTR_ENABLE_RDMA_READ |
				     CHRD_QP_ATTR_ENABLE_RDMA_WRITE |
				     CHRD_QP_ATTR_MAX_ORD |
				     CHRD_QP_ATTR_MAX_IRD |
				     CHRD_QP_ATTR_LLP_STREAM_HANDLE |
				     CHRD_QP_ATTR_STREAM_MSG_BUFFER |
				     CHRD_QP_ATTR_MPA_ATTR |
				     CHRD_QP_ATTR_QP_CONTEXT_ACTIVATE)
};

int chrd_modify_iw_rc_qp(struct chrd_qp *qhp, enum chrd_qp_attr_mask mask,
		      struct chrd_common_qp_attributes *attrs, int internal);

enum chrd_qp_state {
	CHRD_QP_STATE_IDLE,
	CHRD_QP_STATE_RTR,
	CHRD_QP_STATE_RTS,
	CHRD_QP_STATE_ERROR,
	CHRD_QP_STATE_TERMINATE,
	CHRD_QP_STATE_CLOSING,
	CHRD_QP_STATE_TOT
};

static inline int chrd_convert_state(enum ib_qp_state ib_state)
{
	switch (ib_state) {
	case IB_QPS_RESET:
	case IB_QPS_INIT:
		return CHRD_QP_STATE_IDLE;
	case IB_QPS_RTR:
		return CHRD_QP_STATE_RTR;
	case IB_QPS_RTS:
		return CHRD_QP_STATE_RTS;
	case IB_QPS_SQD:
		return CHRD_QP_STATE_CLOSING;
	case IB_QPS_SQE:
		return CHRD_QP_STATE_TERMINATE;
	case IB_QPS_ERR:
		return CHRD_QP_STATE_ERROR;
	default:
		return -1;
	}
}

static inline int to_ib_qp_state(int chrd_qp_state)
{
	switch (chrd_qp_state) {
	case CHRD_QP_STATE_IDLE:
		return IB_QPS_INIT;
	case CHRD_QP_STATE_RTR:
		return IB_QPS_RTR;
	case CHRD_QP_STATE_RTS:
		return IB_QPS_RTS;
	case CHRD_QP_STATE_CLOSING:
		return IB_QPS_SQD;
	case CHRD_QP_STATE_TERMINATE:
		return IB_QPS_SQE;
	case CHRD_QP_STATE_ERROR:
		return IB_QPS_ERR;
	}
	return IB_QPS_ERR;
}

enum chrd_v2_qp_state {
	CHRD_QP_V2_STATE_RESET,
	CHRD_QP_V2_STATE_IDLE,
	CHRD_QP_V2_STATE_RTR,
	CHRD_QP_V2_STATE_RTS,
	CHRD_QP_V2_STATE_ERROR,
	CHRD_QP_V2_STATE_TERMINATE,
	CHRD_QP_V2_STATE_CLOSING,
	CHRD_QP_V2_STATE_TOT
};

static inline int chrd_convert_v2_state(enum ib_qp_state ib_state)
{
	switch (ib_state) {
	case IB_QPS_RESET:
		return CHRD_QP_V2_STATE_RESET;
	case IB_QPS_INIT:
		return CHRD_QP_V2_STATE_IDLE;
	case IB_QPS_RTR:
		return CHRD_QP_V2_STATE_RTR;
	case IB_QPS_RTS:
		return CHRD_QP_V2_STATE_RTS;
	case IB_QPS_SQD:
		return CHRD_QP_V2_STATE_CLOSING;
	case IB_QPS_SQE:
		return CHRD_QP_V2_STATE_TERMINATE;
	case IB_QPS_ERR:
		return CHRD_QP_V2_STATE_ERROR;
	default:
		return -1;
	}
}

static inline int v2_to_ib_qp_state(int chrd_v2_qp_state)
{
	switch (chrd_v2_qp_state) {
	case CHRD_QP_V2_STATE_RESET:
		return IB_QPS_RESET;
	case CHRD_QP_V2_STATE_IDLE:
		return IB_QPS_INIT;
	case CHRD_QP_V2_STATE_RTR:
		return IB_QPS_RTR;
	case CHRD_QP_V2_STATE_RTS:
		return IB_QPS_RTS;
	case CHRD_QP_V2_STATE_CLOSING:
		return IB_QPS_SQD;
	case CHRD_QP_V2_STATE_TERMINATE:
		return IB_QPS_SQE;
	case CHRD_QP_V2_STATE_ERROR:
		return IB_QPS_ERR;
	}
	return IB_QPS_ERR;
}

enum chrd_v2_ing_cqe_opcode {
	IB_CQE_V2_OPC_SEND_FIRST,
	IB_CQE_V2_OPC_SEND_MIDDLE,
	IB_CQE_V2_OPC_SEND_LAST,
	IB_CQE_V2_OPC_SEND_LAST_WITH_IMM,
	IB_CQE_V2_OPC_SEND_ONLY,
	IB_CQE_V2_OPC_SEND_ONLY_WITH_IMM,
	IB_CQE_V2_OPC_WRITE_FIRST,
	IB_CQE_V2_OPC_WRITE_MIDDLE,
	IB_CQE_V2_OPC_WRITE_LAST,
	IB_CQE_V2_OPC_WRITE_LAST_WITH_IMM,
	IB_CQE_V2_OPC_WRITE_ONLY,
	IB_CQE_V2_OPC_WRITE_ONLY_WITH_IMM,
	IB_CQE_V2_OPC_READ_REQUEST,
	IB_CQE_V2_OPC_READ_RESPONSE_FIRST,
	IB_CQE_V2_OPC_READ_RESPONSE_MIDDLE,
	IB_CQE_V2_OPC_READ_RESPONSE_LAST,
	IB_CQE_V2_OPC_READ_RESPONSE_ONLY,
	IB_CQE_V2_OPC_ACK,
	IB_CQE_V2_OPC_SEND_LAST_WITH_INV = 0x16,
	IB_CQE_V2_OPC_SEND_ONLY_WITH_INV = 0x17,
};

static inline int v2_ib_opc_to_fw_opc(enum chrd_v2_ing_cqe_opcode opcode)
{
	switch (opcode) {
	case IB_CQE_V2_OPC_SEND_FIRST:
	case IB_CQE_V2_OPC_SEND_MIDDLE:
	case IB_CQE_V2_OPC_SEND_LAST:
	case IB_CQE_V2_OPC_SEND_ONLY:
		return FW_RI_SEND;
	case IB_CQE_V2_OPC_SEND_LAST_WITH_INV:
	case IB_CQE_V2_OPC_SEND_ONLY_WITH_INV:
		return FW_RI_SEND_WITH_INV;
#if 0 //Bhar: enable send_imm when fw enables it
	case IB_CQE_V2_OPC_SEND_LAST_WITH_IMM:
	case IB_CQE_V2_OPC_SEND_ONLY_WITH_IMM:
		return FW_RI_SEND_IMMEDIATE;
#endif
	case IB_CQE_V2_OPC_WRITE_FIRST:
	case IB_CQE_V2_OPC_WRITE_MIDDLE:
	case IB_CQE_V2_OPC_WRITE_LAST:
	case IB_CQE_V2_OPC_WRITE_ONLY:
		return FW_RI_RDMA_WRITE;
	case IB_CQE_V2_OPC_WRITE_LAST_WITH_IMM:
	case IB_CQE_V2_OPC_WRITE_ONLY_WITH_IMM:
		return FW_RI_WRITE_IMMEDIATE;
	case IB_CQE_V2_OPC_READ_REQUEST:
		return FW_RI_READ_REQ;
	case IB_CQE_V2_OPC_READ_RESPONSE_FIRST:
	case IB_CQE_V2_OPC_READ_RESPONSE_MIDDLE:
	case IB_CQE_V2_OPC_READ_RESPONSE_LAST:
	case IB_CQE_V2_OPC_READ_RESPONSE_ONLY:
		return FW_RI_READ_RESP;
	default:
		return 0x1F; //Bhar: setting opc to reserved code to deal with it in poll_cq_one()
	}
}

static inline u32 chrd_ib_to_tpt_access(int a)
{
	return (a & IB_ACCESS_REMOTE_WRITE ? FW_RI_MEM_ACCESS_REM_WRITE : 0) |
	       (a & IB_ACCESS_REMOTE_READ ? FW_RI_MEM_ACCESS_REM_READ : 0) |
	       (a & IB_ACCESS_LOCAL_WRITE ? FW_RI_MEM_ACCESS_LOCAL_WRITE : 0) |
	       FW_RI_MEM_ACCESS_LOCAL_READ;
}

static inline u32 chrd_ib_to_tpt_bind_access(int acc)
{
	return (acc & IB_ACCESS_REMOTE_WRITE ? FW_RI_MEM_ACCESS_REM_WRITE : 0) |
	       (acc & IB_ACCESS_REMOTE_READ ? FW_RI_MEM_ACCESS_REM_READ : 0);
}

enum chrd_mmid_state {
	CHRD_STAG_STATE_VALID,
	CHRD_STAG_STATE_INVALID
};

#define CHRD_NODE_DESC "cxgb4 Chelsio Communications"

#define MPA_KEY_REQ "MPA ID Req Frame"
#define MPA_KEY_REP "MPA ID Rep Frame"

#define MPA_MAX_PRIVATE_DATA	256
#define MPA_ENHANCED_RDMA_CONN	0x10
#define MPA_REJECT		0x20
#define MPA_CRC			0x40
#define MPA_MARKERS		0x80
#define MPA_FLAGS_MASK		0xE0

#define MPA_V2_PEER2PEER_MODEL		0x8000
#define MPA_V2_ZERO_LEN_FPDU_RTR	0x4000
#define MPA_V2_RDMA_WRITE_RTR           0x8000
#define MPA_V2_RDMA_READ_RTR            0x4000
#define MPA_V2_IRD_ORD_MASK             0x3FFF

#ifdef HAVE_KREF_READ
#define chrd_put_ep(ep) { \
	pr_debug("put_ep ep %p refcnt %d\n", \
		 ep, kref_read(&((ep)->kref))); \
	WARN_ON(kref_read(&((ep)->kref)) < 1); \
	kref_put(&((ep)->kref), _chrd_free_ep); \
}

#define chrd_get_ep(ep) { \
	pr_debug("get_ep ep %p, refcnt %d\n", \
		 ep, kref_read(&((ep)->kref))); \
	kref_get(&((ep)->kref));  \
}
#else
#define chrd_put_ep(ep) { \
	pr_debug("put_ep ep %p refcnt %d\n", \
		 ep, atomic_read(&((ep)->kref.refcount))); \
	WARN_ON(atomic_read(&((ep)->kref.refcount)) < 1); \
	kref_put(&((ep)->kref), _chrd_free_ep); \
}

#define chrd_get_ep(ep) { \
	pr_debug("get_ep ep %p, refcnt %d\n", \
		 ep, atomic_read(&((ep)->kref.refcount))); \
	kref_get(&((ep)->kref));  \
}
#endif
void _chrd_free_ep(struct kref *kref);
struct sk_buff *get_skb(struct sk_buff *skb, int len, gfp_t gfp);
int chrd_l2t_send(struct chrd_rdev *rdev, struct sk_buff *skb,
		  struct l2t_entry *l2t);


struct mpa_message {
	u8 key[16];
	u8 flags;
	u8 revision;
	__be16 private_data_size;
	u8 private_data[];
};

struct mpa_v2_conn_params {
	__be16 ird;
	__be16 ord;
};

struct terminate_message {
	u8 layer_etype;
	u8 ecode;
	__be16 hdrct_rsvd;
	u8 len_hdrs[0];
};

#define TERM_MAX_LENGTH (sizeof(struct terminate_message) + 2 + 18 + 28)

enum chrd_layers_types {
	LAYER_RDMAP		= 0x00,
	LAYER_DDP		= 0x10,
	LAYER_MPA		= 0x20,
	RDMAP_LOCAL_CATA	= 0x00,
	RDMAP_REMOTE_PROT	= 0x01,
	RDMAP_REMOTE_OP		= 0x02,
	DDP_LOCAL_CATA		= 0x00,
	DDP_TAGGED_ERR		= 0x01,
	DDP_UNTAGGED_ERR	= 0x02,
	DDP_LLP			= 0x03
};

enum chrd_rdma_ecodes {
	RDMAP_INV_STAG		= 0x00,
	RDMAP_BASE_BOUNDS	= 0x01,
	RDMAP_ACC_VIOL		= 0x02,
	RDMAP_STAG_NOT_ASSOC	= 0x03,
	RDMAP_TO_WRAP		= 0x04,
	RDMAP_INV_VERS		= 0x05,
	RDMAP_INV_OPCODE	= 0x06,
	RDMAP_STREAM_CATA	= 0x07,
	RDMAP_GLOBAL_CATA	= 0x08,
	RDMAP_CANT_INV_STAG	= 0x09,
	RDMAP_UNSPECIFIED	= 0xff
};

enum chrd_ddp_ecodes {
	DDPT_INV_STAG		= 0x00,
	DDPT_BASE_BOUNDS	= 0x01,
	DDPT_STAG_NOT_ASSOC	= 0x02,
	DDPT_TO_WRAP		= 0x03,
	DDPT_INV_VERS		= 0x04,
	DDPU_INV_QN		= 0x01,
	DDPU_INV_MSN_NOBUF	= 0x02,
	DDPU_INV_MSN_RANGE	= 0x03,
	DDPU_INV_MO		= 0x04,
	DDPU_MSG_TOOBIG		= 0x05,
	DDPU_INV_VERS		= 0x06
};

enum chrd_mpa_ecodes {
	MPA_CRC_ERR		= 0x02,
	MPA_MARKER_ERR		= 0x03,
	MPA_LOCAL_CATA          = 0x05,
	MPA_INSUFF_IRD          = 0x06,
	MPA_NOMATCH_RTR         = 0x07,
};

enum chrd_ep_state {
	IDLE = 0,
	LISTEN,
	CONNECTING,
	MPA_REQ_WAIT,
	MPA_REQ_SENT,
	MPA_REQ_RCVD,
	MPA_REP_SENT,
	FPDU_MODE,
	ABORTING,
	CLOSING,
	MORIBUND,
	DEAD,
};

enum chrd_ep_flags {
	PEER_ABORT_IN_PROGRESS	= 0,
	ABORT_REQ_IN_PROGRESS	= 1,
	RELEASE_RESOURCES	= 2,
	CLOSE_SENT		= 3,
	TIMEOUT			= 4,
	QP_REFERENCED		= 5,
	STOP_MPA_TIMER		= 7,
};

enum chrd_ep_history {
	ACT_OPEN_REQ		= 0,
	ACT_OFLD_CONN		= 1,
	ACT_OPEN_RPL		= 2,
	ACT_ESTAB		= 3,
	PASS_ACCEPT_REQ		= 4,
	PASS_ESTAB		= 5,
	ABORT_UPCALL		= 6,
	ESTAB_UPCALL		= 7,
	CLOSE_UPCALL		= 8,
	ULP_ACCEPT		= 9,
	ULP_REJECT		= 10,
	TIMEDOUT		= 11,
	PEER_ABORT		= 12,
	PEER_CLOSE		= 13,
	CONNREQ_UPCALL		= 14,
	ABORT_CONN		= 15,
	DISCONN_UPCALL		= 16,
	EP_DISC_CLOSE		= 17,
	EP_DISC_ABORT		= 18,
	CONN_RPL_UPCALL		= 19,
	ACT_RETRY_NOMEM		= 20,
	ACT_RETRY_INUSE		= 21,
	CLOSE_CON_RPL		= 22,
	KILLED			= 23,
	EP_DISC_FAIL		= 24,
	QP_REFED  		= 25,
	QP_DEREFED  		= 26,
	CM_ID_REFED		= 27,
	CM_ID_DEREFED		= 28,
};

enum conn_pre_alloc_buffers {
        CN_ABORT_REQ_BUF,
        CN_ABORT_RPL_BUF,
        CN_CLOSE_CON_REQ_BUF,
        CN_DESTROY_BUF,
        CN_FLOWC_BUF,
        CN_MAX_CON_BUF
};

enum {
	FLOWC_LEN = offsetof(struct fw_flowc_wr, mnemval[FW_FLOWC_MNEM_MAX]),
};

union cpl_wr_size {
	struct cpl_abort_req abrt_req;
	struct cpl_abort_rpl abrt_rpl;
	struct fw_ri_wr ri_req;
	struct cpl_close_con_req close_req;
	char flowc_buf[FLOWC_LEN];
};

struct chrd_ep_common {
	struct iw_cm_id *cm_id;
	struct chrd_qp *qp;
	struct chrd_dev *dev;
	struct sk_buff_head ep_skb_list;
	enum chrd_ep_state state;
	struct kref kref;
	u16 txq_idx;
	struct mutex mutex;
	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;
	struct chrd_wr_wait *wr_waitp;
	unsigned long flags;
	unsigned long history;
	struct list_head glist_entry;
};

struct chrd_listen_ep {
	struct chrd_ep_common com;
	unsigned int stid;
	int backlog;
};

struct chrd_ep_stats {
	unsigned connect_neg_adv;
	unsigned abort_neg_adv;
};

struct chrd_ep {
	struct chrd_ep_common com;
	struct chrd_ep *parent_ep;
	struct timer_list timer;
	struct list_head entry;
	unsigned int atid;
	u32 hwtid;
	u32 snd_seq;
	u32 rcv_seq;
	struct l2t_entry *l2t;
	struct dst_entry *dst;
	struct sk_buff *mpa_skb;
	struct chrd_mpa_attributes mpa_attr;
	u8 mpa_pkt[sizeof(struct mpa_message) + MPA_MAX_PRIVATE_DATA];
	unsigned int mpa_pkt_len;
	u32 ird;
	u32 ord;
	u32 smac_idx;
	u32 tx_chan;
	u32 mtu;
	u16 mss;
	u16 emss;
	u16 plen;
	u16 rss_qid;
	u16 ctrlq_idx;
	u8 tos;
	u8 retry_with_mpa_v1;
	u8 tried_with_mpa_v1;
	u8 port_chan;
	unsigned int retry_count;
	int snd_win;
	int rcv_win;
	u16 ipsecidx;
	u32 snd_wscale;
	struct chrd_ep_stats stats;
	u32 srqe_idx;
	u32 rx_pdu_out_cnt;
	struct sk_buff *peer_abort_skb;
};

static inline struct chrd_ep *to_ep(struct iw_cm_id *cm_id)
{
	return cm_id->provider_data;
}

static inline struct chrd_listen_ep *to_listen_ep(struct iw_cm_id *cm_id)
{
	return cm_id->provider_data;
}

static inline struct chrd_ah *to_chrd_ah(struct ib_ah *ibah)
{
	return container_of(ibah, struct chrd_ah, ibah);
}

static inline int compute_wscale(int win)
{
	int wscale = 0;

	while (wscale < 14 && (65535<<wscale) < win)
		wscale++;
	return wscale;
}

static inline int ocqp_supported(const struct cxgb4_lld_info *infop)
{
#if defined(__i386__) || defined(__x86_64__) || defined (CONFIG_PPC64)
	return infop->vr->ocq.size > 0;
#else
        return 0;
#endif
}

typedef int (*chrd_handler_func)(struct chrd_dev *dev, struct sk_buff *skb);

int chrd_ep_redirect(void *ctx, struct dst_entry *old, struct dst_entry *new,
		     struct l2t_entry *l2t);
void chrd_put_qpid(struct chrd_rdev *rdev, u32 qpid,
		   struct cxgb4_dev_ucontext *uctx);
int chrd_init_resource(struct chrd_rdev *rdev, u32 nr_tpt);
int chrd_init_ctrl_qp(struct chrd_rdev *rdev);
int chrd_pblpool_create(struct chrd_rdev *rdev);
int chrd_rrqtpool_create(struct chrd_rdev *rdev);
void chrd_pblpool_destroy(struct chrd_rdev *rdev);
void chrd_rqtpool_destroy(struct chrd_rdev *rdev);
void chrd_rrqtpool_destroy(struct chrd_rdev *rdev);
void chrd_destroy_resource(struct chrd_rdev *rdev);
int chrd_destroy_ctrl_qp(struct chrd_rdev *rdev);
void chrd_register_device(struct work_struct *work);
void chrd_unregister_device(struct chrd_dev *dev);
int __init chrd_cm_init(void);
void chrd_cm_term(void);
int chrd_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc);
int chrd_iw_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
		      const struct ib_send_wr **bad_wr);
int chrd_roce_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			const struct ib_send_wr **bad_wr);
int chrd_post_receive(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		      const struct ib_recv_wr **bad_wr);
int chrd_iw_connect(struct iw_cm_id *cm_id, struct iw_cm_conn_param *conn_param);
int chrd_iw_create_listen(struct iw_cm_id *cm_id, int backlog);
int chrd_iw_destroy_listen(struct iw_cm_id *cm_id);
int chrd_iw_accept_cr(struct iw_cm_id *cm_id, struct iw_cm_conn_param *conn_param);
int chrd_iw_reject_cr(struct iw_cm_id *cm_id, const void *pdata, u8 pdata_len);
void chrd_iw_qp_add_ref(struct ib_qp *qp);
void chrd_iw_qp_rem_ref(struct ib_qp *qp);
struct ib_mr *chrd_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			    u32 max_num_sg);
int chrd_map_mr_sg(struct ib_mr *ibmr,
		   struct scatterlist *sg,
#ifdef IWARP_HAVE_SG_OFFSET
		   int sg_nents, unsigned int *sg_offset);
#else
		   int sg_nents);
#endif
int chrd_dealloc_mw(struct ib_mw *mw);
void chrd_dealloc(struct uld_ctx *ctx);
void chrd_dispatch_event(struct ib_device* ibdev,
			  u8 port_num,
			  enum ib_event_type type);
int chrd_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata);
struct ib_mr *chrd_reg_user_mr(struct ib_pd *pd, u64 start,
					   u64 length, u64 virt, int acc,
					   struct ib_udata *udata);
struct ib_mr *chrd_get_dma_mr(struct ib_pd *pd, int acc);
int chrd_dereg_mr(struct ib_mr *ib_mr, struct ib_udata *udata);
int chrd_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata);
int chrd_create_cq(struct ib_cq *ibcq,
#ifdef IWARP_HAVE_CQ_INIT_ATTR
			     const struct ib_cq_init_attr *attr,
			     struct uverbs_attr_bundle *attrs);
#else
			     int entries, int vector,
			     struct ib_ucontext *ib_context,
			     struct uverbs_attr_bundle *attrs);
#endif
int chrd_resize_cq(struct ib_cq *cq, int cqe, struct ib_udata *udata);
int chrd_arm_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags);
int chrd_modify_srq(struct ib_srq *ib_srq, struct ib_srq_attr *attr,
		    enum ib_srq_attr_mask srq_attr_mask,
		    struct ib_udata *udata);
int chrd_destroy_srq(struct ib_srq *ib_srq, struct ib_udata *udata);
int chrd_create_srq(struct ib_srq *srq,
		    struct ib_srq_init_attr *attrs,
		    struct ib_udata *udata);
int chrd_destroy_qp(struct ib_qp *ib_qp, struct ib_udata *udata);
int chrd_create_qp(struct ib_qp *qp, struct ib_qp_init_attr *attrs,
		   struct ib_udata *udata);
int chrd_iw_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		      int attr_mask, struct ib_udata *udata);
int chrd_roce_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			int attr_mask, struct ib_udata *udata);
int chrd_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		  int attr_mask, struct ib_qp_init_attr *init_attr);
struct ib_qp *chrd_iw_get_qp(struct ib_device *dev, int qpn);
u32 chrd_rrqtpool_alloc(struct chrd_rdev *rdev, int size);
void chrd_rrqtpool_free(struct chrd_rdev *rdev, u32 addr, int size);
u32 chrd_rqtpool_alloc(struct chrd_rdev *rdev, int size);
void chrd_rqtpool_free(struct chrd_rdev *rdev, u32 addr, int size);
u32 chrd_pblpool_alloc(struct chrd_rdev *rdev, int size);
void chrd_pblpool_free(struct chrd_rdev *rdev, u32 addr, int size);
void chrd_flush_hw_cq(struct chrd_cq *chp, struct chrd_qp *flush_qhp);
void chrd_count_rcqes(struct t4_cq *cq, struct t4_wq *wq, int *count);
int chrd_ep_disconnect(struct chrd_ep *ep, int abrupt, gfp_t gfp);
int chrd_flush_rq(struct chrd_qp *qhp, struct t4_cq *cq, int count);
int chrd_flush_sq(struct chrd_qp *qhp);
int chrd_ev_handler(struct chrd_dev *rnicp, u32 qid, u32 pidx);
u16 chrd_rqes_posted(struct chrd_qp *qhp);
int chrd_post_terminate(struct chrd_qp *qhp, struct t4_cqe *err_cqe);
void chrd_ev_dispatch(struct chrd_dev *dev, struct t4_cqe *err_cqe);

extern chrd_handler_func chrd_handlers[NUM_CPL_CMDS];
struct ib_qp *chrd_create_raw_qp(struct ib_pd *pd,
				 struct ib_qp_init_attr *attrs,
				 struct ib_udata *udata);
void __iomem *chrd_bar2_addrs(struct chrd_rdev *rdev, unsigned int qid,
			      enum cxgb4_bar2_qtype qtype,
			      unsigned int *pbar2_qid, u64 *pbar2_pa);
extern void chrd_log_wr_stats(struct t4_wq *wq, struct t4_cqe *cqe);
extern int chrd_wr_log;

extern int use_dsgl;
extern int wd_disable_inaddr_any;
extern int roce_mode;
void chrd_dispatch_srq_limit_reached_event(struct chrd_srq *srq);

#ifndef IB_QPT_RAW_ETH
#define IB_QPT_RAW_ETH 8
#endif
void chrd_copy_wr_to_srq(struct t4_srq *srq, union t4_recv_wr *wqe, u8 len16);
void chrd_flush_srqidx(struct chrd_qp *qhp, u32 srqidx);
int chrd_post_srq_recv(struct ib_srq *ibsrq, const struct ib_recv_wr *wr,
		       const struct ib_recv_wr **bad_wr);
void chrd_invalidate_mr(struct chrd_dev *rhp, u32 rkey);
struct chrd_wr_wait *chrd_alloc_wr_wait(gfp_t gfp);

typedef int chrd_restrack_func(struct sk_buff *msg,
			       struct rdma_restrack_entry *res);
int chrd_fill_res_mr_entry(struct sk_buff *msg, struct ib_mr *ibmr);
int chrd_fill_res_cq_entry(struct sk_buff *msg, struct ib_cq *ibcq);
int chrd_fill_res_qp_entry(struct sk_buff *msg, struct ib_qp *ibqp);
int chrd_fill_res_cm_id_entry(struct sk_buff *msg, struct rdma_cm_id *cm_id);

#endif
