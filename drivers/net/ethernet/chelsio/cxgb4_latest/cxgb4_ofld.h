/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver.
 *
 * Copyright (C) 2009-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4_OFLD_H
#define __CXGB4_OFLD_H

#include <linux/cache.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/completion.h>
#include <linux/bitmap.h>
#include <net/sock.h>
#include "l2t.h"
#include <asm/atomic.h>

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#include <net/offload.h>
#include "ocqp.h"
#include "cxgb4_uld.h"
#endif

/* CPL message priority levels */
enum {
	CPL_PRIORITY_DATA     = 0,  /* data messages */
	CPL_PRIORITY_SETUP    = 1,  /* connection setup messages */
	CPL_PRIORITY_TEARDOWN = 0,  /* connection teardown messages */
	CPL_PRIORITY_LISTEN   = 1,  /* listen start/stop messages */
	CPL_PRIORITY_ACK      = 1,  /* RX ACK messages */
	CPL_PRIORITY_CONTROL  = 1   /* control messages */
};

/*
 * Max Tx descriptor space we allow for an Ethernet packet to be inlined
 * into a WR.
 */
#define MAX_IMM_TX_PKT_LEN 256

/*
 * Max WR length for FW_OFLD_TX_DATA_WR in immediate only case
 * Work request header + 256B immediate data length
 */
#define MAX_IMM_OFLD_TX_DATA_WR_LEN (0xff + sizeof(struct fw_ofld_tx_data_wr))
#define MAX_IMM_OFLD_TX_DATA_V2_WR_LEN (0xff + sizeof(struct fw_ofld_tx_data_v2_wr))

static inline u16 ofld_tx_data_wr_max_len(bool sendpath_enable)
{
	return sendpath_enable ? MAX_IMM_OFLD_TX_DATA_V2_WR_LEN :
				 MAX_IMM_OFLD_TX_DATA_WR_LEN;
}

/* fw_nvmet_v2_fr_nsmr_tpte_wr + payload */
#define MAX_IMM_NSMR_TPTE_WR_LEN (sizeof(struct fw_nvmet_v2_fr_nsmr_tpte_wr) + 256)

/* ulp_mem_io + ulptx_idata + payload + padding */
#define MAX_IMM_ULPTX_WR_LEN (32 + 8 + 256 + 8)

/*
 * fw_ri_rw[fw_ri_type_init] + cpl_tx_tnl_lso + cpl_tx_pkt_xt + fw_ri_imm + headers
 * headers = 18B eth & vlan + 40B Outer_IP + 16B ESP + 40B Inner_IP + 8B UDP + 12B BTH
 */
#define MAX_IMM_ROCE_WR_LEN (round_up(80 + 32 + 16 + 8 + 134, 16))

#define INIT_TP_WR(w, tid) do { \
	(w)->wr.wr_hi = htonl(V_FW_WR_OP(FW_TP_WR) | \
			      V_FW_WR_IMMDLEN(sizeof(*w) - sizeof(w->wr))); \
	(w)->wr.wr_mid = htonl(V_FW_WR_LEN16(DIV_ROUND_UP(sizeof(*w), 16)) | \
			       V_FW_WR_FLOWID(tid)); \
	(w)->wr.wr_lo = cpu_to_be64(0); \
} while (0)

#define INIT_TP_WR_MIT_CPL(w, cpl, tid) do { \
	INIT_TP_WR(w, tid); \
	OPCODE_TID(w) = htonl(MK_OPCODE_TID(cpl, tid)); \
} while (0)

#define INIT_ULPTX_WR(w, wrlen, atomic, tid) do { \
	(w)->wr.wr_hi = htonl(V_FW_WR_OP(FW_ULPTX_WR) | V_FW_WR_ATOMIC(atomic)); \
	(w)->wr.wr_mid = htonl(V_FW_WR_LEN16(DIV_ROUND_UP(wrlen, 16)) | \
			       V_FW_WR_FLOWID(tid)); \
	(w)->wr.wr_lo = cpu_to_be64(0); \
} while (0)

/* Special asynchronous notification message */
#define CXGB4_MSG_AN ((void *)1)

void *cxgb_alloc_mem(unsigned long size);

struct in6_addr;

#define S_CXGB4_ULD_SKB_PIDX_OFFSET 16
#define M_CXGB4_ULD_SKB_PIDX_OFFSET 0xffff
#define V_CXGB4_ULD_SKB_PIDX_OFFSET(x) ((x) << S_CXGB4_ULD_SKB_PIDX_OFFSET)
#define G_CXGB4_ULD_SKB_PIDX_OFFSET(x) \
	(((x) >> S_CXGB4_ULD_SKB_PIDX_OFFSET) & M_CXGB4_ULD_SKB_PIDX_OFFSET)

#define S_CXGB4_ULD_SKB_RSVD 8
#define M_CXGB4_ULD_SKB_RSVD 0xff
#define V_CXGB4_ULD_SKB_RSVD(x) ((x) << S_CXGB4_ULD_SKB_RSVD)
#define G_CXGB4_ULD_SKB_RSVD(x) \
	(((x) >> S_CXGB4_ULD_SKB_RSVD) & M_CXGB4_ULD_SKB_RSVD)

#define S_CXGB4_ULD_SKB_PRIO 7
#define M_CXGB4_ULD_SKB_PRIO 1
#define V_CXGB4_ULD_SKB_PRIO(x) ((x) << S_CXGB4_ULD_SKB_PRIO)
#define G_CXGB4_ULD_SKB_PRIO(x) \
	(((x) >> S_CXGB4_ULD_SKB_PRIO) & M_CXGB4_ULD_SKB_PRIO)

#define S_CXGB4_ULD_SKB_CREDITS 0
#define M_CXGB4_ULD_SKB_CREDITS 0x7f
#define V_CXGB4_ULD_SKB_CREDITS(x) ((x) << S_CXGB4_ULD_SKB_CREDITS)
#define G_CXGB4_ULD_SKB_CREDITS(x) \
	(((x) >> S_CXGB4_ULD_SKB_CREDITS) & M_CXGB4_ULD_SKB_CREDITS)

static inline void cxgb4_uld_skb_set_pidx_offset(struct sk_buff *skb,
						 u16 offset)
{
	skb->priority |= V_CXGB4_ULD_SKB_PIDX_OFFSET(offset);
}

static inline u16 cxgb4_uld_skb_get_pidx_offset(const struct sk_buff *skb)
{
	return G_CXGB4_ULD_SKB_PIDX_OFFSET(skb->priority);
}

static inline void cxgb4_uld_skb_set_prio(struct sk_buff *skb, bool prio)
{
	skb->priority |= V_CXGB4_ULD_SKB_PRIO(prio);
}

static inline bool cxgb4_uld_skb_get_prio(const struct sk_buff *skb)
{
	return G_CXGB4_ULD_SKB_PRIO(skb->priority);
}

static inline void cxgb4_uld_skb_set_credits(struct sk_buff *skb,
					     u16 credits)
{
	skb->priority |= V_CXGB4_ULD_SKB_CREDITS(credits);
}

static inline u16 cxgb4_uld_skb_get_credits(const struct sk_buff *skb)
{
	return G_CXGB4_ULD_SKB_CREDITS(skb->priority);
}

static inline void cxgb4_uld_skb_set_queue(struct sk_buff *skb, u16 queue)
{
	skb_set_queue_mapping(skb, queue);
}

static inline u16 cxgb4_uld_skb_get_queue(const struct sk_buff *skb)
{
	return skb_get_queue_mapping(skb);
}

static inline void set_wr_txq(struct sk_buff *skb, bool prio, u16 queue)
{
	cxgb4_uld_skb_set_prio(skb, prio);
	cxgb4_uld_skb_set_queue(skb, queue);
}

#define ofld_skb_premapped_frags(skb)   ((skb)->peeked)

/*
 *      ofld_skb_get_premapped_frags - return if the skb contains pre-mapped dma
 *                      addresses
 *      @skb: the packet
 *      Returns true if the skb contains pre-mapped dma addresses
 */
static inline unsigned int
ofld_skb_get_premapped_frags(const struct sk_buff *skb)
{
	return skb->peeked;
}

/*
 *      ofld_skb_set_premapped_frags - skb contains pre-mapped dma addresses
 *                      addresses
 *      @skb: the packet
 *      @premapped: 0 or 1
 */
static inline void ofld_skb_set_premapped_frags(struct sk_buff *skb,
						int premapped)
{
	skb->peeked = premapped;
}

/*
 *      is_ofld_sg_reqd - check whether a packet requires an SG list
 *      @skb: the packet
 *
 *      Returns true if a packet cannot be sent as an offload WR entirely with
 *      immediate data.
 */
static inline int is_ofld_sg_reqd(const struct sk_buff *skb)
{
	return ofld_skb_get_premapped_frags(skb) ||
			(skb->len > MAX_IMM_ULPTX_WR_LEN);
}


enum cxgb4_txq_type {
	CXGB4_TXQ_ETH,
	CXGB4_TXQ_ULD,
	CXGB4_TXQ_CTRL,
	CXGB4_TXQ_MAX
};

enum cxgb4_state {
	CXGB4_STATE_UP,
	CXGB4_STATE_START_RECOVERY,
	CXGB4_STATE_DOWN,
	CXGB4_STATE_DETACH,
	CXGB4_STATE_SHUTDOWN
};

enum cxgb4_control {
	CXGB4_CONTROL_SET_OFFLOAD_POLICY,
	CXGB4_CONTROL_DB_FULL,
	CXGB4_CONTROL_DB_EMPTY,
	CXGB4_CONTROL_DB_DROP,
	CXGB4_CONTROL_MAC_ADDR_CHANGE,
};

struct pci_dev;
struct l2t_data;
struct net_device;
struct pkt_gl;
struct t4_lro_mgr;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
/*
 * Block of information the LLD provides to ULDs attaching to a device.
 */
struct cxgb4_lld_info {
	struct device *dev;                  /* associated device */
	const char *name;                    /* associated PCI/Platform device name */
	u32 vendor_id;			     /* associated vendor_id */
	u32 device_id;			     /* associated device id */
	struct l2t_data *l2t;                /* L2 table */
	struct cxgb4_uld_tid_info uld_tids;  /* ULD TID info */
	struct net_device **ports;           /* device ports */
	const struct cxgb4_virt_res *vr;     /* assorted HW resources */
	const unsigned short *mtus;          /* MTU table */
	const unsigned short *rxq_ids;       /* the ULD's Rx queue ids */
	const unsigned short *txq_ids;       /* the ULD's Tx queue ids */
	const unsigned short *ciq_ids;       /* the ULD's concentrator IQ ids */
	unsigned int ctrlq_start;            /* the ULD's control qid start */
	unsigned short nrxq;                 /* # of Rx queues */
	unsigned short ntxq;                 /* # of Tx queues */
	unsigned short nciq;		     /* # of concentrator IQ */
	unsigned char nchan:4;               /* # of channels */
	unsigned char nports:4;              /* # of ports */
	unsigned char wr_cred;               /* WR 16-byte credits */
	unsigned char fw_api_ver;            /* FW API version */
	enum chip_type adapter_type;         /* type of adapter */
	unsigned int fw_vers;                /* FW version */
	unsigned int iscsi_iolen;            /* iSCSI max I/O length */
	unsigned int nvmt_iolen;             /* NVMe/TCP max I/O length */
	unsigned short udb_density;          /* # of user DB/page */
	unsigned short ucq_density;          /* # of user CQs/page */
	unsigned int sge_host_page_size;     /* SGE host page size */
	unsigned short tx_db_wc;             /* use TX Doorbell Write Combining */
	unsigned short filt_mode;            /* filter optional components */
	unsigned short tx_modq[NCHAN]; 	     /* maps each tx channel to a scheduler queue */
	void __iomem *gts_reg;               /* address of GTS register */
	void __iomem *db_reg;                /* address of kernel doorbell */
	int dbfifo_int_thresh;		     /* doorbell fifo int threshold */
	unsigned int sge_ingpadboundary;     /* SGE ingress padding boundary */
	unsigned int sge_pktshift;   	     /* Padding between CPL and packet Data */
	unsigned int sge_egrstatuspagesize;  /* SGE egress status page size */
	unsigned int pf;                     /* Physical Function we're using */
	bool enable_fw_ofld_conn;	     /* Enable connection through fw WR */
	unsigned int nsched_cls;             /* number of traffic classes */
	unsigned int max_ordird_qp;	     /* Max ORD/IRD depth per RDMA QP */
	unsigned int max_ird_adapter;	     /* Max IRD memory per adapter */
	bool ulptx_memwrite_dsgl;            /* use of T5 DSGL allowed */
	bool dev_512sgl_mr;		     /* support 512 pbl entries per FR MR*/
	unsigned int iscsi_tagmask;          /* iscsi ddp tag mask */
	unsigned int iscsi_pgsz_order;       /* iscsi ddp page size orders */
	unsigned int cclk_ps;		     /* Core clock period in picoseconds */
	unsigned int iscsi_llimit;	     /* chip's iscsi region llimit */
	void **iscsi_ppm;	             /* iscsi pagepod manager */
	void **rdma_resource;	             /* rdma resource manager */
	void **cnvme_ddp;		     /* NVMe/TCP DDP resource manager */
	int nodeid;			     /* device numa node id */
	unsigned char ulp_t10dif;            /* t10dif support in ulp */
	unsigned int ulp_crypto;             /* crypto lookaside support */
	bool fr_nsmr_tpte_wr_support;        /* FW support for FR_NSMR_TPTE_WR */
	bool write_w_imm_support;	     /* FW supports WRITE_WITH_IMMEDIATE */
	bool relaxed_ordering;               /* OK to use PCIe Relaxed Ordering */
	bool write_cmpl_support;	     /* FW supports WRITE_CMPL WR */
	unsigned int neq;                    /* Max # of Tx queues supported by FW */
	bool sendpath_enabled;               /* FW supports Tx SENDPATH */
	bool cpl_nvmt_data_iqe;		     /* HW delivers CPL_NVMT_DATA in IQE */
	bool cpl_iscsi_data_iqe;	     /* HW delivers CPL_ISCSI_DATA in IQE */
	bool iscsi_all_cmp_mode; /* HW delivers CPL_ISCSI_CMP for all Data pdus */
	bool non_ddp_bit; /* non-ddp bit dedicated for iscsi */
	unsigned int tid_qid_sel_mask; /* TID based QID selection mask */
	unsigned char tid_qid_sel_shift; /* TID based QID selection shift */
};

struct cxgb4_uld_info {
	const char *name;
	void *(*add)(const struct cxgb4_lld_info *p);
	int (*rx_handler)(void *handle, const __be64 *rsp,
			  const struct pkt_gl *gl);
	int (*ma_failover_handler)(void *handle, const __be64 *rsp,
				   const struct pkt_gl *gl);
	int (*state_change)(void *handle, enum cxgb4_state new_state);
	int (*control)(void *handle, enum cxgb4_control control, ...);
	int (*lro_rx_handler)(void *handle, const __be64 *rsp,
			      const struct pkt_gl *gl,
			      struct t4_lro_mgr *lro_mgr,
			      struct napi_struct *napi);
	void (*lro_flush)(struct t4_lro_mgr *);
	int (*tx_handler)(struct sk_buff *skb, struct net_device *dev);
#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)
	const struct xfrmdev_ops *xfrmdev_ops;
	u16 (*xfrm_ipsecidx_get)(struct xfrm_state *xfrm);
	void (*ch_ipsec_show)(struct adapter *adap, struct seq_file *seq);
#endif
};

extern struct cxgb4_uld_info cxgb4_ulds[CXGB4_ULD_TYPE_MAX];

int cxgb4_register_uld_type(enum cxgb4_uld_type type,
			    const struct cxgb4_uld_info *p);
int cxgb4_unregister_uld_type(enum cxgb4_uld_type type);
bool cxgb4_uld_is_registered(struct adapter *adap, enum cxgb4_uld_type type);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

unsigned int cxgb4_dbfifo_count(const struct net_device *dev, int lpfifo);
unsigned int cxgb4_port_chan(const struct net_device *dev);
u8 cxgb4_port_tx_chan(const struct net_device *dev);
u8 cxgb4_port_rx_chan(const struct net_device *dev);
unsigned int cxgb4_port_e2cchan(const struct net_device *dev);
unsigned int cxgb4_port_viid(const struct net_device *dev);
unsigned int cxgb4_port_idx(const struct net_device *dev);
int cxgb4_dcb_enabled(const struct net_device *dev);
struct net_device *cxgb4_netdev_by_hwid(struct pci_dev *pdev, unsigned int id);
unsigned int cxgb4_best_mtu(const unsigned short *mtus, unsigned short mtu,
			    unsigned int *idx);
unsigned int cxgb4_best_aligned_mtu(const unsigned short *mtus,
				    unsigned short header_size,
				    unsigned short data_size_max,
				    unsigned short data_size_align,
				    unsigned int *mtu_idxp);
void cxgb4_get_tcp_stats(struct net_device *dev, struct tp_tcp_stats *v4,
                        struct tp_tcp_stats *v6);
int cxgb4_wr_mbox(struct net_device *dev, const void *cmd, int size, void *rpl);
int cxgb4_flush_eq_cache(struct net_device *dev);
int cxgb4_read_tpte(struct net_device *dev, u32 stag, __be32 *tpte);
int cxgb4_set_params(struct net_device *dev, unsigned int nparams,
		     const u32 *params, const u32 *val);
u64 cxgb4_read_sge_timestamp(struct net_device *dev);
struct sk_buff *cxgb4_pktgl_to_skb(struct napi_struct *napi,
				   const struct pkt_gl *gl,
				   unsigned int skb_len, unsigned int pull_len);
void t4_pktgl_free(const struct pkt_gl *gl);

enum cxgb4_bar2_qtype { CXGB4_BAR2_QTYPE_EGRESS, CXGB4_BAR2_QTYPE_INGRESS };
int cxgb4_bar2_sge_qregs(struct net_device *dev,
			 unsigned int qid,
			 enum cxgb4_bar2_qtype qtype,
			 int user,
			 u64 *pbar2_qoffset,
			 unsigned int *pbar2_qid);
void cxgb4_fatal_err(struct net_device *dev);
u16 cxgb4_uld_xfrm_ipsecidx_get(struct xfrm_state *xfrm);

/*
 * Allocate n page pods.  Returns -1 on failure or the page pod tag.
 */
static inline int cxgb4_alloc_ppods(unsigned long *bmap, unsigned int max_ppods,
				    unsigned int start, unsigned int n,
				    unsigned int align_mask)
{
	unsigned long tag;

	tag = bitmap_find_next_zero_area(bmap, max_ppods, start, n, align_mask);
	if (unlikely(tag >= max_ppods))
		return -1;

	bitmap_set(bmap, tag, n);
	return tag;
}

static inline void cxgb4_free_ppods(unsigned long *bmap,
				    unsigned int tag, unsigned int n)
{
	bitmap_clear(bmap, tag, n);
}

/*
 * Opaque version of structure the SGE stores at skb->head of TX_DATA packets
 * and for which we must reserve space.
 */
struct sge_opaque_hdr {
	struct scatterlist addr[MAX_SKB_FRAGS + 1];
};

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
struct resource *cxgb4_bar_resource(struct net_device *dev, u8 index);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
#endif  /* !__CXGB4_OFLD_H */
