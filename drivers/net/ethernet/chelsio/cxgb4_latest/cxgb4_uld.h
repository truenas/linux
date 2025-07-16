/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4_ULD_H__
#define __CXGB4_ULD_H__

extern struct mutex uld_mutex;

enum cxgb4_uld_type {
	CXGB4_ULD_TYPE_RDMA,
	CXGB4_ULD_TYPE_ISCSI,
	CXGB4_ULD_TYPE_ISCSIT,
	CXGB4_ULD_TYPE_NVME_TCP_HOST,
	CXGB4_ULD_TYPE_NVME_TCP_TARGET,
	CXGB4_ULD_TYPE_CSTOR,
	CXGB4_ULD_TYPE_CRYPTO,
	CXGB4_ULD_TYPE_TOE,
	CXGB4_ULD_TYPE_CHTCP,
	CXGB4_ULD_TYPE_IPSEC,
	CXGB4_ULD_TYPE_MAX
};

struct cxgb4_range {
	unsigned int start;
	unsigned int size;
};

struct cxgb4_virt_res {                      /* virtualized HW resources */
	struct cxgb4_range ddp;
	struct cxgb4_range iscsi;
	struct cxgb4_range stag;
	struct cxgb4_range nvme_stag;
	struct cxgb4_range rq;
	struct cxgb4_range srq;
	struct cxgb4_range rrq;
	struct cxgb4_range pbl;
	struct cxgb4_range nvme_pbl;
	struct cxgb4_range qp;
	struct cxgb4_range cq;
	struct cxgb4_range ocq;
	struct cxgb4_range key;
	struct cxgb4_range ppod_edram;
	struct cxgb4_range sendpath_qp;
	unsigned int ncrypto_fc;
#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)
	unsigned int ipsec_max_nic_tunnel;
	unsigned int ipsec_max_nic_transport;
	unsigned int ipsec_max_ofld_conn;
#endif /* CONFIG_CHELSIO_T4_IPSEC_INLINE */
#ifdef CONFIG_PO_FCOE
	unsigned int toe_nppods;
	unsigned int fcoe_nppods;
#endif /* CONFIG_PO_FCOE */
};

struct chcr_stats {
	atomic_t cipher_rqst;
	atomic_t digest_rqst;
	atomic_t aead_rqst;
	atomic_t rqst_comp;
	atomic_t rsp_error;
	atomic_t fallback;
};

#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)
struct ch_ipsec_stats_debug {
	atomic_t ipsec_cnt;
	atomic_t ipsec_rx_cnt;
	atomic_t nipsec_tunnel;
	atomic_t nipsec_transport;
	atomic_t ofld_nipsec_tunnel;
};
#endif

struct tls_stats {
	atomic_t tls_pdu_tx;
	atomic_t tls_pdu_rx;
	atomic_t dtls_pdu_tx;
	atomic_t dtls_pdu_rx;
	atomic_t tls_key;
};

struct cxgb4_uld_stats {
#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)
	struct ch_ipsec_stats_debug ipsec;
#endif /* CONFIG_CHELSIO_T4_IPSEC_INLINE */
	struct chcr_stats chcr;
	struct tls_stats tls;
};

#define OCQ_WIN_OFFSET(pdev, vres) \
	(pci_resource_len((pdev), 2) - roundup_pow_of_two((vres)->ocq.size))

struct cxgb4_uld_tid_info {
	struct cxgb4_range tids;
	struct cxgb4_range atids;
	struct cxgb4_range hpftids;
	struct cxgb4_range ftids;
	struct cxgb4_range stids;
};

enum cxgb4_uld_txq_desc {
	CXGB4_ULD_TXQ_DESC_NUM = 1024,
	CXGB4_ULD_TXQ_SENDPATH_DESC_NUM = 256,
};

enum cxgb4_uld_txq_type {
	CXGB4_ULD_TXQ_TYPE_SHARED = 0,
	CXGB4_ULD_TXQ_TYPE_SENDPATH,
	CXGB4_ULD_TXQ_TYPE_MAX,
};

enum cxgb4_uld_txq_info_flags {
	CXGB4_ULD_TXQ_INFO_FLAG_SENDPATH = BIT(0),
};

struct cxgb4_uld_txq_info {
	/* Filled by ULD */
	u32 uld_index; /* ULD index to the queue */
	u32 flags; /* ULD TXQ_INFO_FLAGS */
	u32 iqid; /* ULD Ingress Queue for completions */
	u64 cookie; /* ULD cookie for completions */

	/* Filled by LLD */
	u32 lld_index; /* LLD index to the queue */
	u16 size; /* Maximum queue size */
};

struct cxgb4_uld_txq {
	struct sge_ofld_txq *ofldtxq;
	struct cxgb4_uld_txq_info info;
	enum cxgb4_uld_txq_type qtype;
	enum cxgb4_uld_type uld;
	u32 users;
	struct net_device *dev;
	struct work_struct task_txq_free;

	u8 tid_qid_group_id;
	struct list_head tid_qid_group;
};

struct cxgb4_uld_queue_tid_qid_group {
	struct cxgb4_uld_txq *cur_entry;
	struct list_head list_head;
	spinlock_t lock; /* Lock to update cur_entry */
};

struct cxgb4_uld_queue_tid_qid_map {
	u8 ngroups;
	struct cxgb4_uld_queue_tid_qid_group *qid_arr;
};

struct cxgb4_uld_queue_map {
	u32 max_queues;
	u32 num_queues;
	struct xarray queues;
	struct cxgb4_uld_queue_tid_qid_map *tid_qid_map;
};

struct cxgb4_uld_queues_toe {
	struct cxgb4_uld_queue_map shared_txqs;
	struct cxgb4_uld_queue_map txqs;
};

struct cxgb4_uld_queues_rdma {
	struct cxgb4_uld_queue_map txqs;
};

struct cxgb4_uld_queues_iscsi {
	struct cxgb4_uld_queue_map txqs;
};

struct cxgb4_uld_queues_iscsit {
	struct cxgb4_uld_queue_map txqs;
};

struct cxgb4_uld_queues_nvmeh {
	struct cxgb4_uld_queue_map txqs;
};

struct cxgb4_uld_queues_nvmet {
	struct cxgb4_uld_queue_map txqs;
};

struct cxgb4_uld_queues_cstor {
	struct cxgb4_uld_queue_map txqs;
};

struct cxgb4_uld_queues_crypto {
	struct cxgb4_uld_queue_map shared_txqs;
	struct cxgb4_uld_queue_map txqs;
};

struct cxgb4_uld_queues_chtcp {
	struct cxgb4_uld_queue_map txqs;
};

struct cxgb4_uld_queue_info {
	struct cxgb4_uld_queues_toe toeqs;
	struct cxgb4_uld_queues_rdma rdmaqs;
	struct cxgb4_uld_queues_iscsi iscsiqs;
	struct cxgb4_uld_queues_iscsit iscsitqs;
	struct cxgb4_uld_queues_nvmeh nvmehqs;
	struct cxgb4_uld_queues_nvmet nvmetqs;
	struct cxgb4_uld_queues_cstor cstorqs;
	struct cxgb4_uld_queues_crypto cryptoqs;
	struct cxgb4_uld_queues_chtcp chtcpqs;
};

struct cxgb4_uld_sendpath_res {
	struct ida qp_ida;
};

struct cxgb4_uld_resources {
	struct cxgb4_uld_sendpath_res sendpath_res;
};

struct cxgb4_uld {
	struct mutex uld_mutex; /* Used to sync access to ULD data */
	struct cxgb4_uld_queue_info qinfo[NCHAN];
	struct cxgb4_virt_res vres;
	struct cxgb4_uld_resources res;
	void *iscsi_ppm;
	void *rdma_resource;
	void *cnvme_ddp;
	struct gen_pool *ocqp_pool;
	unsigned long oc_mw_pa;
	void __iomem *oc_mw_kva;
	struct srq_data *srq;
#ifdef CONFIG_PO_FCOE
	u8 *ppod_map;
	u16 *tid2xid;
	spinlock_t ppod_map_lock;	/* page pod map lock */
#endif /* CONFIG_PO_FCOE */
	struct cxgb4_uld_stats stats;
};

unsigned int cxgb4_uld_atid_in_use(struct net_device *dev);
void *cxgb4_uld_atid_lookup(struct net_device *dev, u32 atid);
int cxgb4_uld_atid_alloc(struct net_device *dev, void *data);
void cxgb4_uld_atid_free(struct net_device *dev, u32 atid);

u32 cxgb4_uld_tid_in_use(struct net_device *dev);
bool cxgb4_uld_tid_out_of_range(struct net_device *dev, u32 tid);
void *cxgb4_uld_tid_lookup(struct net_device *dev, u32 tid);
int cxgb4_uld_tid_insert(struct net_device *dev, u16 family, u32 tid,
			 void *data);
void cxgb4_uld_tid_remove(struct net_device *dev, u8 chan, u16 family, u32 tid);

void *cxgb4_uld_stid_lookup(struct net_device *dev, u32 stid);
int cxgb4_uld_stid_alloc(struct net_device *dev, u16 family, void *data);
int cxgb4_uld_sftid_alloc(struct net_device *dev, u16 family, void *data);
void cxgb4_uld_stid_free(struct net_device *dev, u16 family, u32 stid);

void *cxgb4_uld_uotid_lookup(struct net_device *dev, u32 uotid);
int cxgb4_uld_uotid_alloc(struct net_device *dev, void *data);
void cxgb4_uld_uotid_free(struct net_device *dev, u32 uotid);

int cxgb4_uld_server_create(const struct net_device *dev, unsigned int stid,
			    __be32 sip, __be16 sport, __be16 vlan,
			    unsigned int queue, const u8 *tx_chan);
int cxgb4_uld_server6_create(const struct net_device *dev, unsigned int stid,
			     const struct in6_addr *sip, __be16 sport,
			     __be16 vlan, unsigned int queue,
			     const u8 *tx_chan);

int __cxgb4_uld_server_remove(const struct net_device *dev, unsigned int stid,
			      unsigned int queue, bool ipv6, struct sk_buff *skb);
int cxgb4_uld_server_remove(const struct net_device *dev, unsigned int stid,
			    unsigned int queue, bool ipv6);

void cxgb4_uld_tid_qid_sel_update(struct net_device *dev,
				  enum cxgb4_uld_type uld, u32 tid, u16 *qid);

bool cxgb4_uld_sendpath_enabled(struct adapter *adap);
void cxgb4_uld_sendpath_qp_free(struct net_device *dev, unsigned int index);
int cxgb4_uld_sendpath_qp_alloc(struct net_device *dev);
struct cxgb4_uld_queue_map *cxgb4_uld_queues_txq_map_get(struct net_device *dev,
							 enum cxgb4_uld_txq_type qtype,
							 enum cxgb4_uld_type uld);
void cxgb4_uld_txq_purge(struct net_device *dev, enum cxgb4_uld_type uld,
			 struct cxgb4_uld_txq_info *info);
void cxgb4_uld_txq_free(struct net_device *dev, enum cxgb4_uld_type uld,
			struct cxgb4_uld_txq_info *info);
int cxgb4_uld_txq_alloc(struct net_device *dev, enum cxgb4_uld_type uld,
			struct cxgb4_uld_txq_info *info);
int cxgb4_uld_xmit(struct net_device *dev, struct sk_buff *skb);
int cxgb4_uld_xmit_direct(struct net_device *dev, bool control,
			  unsigned int index, const void *data,
			  unsigned int len);
void cxgb4_uld_txq_cidx_update(struct net_device *dev, u32 index, u16 cidx);
bool cxgb4_uld_txq_full(struct net_device *dev, unsigned int index);
void cxgb4_uld_txq_all_stop(struct adapter *adap);
void cxgb4_uld_txq_all_start(struct adapter *adap);
void cxgb4_uld_txq_all_disable_dbs(struct adapter *adap);
void cxgb4_uld_txq_all_enable_dbs(struct adapter *adap);
void cxgb4_uld_txq_all_recover(struct adapter *adap);
int cxgb4_uld_txq_sync_pidx(struct net_device *dev, u16 qid, u16 pidx,
			    u16 size);
struct cxgb4_uld_txq *cxgb4_uld_txq_get_by_qid(struct net_device *dev,
					       enum cxgb4_uld_type uld,
					       u32 qid);
int cxgb4_uld_txq_get_desc(struct adapter *adap, enum cxgb4_uld_type uld,
			   u32 qid, void *data, u32 off, u32 len);
void cxgb4_uld_txq_free_shared(struct adapter *adap, enum cxgb4_uld_type uld);
void cxgb4_uld_txq_alloc_shared(struct adapter *adap, enum cxgb4_uld_type uld);

void cxgb4_uld_queues_cleanup(struct adapter *adap);
void cxgb4_uld_queues_init(struct adapter *adap);

bool cxgb4_uld_crypto_supported_ulp_tls(const struct net_device *dev);

bool cxgb4_uld_supported_any(struct adapter *adap);
bool cxgb4_uld_supported(struct adapter *adap, enum cxgb4_uld_type uld);
const char *cxgb4_uld_type_to_name(enum cxgb4_uld_type uld);
void cxgb4_uld_cleanup(struct adapter *adap);
int cxgb4_uld_init(struct adapter *adap,
		   const struct fw_caps_config_cmd *caps_cmd);
#endif /* __CXGB4_ULD_H__ */
