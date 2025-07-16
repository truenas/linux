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

#ifndef __CXGB4_FILTER_H__
#define __CXGB4_FILTER_H__

#ifdef CONFIG_NUMA
#include <linux/vmalloc.h>
#endif

#define CXGB4_FILTER_ID_ANY UINT_MAX

extern unsigned int use_ddr_filters;
extern int user_filter_perc;

struct filter_ehash_bucket {
	struct hlist_nulls_head chain;
};

struct filter_hashinfo {
	struct filter_ehash_bucket *ehash;
	spinlock_t *ehash_filter_locks; /* Lock to access ehash table */
	unsigned int ehash_mask;
	unsigned int ehash_filter_locks_mask;
};

/* Filter operation context to allow callers of cxgb_set_filter() and
 * cxgb_del_filter() to wait for an asynchronous completion.
 */
struct filter_ctx {
	struct completion completion;	/* completion rendezvous */
	void *closure;			/* caller's opaque information */
	int result;			/* result of operation */
	u32 tid;			/* to store tid of hash filter */
};

/* Host shadow copy of ingress filter entry.  This is in host native format
 * and doesn't match the ordering or bit order, etc. of the hardware or the
 * firmware command.
 */
struct filter_entry {
	/*
	 * Administrative fields for filter.
	 */
	u32 valid:1;            /* filter allocated and valid */
	u32 locked:1;           /* filter is administratively locked */
	u32 pending:1;          /* filter action is pending firmware reply */
	u32 smtidx:8;           /* Source MAC Table index for smac */
	struct filter_ctx *ctx; /* caller's completion hook */
	struct l2t_entry *l2t;  /* Layer Two Table entry for dmac */
	struct smt_entry *smt;  /* Source Mac Table entry for smac */
	struct net_device *dev;
	/* This will store the actual tid */
	u32 tid;
	unsigned int filter_hash;
	struct hlist_nulls_node filter_nulls_node;
	u64 pkt_counter;
	u64 byte_counter;

	/*
	 * The filter itself.  Most of this is a straight copy of information
	 * provided by the extended ioctl().  Some fields are translated to
	 * internal forms -- for instance the Ingress Queue ID passed in from
	 * the ioctl() is translated into the Absolute Ingress Queue ID.
	 */
	struct ch_filter_specification fs;
};

#define WORD_MASK       0xffffffff

static inline void ehash_filter_locks_free(struct filter_hashinfo *hashinfo)
{
	if (hashinfo->ehash_filter_locks) {
#ifdef CONFIG_NUMA
		unsigned int size = (hashinfo->ehash_filter_locks_mask + 1) *
			sizeof(spinlock_t);
		if (size > PAGE_SIZE)
			vfree(hashinfo->ehash_filter_locks);
		else
#endif
		kfree(hashinfo->ehash_filter_locks);
		hashinfo->ehash_filter_locks = NULL;
	}
}

struct cpl_set_tcb_rpl;
struct cpl_act_open_rpl;
struct cpl_abort_rpl_rss;

unsigned int cxgb4_filter_num_tids(struct adapter *adap);

void cxgb4_filter_normal_rpl(struct adapter *adap,
			     const struct cpl_set_tcb_rpl *rpl);

#ifndef INET_HASHFN
unsigned int inet_ehashfn(struct net *net, const __be32 laddr,
			  const __u16 lport, const __be32 faddr,
			  const __be16 fport);
#endif
unsigned int t4_inet6_ehashfn(struct net *net, const struct in6_addr *laddr,
			      const u16 lport, const struct in6_addr *faddr,
			      const __be16 fport);
void cxgb4_filter_hash_create_rpl(struct adapter *adap,
				  const struct cpl_act_open_rpl *rpl);
void cxgb4_filter_hash_delete_rpl(struct adapter *adap,
				  const struct cpl_abort_rpl_rss *rpl);

int cxgb4_filter_create(struct net_device *dev, u32 filter_id,
			struct ch_filter_specification *fs,
			struct filter_ctx *ctx, gfp_t flags);
int cxgb4_filter_normal_create(struct net_device *dev, u32 filter_id,
				struct ch_filter_specification *fs,
				struct filter_ctx *ctx, gfp_t flags);
int cxgb4_filter_delete(struct net_device *dev, u32 filter_id,
			struct ch_filter_specification *fs,
			struct filter_ctx *ctx, gfp_t flags);

int cxgb4_filter_get_count(struct adapter *adapter, unsigned int fidx,
			   u64 *c, int hash, bool get_byte);
int cxgb4_filter_get_counters(struct net_device *dev, unsigned int fidx,
			      u64 *hitcnt, u64 *bytecnt, int hash);

void cxgb4_filter_clear_all(struct adapter *adapter);
void cxgb4_flush_all_filters(struct adapter *adapter, gfp_t flags);

int cxgb4_hash_filter_config_verify(struct adapter *adap, bool offload_caps);
int cxgb4_hash_filter_init(struct adapter *adap);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
int cxgb4_uld_filter_create(struct net_device *dev, u32 filter_id,
			    struct ch_filter_specification *fs,
			    struct filter_ctx *ctx, gfp_t flags);
int cxgb4_uld_filter_delete(struct net_device *dev, u32 filter_id,
			    struct ch_filter_specification *fs,
			    struct filter_ctx *ctx, gfp_t flags);
int cxgb4_uld_server_filter_insert(const struct net_device *dev, u32 stid,
				   __be32 sip, __be16 sport, __be16 vlan,
				   u32 queue, u8 port, u8 port_mask);
int cxgb4_uld_server_filter_remove(const struct net_device *dev, u32 stid);
int cxgb4_uld_create_filter_info(const struct net_device *dev,
				 u64 *filter_value, u64 *filter_mask,
				 int fcoe, int port, int vnic,
				 int vlan, int vlan_pcp, int vlan_dei,
				 int tos, int protocol, int ethertype,
				 int macmatch, int matchtype, int frag);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

extern const struct file_operations filters_debugfs_fops;
extern const struct file_operations hash_filters_debugfs_fops;
#endif /* __CXGB4_FILTER_H__ */
