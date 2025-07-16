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

#ifndef __CXGB4_FCOE_H__
#define __CXGB4_FCOE_H__

#ifdef CONFIG_PO_FCOE

#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/io.h>
#include "t4_regs_values.h"

#define CXGB_FCOE_TXPKT_CSUM_START	28
#define CXGB_FCOE_TXPKT_CSUM_END	8

#define CXGB_FCOE_ATID		13
#define CXGB_FCOE_GET_XID(x)	((x) & 0x3FF)

#define CXGB_FCOE_SHIFT_PORTID	11
#define CXGB_FCOE_MASK_PORTID	0x3
#define CXGB_FCOE_GET_PORTID(x)	\
	(((x) >> CXGB_FCOE_SHIFT_PORTID) & CXGB_FCOE_MASK_PORTID)

/* # of sentinel invalid page pods at the end of a group of valid page pods */
#define CXGB_FCOE_NUM_SENTINEL_PPODS	0

#define CXGB_FCOE_PPOD_SIZE		sizeof(struct pagepod)

#define CXGB_FCOE_MAX_XCHGS_PORT	1024	/* Per netdev */
#define CXGB_FCOE_MAX_PAGE_CNT		((10 * 1024 * 1024) / PAGE_SIZE)

/* ddp flags */
enum {
	CXGB_FCOE_DDP_ERROR     = (1 << 0),
	CXGB_FCOE_DDP_TID_VALID = (1 << 1),
};

struct cxgb_fcoe_ddp {
	unsigned int sgc;
	struct scatterlist *sgl;
	int ddp_len;
	unsigned int tid;
	unsigned int nppods;
	unsigned int npages;
	unsigned int ppod_tag;
	unsigned int first_pg_off;
	unsigned int xfer_len;
	u16 vlan_tci;
	u16 xid;
	u8 h_source[ETH_ALEN];
	u8 h_dest[ETH_ALEN];
	u8 d_id[3];
	u8 flags;
	dma_addr_t *ppod_gl;
};

/* fcoe flags */
enum {
	CXGB_FCOE_ENABLED     = (1 << 0),
};

struct cxgb_fcoe {
	u8	flags;
	struct completion *cmpl;
	struct	cxgb_fcoe_ddp ddp[CXGB_FCOE_MAX_XCHGS_PORT];
};

struct sge;
struct sge_eth_rxq;
struct port_info;
struct sge_rspq;

int cxgb_fcoe_rx_handler(struct sge_rspq *, const __be64 *);
void cxgb_fcoe_free_ppods(struct adapter *, unsigned int, unsigned int);
int cxgb_fcoe_ddp_setup(struct net_device *netdev, u16 xid,
			struct scatterlist *sgl, unsigned int);
int cxgb_fcoe_ddp_done(struct net_device *netdev, u16 xid);
int cxgb_fcoe_enable(struct net_device *netdev);
int cxgb_fcoe_disable(struct net_device *netdev);
void cxgb_fcoe_init_ddp(struct adapter *);
void cxgb_fcoe_exit_ddp(struct adapter *);
void cxgb_fcoe_cpl_act_open_rpl(struct adapter *, unsigned int,
				unsigned int, unsigned int);
bool cxgb_fcoe_sof_eof_supported(struct adapter *, struct sk_buff *);
#endif /* CONFIG_PO_FCOE */
#endif /* __CXGB4_FCOE_H__ */
