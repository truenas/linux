/*
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef _CXGB4_OFLD_CTL_DEFS_H
#define _CXGB4_OFLD_CTL_DEFS_H

#include <linux/types.h>

enum {
	GET_MAX_OUTSTANDING_WR = 0,
	GET_TX_MAX_CHUNK       = 1,
	GET_MTUS               = 6,
	GET_WR_LEN             = 7,
	GET_DDP_PARAMS         = 9,

	ULP_ISCSI_GET_PARAMS   = 10,
	ULP_ISCSI_SET_PARAMS   = 11,

	RDMA_GET_PARAMS        = 12,
	RDMA_CQ_OP             = 13,
	RDMA_CQ_SETUP          = 14,
	RDMA_CQ_DISABLE        = 15,

	GET_PORT_SCHED         = 21,
	GET_NUM_QUEUES         = 22,
	GET_CHAN_MAP	       = 23,
	GET_PORT_ARRAY         = 24,

	FAILOVER		= 30,
	FAILOVER_DONE		= 31,
	FAILOVER_CLEAR		= 32,
	FAILOVER_ACTIVE_SLAVE	= 33,
	FAILOVER_PORT_DOWN	= 34,
	FAILOVER_PORT_UP	= 35,
	FAILOVER_PORT_RELEASE	= 36,
	FAILOVER_BOND_DOWN	= 38,
	FAILOVER_BOND_UP	= 39,
};

/*
 * Structure used to describe a TID range.  Valid TIDs are [base, base+num).
 */
struct tid_range {
	unsigned int base;   /* first TID */
	unsigned int num;    /* number of TIDs in range */
};

/*
 * Structure used to request the size and contents of the MTU table.
 */
struct mtutab {
	unsigned int size;          /* # of entries in the MTU table */
	const unsigned short *mtus; /* the MTU table values */
};

struct adap_ports {
	unsigned int nports;          /* number of ports on this adapter */
	struct net_device *lldevs[4]; /* Max number of ports is 4 */
};

struct port_array {
        unsigned int nports;          /* number of ports on this adapter */
        struct net_device **lldevs;   /* points to array of net_devices */
};

struct net_device;

/* Structure used to request a port's offload scheduler */
struct port_sched {
	struct net_device *dev;          /* the net_device */
	int sched;                       /* associated scheduler */
};

struct bond_ports {
	unsigned int port;
	unsigned int nports;            /* number of ports on this adapter */
	unsigned int ports[4];          /* Max number of ports is 4 */
	struct net_device *slave_dev;	/* Corresponding net_dev */
};

struct pci_dev;

/*
 * Structure used to request the TCP DDP parameters.
 */
struct ddp_params {
	unsigned int llimit;     /* TDDP region start address */
	unsigned int ulimit;     /* TDDP region end address */
	unsigned int tag_mask;   /* TDDP tag mask */
	struct pci_dev *pdev;
};

/*
 * Structure used to return information to the iscsi layer.
 */
struct ulp_iscsi_info {
	unsigned int	offset;
	unsigned int	llimit;
	unsigned int	ulimit;
	unsigned int	tagmask;
	unsigned char	pgsz_factor[4];
	unsigned int	max_rxsz;
	unsigned int	max_txsz;
	struct pci_dev	*pdev;
};

/*
 * Structure used to return information to the RDMA layer.
 */
struct rdma_info {
	unsigned int tpt_base;   /* TPT base address */
	unsigned int tpt_top;	 /* TPT last entry address */
	unsigned int pbl_base;   /* PBL base address */
	unsigned int pbl_top;	 /* PBL last entry address */
	unsigned int rqt_base;   /* RQT base address */
	unsigned int rqt_top;	 /* RQT last entry address */
	unsigned int udbell_len; /* user doorbell region length */
	resource_size_t udbell_physbase; /* user doorbell physical start addr */
	void __iomem *kdb_addr;  /* kernel doorbell register address */
	struct pci_dev *pdev;    /* associated PCI device */
};

/*
 * Structure used to request an operation on an RDMA completion queue.
 */
struct rdma_cq_op {
	unsigned int id;
	unsigned int op;
	unsigned int credits;
};

/*
 * Structure used to setup RDMA completion queues.
 */
struct rdma_cq_setup {
	unsigned int id;
	unsigned long long base_addr;
	unsigned int size;
	unsigned int credits;
	unsigned int credit_thres;
	unsigned int ovfl_mode;
};

struct toedev;

#endif /* _CXGB4_OFLD_CTL_DEFS_H */
