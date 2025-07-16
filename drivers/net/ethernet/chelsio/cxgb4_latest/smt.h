/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2008-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Kumar Sanghvi (kumaras@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/* Heavily derived from l2t.h */

#ifndef __CXGB4_SMT_H
#define __CXGB4_SMT_H

#include <linux/spinlock.h>
#include <linux/if_ether.h>
#include <asm/atomic.h>
#include "cxgb4_ctl_defs.h"

struct adapter;
struct file_operations;
struct cpl_smt_write_rpl;


/*
 * SMT related handling. Heavily adapted based on l2t ops in l2t.h/l2t.c
 */
enum {
	SMT_STATE_SWITCHING,
	SMT_STATE_UNUSED,
	SMT_STATE_ERROR
};

enum {
	SMT_SIZE = 256
};

struct smt_entry {
	u16 state;
	u16 idx;
	u16 pfvf;
	u16 hw_idx;
	u8 src_mac[ETH_ALEN];
	atomic_t refcnt;
	spinlock_t lock;
};

struct smt_data {
	unsigned int smt_size;
	unsigned int smt_start;
	rwlock_t lock;
	struct smt_entry smtab[];
};

struct smt_data *t4_init_smt(u32, u32);
int write_ofld_smt(struct net_device *dev, unsigned int tid, u8 vi_vld);
struct smt_entry *cxgb4_smt_alloc_switching(struct net_device *dev, u8 *smac);
struct smt_entry *cxgb4_lookup_smte(struct net_device *dev, u8 *smac);
void cxgb4_smt_release(struct smt_entry *e);
void do_smt_write_rpl(struct adapter *p, const struct cpl_smt_write_rpl *rpl);
extern const struct file_operations t4_smt_debugfs_fops;
#endif  /* __CXGB4_SMT_H */
