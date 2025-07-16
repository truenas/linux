/*
 * This file is part of the Chelsio T4 Ethernet driver for Linux.
 *
 * Copyright (C) 2015-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Santosh Rastapur (santosh@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/* Heavily derived from smt.h */

#ifndef __CXGB4_SRQ_H
#define __CXGB4_SRQ_H

#include <linux/spinlock.h>
#include <linux/if_ether.h>
#include <linux/completion.h>
#include "cxgb4_ctl_defs.h"

struct adapter;
struct file_operations;
struct cpl_srq_table_rpl;

enum {
	SRQ_WAIT_TO = (HZ * 5),
};

struct srq_entry {
	u8 valid;
	u8 idx;
	u8 qlen;
	u16 pdid;
	u16 cur_msn;
	u16 max_msn;
	u32 qbase;
};

struct srq_data {
	unsigned int srq_size;
	struct completion comp;
	int rpl_count;
	struct srq_entry srqtab[];
};

int cxgb4_srq_init(struct adapter *adap, u32 srq_size);
void cxgb4_srq_cleanup(struct adapter *adap);
void do_srq_table_rpl(struct adapter *adap, const struct cpl_srq_table_rpl *rpl);
extern const struct file_operations t4_srq_debugfs_fops;
#endif  /* __CXGB4_SRQ_H */

