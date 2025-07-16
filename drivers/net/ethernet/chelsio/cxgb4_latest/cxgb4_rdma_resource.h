/*
 * Copyright (c) 2009-2025 Chelsio, Inc. All rights reserved.
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

#ifndef __CXGB4_RDMA_RESOURCE_H__
#define __CXGB4_RDMA_RESOURCE_H__
#include "common.h"
#include "cxgb4_ofld.h"

#define CXGB4_ID_TABLE_F_RANDOM 1	/* Pseudo-randomize the id's returned */
#define CXGB4_ID_TABLE_F_EMPTY  2	/* Table is initially empty */
#define T4_MAX_NUM_PD 65536

struct cxgb4_id_table {
	unsigned long *table;
	spinlock_t lock;
	u32 flags;
	u32 start;	/* logical minimal id */
	u32 last;	/* hint for find */
	u32 max;
};

struct cxgb4_qid_list {
	struct list_head entry;
	u32 qid;
};

struct cxgb4_dev_ucontext {
	struct list_head qpids;
	struct list_head cqids;
	struct mutex lock;
};

struct cxgb4_rdma_stat {
	u64 total;
	u64 cur;
	u64 max;
	u64 fail;
};

struct cxgb4_rdma_stats {
	struct cxgb4_rdma_stat qid;
	struct cxgb4_rdma_stat pd;
	struct cxgb4_rdma_stat srqt;
	struct cxgb4_rdma_stat rqt;
	struct mutex lock;
};

struct cxgb4_rdma_resource {
	struct cxgb4_id_table qid_table;
	struct cxgb4_id_table pdid_table;
	struct cxgb4_id_table srq_table;
	struct gen_pool *rqt_pool;
	struct cxgb4_rdma_stats stats;
	void **rdma_resource;
	struct kref kref;
	u32 qpmask;
	u32 cqmask;
};

u32 cxgb4_alloc_id(struct cxgb4_id_table *alloc);
void cxgb4_free_id(struct cxgb4_id_table *alloc, u32 obj);
int cxgb4_uld_alloc_id_table(struct cxgb4_id_table *alloc, u32 start, u32 num,
			     u32 reserved, u32 flags);
void cxgb4_uld_free_id_table(struct cxgb4_id_table *alloc);

u32 cxgb4_uld_get_resource(struct cxgb4_id_table *id_table);
void cxgb4_uld_put_resource(struct cxgb4_id_table *id_table, u32 entry);
struct cxgb4_rdma_resource *cxgb4_uld_init_rdma_resource(struct cxgb4_lld_info *lldi);
void cxgb4_uld_destroy_rdma_resource(struct cxgb4_rdma_resource *res);

u32 cxgb4_uld_get_cqid(struct cxgb4_rdma_resource *res,
		       struct cxgb4_dev_ucontext *uctx);
void cxgb4_uld_put_cqid(struct cxgb4_dev_ucontext *uctx, u32 qid);
u32 cxgb4_uld_get_qpid(struct cxgb4_rdma_resource *res,
		       struct cxgb4_dev_ucontext *uctx);
void cxgb4_uld_put_qpid(struct cxgb4_dev_ucontext *uctx, u32 qid);
void cxgb4_uld_release_dev_ucontext(struct cxgb4_rdma_resource *res,
				    struct cxgb4_dev_ucontext *uctx);
void cxgb4_uld_init_dev_ucontext(struct cxgb4_dev_ucontext *uctx);

int cxgb4_uld_get_pdid(struct cxgb4_rdma_resource *res);
void cxgb4_uld_put_pdid(struct cxgb4_rdma_resource *res, int pdid);

int cxgb4_uld_alloc_srq_idx(struct cxgb4_rdma_resource *res);
void cxgb4_uld_free_srq_idx(struct cxgb4_rdma_resource *res, int idx);

u32 cxgb4_uld_alloc_rqtpool(struct cxgb4_rdma_resource *res, int size);
void cxgb4_uld_free_rqtpool(struct cxgb4_rdma_resource *res, u32 addr,
			    int size);
#endif /* __CXGB4_RDMA_RESOURCE_H__ */
