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
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
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

/* Crude resource management */
#include <linux/genalloc.h>
#include "cxgb4_rdma_resource.h"

/*
 * RQT Memory Manager.  Uses Linux generic allocator.
 */

#define T4_RQT_ENTRY_SIZE	(1 << 6)
#define T4_MIN_RQT_SHIFT	10	/* 1KB == min RQT size (16 entries) */

u32 cxgb4_uld_alloc_rqtpool(struct cxgb4_rdma_resource *res, int size)
{
	unsigned long addr = gen_pool_alloc(res->rqt_pool, size << 6);

	pr_debug("addr %#x size %d\n", (u32)addr, size << 6);
	if (!addr)
		pr_warn_ratelimited("Out of RQT memory\n");

	mutex_lock(&res->stats.lock);
	if (addr) {
		res->stats.rqt.cur += roundup(size << 6,
					      1 << T4_MIN_RQT_SHIFT);
		if (res->stats.rqt.cur > res->stats.rqt.max)
			res->stats.rqt.max = res->stats.rqt.cur;
	} else {
		res->stats.rqt.fail++;
	}

	mutex_unlock(&res->stats.lock);

	return (u32)addr;
}
EXPORT_SYMBOL(cxgb4_uld_alloc_rqtpool);

void cxgb4_uld_free_rqtpool(struct cxgb4_rdma_resource *res, u32 addr,
			    int size)
{
	pr_debug("addr %#x size %d\n", addr, size << 6);
	mutex_lock(&res->stats.lock);
	res->stats.rqt.cur -= roundup(size << 6, 1 << T4_MIN_RQT_SHIFT);
	mutex_unlock(&res->stats.lock);
	gen_pool_free(res->rqt_pool, (unsigned long)addr, size << 6);
}
EXPORT_SYMBOL(cxgb4_uld_free_rqtpool);

static int cxgb4_create_rqtpool(struct cxgb4_lld_info *lldi,
				struct cxgb4_rdma_resource *res)
{
	u32 rqt_start, rqt_chunk, rqt_top;
	int skip = 0;

	res->rqt_pool = gen_pool_create(T4_MIN_RQT_SHIFT, -1);
	if (!res->rqt_pool)
		return -ENOMEM;

	/*
	 * IF SRQs are supported, then never use the first RQE from
	 * the RQT region.  This is because HW uses RQT index 0 as NULL.
	 */
	if (lldi->vr->srq.size)
		skip = T4_RQT_ENTRY_SIZE;

	rqt_start = lldi->vr->rq.start + skip;
	rqt_chunk = lldi->vr->rq.size - skip;
	rqt_top = rqt_start + rqt_chunk;

	while (rqt_start < rqt_top) {
		rqt_chunk = min(rqt_top - rqt_start + 1, rqt_chunk);
		if (gen_pool_add(res->rqt_pool, rqt_start, rqt_chunk, -1)) {
			pr_debug("failed to add RQT chunk (%#x/%#x)\n",
				 rqt_start, rqt_chunk);
			if (rqt_chunk <= (1024 << T4_MIN_RQT_SHIFT)) {
				pr_warn("Failed to add all RQT chunks "
					"(%#x/%#x)\n", rqt_start,
					rqt_top - rqt_start);
				return 0;
			}

			rqt_chunk >>= 1;
		} else {
			pr_debug("added RQT chunk (%#x/%#x)\n",
				 rqt_start, rqt_chunk);
			rqt_start += rqt_chunk;
		}
	}

	return 0;
}

static void cxgb4_destroy_rqtpool(struct cxgb4_rdma_resource *res)
{
	gen_pool_destroy(res->rqt_pool);
}

static int cxgb4_init_qid_table(struct cxgb4_id_table *qid_table,
				const struct cxgb4_range *qp, u32 qpmask)
{
	u32 i;

	if (cxgb4_uld_alloc_id_table(qid_table, qp->start,
				     qp->size, qp->size, 0))
		return -ENOMEM;

	for (i = qp->start; i < (qp->start + qp->size); i++)
		if (!(i & qpmask))
			cxgb4_free_id(qid_table, i);

	return 0;
}

/* nr_* must be power of 2 */
struct cxgb4_rdma_resource *cxgb4_uld_init_rdma_resource(struct cxgb4_lld_info *lldi)
{
	struct cxgb4_rdma_resource *res = *lldi->rdma_resource;
	u32 factor;
	int ret;

	if (res) {
		kref_get(&res->kref);
		return res;
	}

	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res)
		return NULL;

	kref_init(&res->kref);
	mutex_init(&res->stats.lock);

	factor = PAGE_SIZE / lldi->sge_host_page_size;
	res->qpmask = (lldi->udb_density * factor) - 1;
	res->cqmask = (lldi->ucq_density * factor) - 1;

	ret = cxgb4_init_qid_table(&res->qid_table, &lldi->vr->qp,
				   res->qpmask);
	if (ret)
		goto qid_err;

	ret = cxgb4_uld_alloc_id_table(&res->pdid_table, 0, T4_MAX_NUM_PD,
				       1, 0);
	if (ret)
		goto pdid_err;

	if (!lldi->vr->srq.size)
		ret = cxgb4_uld_alloc_id_table(&res->srq_table, 0, 1, 1, 0);
	else
		ret = cxgb4_uld_alloc_id_table(&res->srq_table, 0,
					       lldi->vr->srq.size, 0, 0);
	if (ret)
		goto srq_err;

	ret = cxgb4_create_rqtpool(lldi, res);
	if (ret) {
		pr_err("initializing rqtpool failed with err %d\n", ret);
		goto rqt_err;
	}

	res->stats.qid.total = lldi->vr->qp.size;
	res->stats.pd.total = T4_MAX_NUM_PD;
	res->stats.srqt.total = lldi->vr->srq.size;
	res->stats.rqt.total = lldi->vr->rq.size;

	*lldi->rdma_resource = res;
	res->rdma_resource = lldi->rdma_resource;
	return res;
rqt_err:
	cxgb4_uld_free_id_table(&res->srq_table);
srq_err:
	cxgb4_uld_free_id_table(&res->pdid_table);
pdid_err:
	cxgb4_uld_free_id_table(&res->qid_table);
qid_err:
	kfree(res);
	return NULL;
}
EXPORT_SYMBOL(cxgb4_uld_init_rdma_resource);

static void cxgb4_destroy_rdma_resource(struct kref *kref)
{
	struct cxgb4_rdma_resource *res;

	res = container_of(kref, struct cxgb4_rdma_resource, kref);

	cxgb4_destroy_rqtpool(res);
	cxgb4_uld_free_id_table(&res->qid_table);
	cxgb4_uld_free_id_table(&res->pdid_table);
	cxgb4_uld_free_id_table(&res->srq_table);

	*res->rdma_resource = NULL;
	kfree(res);
}

void cxgb4_uld_destroy_rdma_resource(struct cxgb4_rdma_resource *res)
{
	kref_put(&res->kref, cxgb4_destroy_rdma_resource);
}
EXPORT_SYMBOL(cxgb4_uld_destroy_rdma_resource);

/*
 * returns 0 if no resource available
 */
u32 cxgb4_uld_get_resource(struct cxgb4_id_table *id_table)
{
	u32 entry;

	entry = cxgb4_alloc_id(id_table);
	if (entry == UINT_MAX)
		return 0;

	return entry;
}
EXPORT_SYMBOL(cxgb4_uld_get_resource);

void cxgb4_uld_put_resource(struct cxgb4_id_table *id_table, u32 entry)
{
	pr_debug("entry %#x\n", entry);
	cxgb4_free_id(id_table, entry);
}
EXPORT_SYMBOL(cxgb4_uld_put_resource);

u32 cxgb4_uld_get_cqid(struct cxgb4_rdma_resource *res,
		       struct cxgb4_dev_ucontext *uctx)
{
	struct cxgb4_qid_list *entry;
	u32 qid;
	int i;

	mutex_lock(&uctx->lock);
	if (!list_empty(&uctx->cqids)) {
		entry = list_entry(uctx->cqids.next, struct cxgb4_qid_list,
				   entry);
		list_del(&entry->entry);
		qid = entry->qid;
		kfree(entry);
	} else {
		qid = cxgb4_uld_get_resource(&res->qid_table);
		if (!qid) {
			mutex_lock(&res->stats.lock);
			res->stats.qid.fail++;
			mutex_unlock(&res->stats.lock);
			goto out;
		}

		mutex_lock(&res->stats.lock);
		res->stats.qid.cur += res->qpmask + 1;
		mutex_unlock(&res->stats.lock);
		for (i = qid + 1; i & res->qpmask; i++) {
			entry = kmalloc(sizeof(*entry), GFP_KERNEL);
			if (!entry)
				goto out;

			entry->qid = i;
			list_add_tail(&entry->entry, &uctx->cqids);
		}

		/*
		 * now put the same ids on the qp list since they all
		 * map to the same db/gts page.
		 */
		entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry)
			goto out;

		entry->qid = qid;
		list_add_tail(&entry->entry, &uctx->qpids);
		for (i = qid + 1; i & res->qpmask; i++) {
			entry = kmalloc(sizeof(*entry), GFP_KERNEL);
			if (!entry)
				goto out;

			entry->qid = i;
			list_add_tail(&entry->entry, &uctx->qpids);
		}
	}
out:
	mutex_unlock(&uctx->lock);
	mutex_lock(&res->stats.lock);
	if (res->stats.qid.cur > res->stats.qid.max)
		res->stats.qid.max = res->stats.qid.cur;
	mutex_unlock(&res->stats.lock);

	pr_debug("qid %#x\n", qid);
	return qid;
}
EXPORT_SYMBOL(cxgb4_uld_get_cqid);

void cxgb4_uld_put_cqid(struct cxgb4_dev_ucontext *uctx, u32 qid)
{
	struct cxgb4_qid_list *entry;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;

	pr_debug("qid %#x\n", qid);
	entry->qid = qid;

	mutex_lock(&uctx->lock);
	list_add_tail(&entry->entry, &uctx->cqids);
	mutex_unlock(&uctx->lock);
}
EXPORT_SYMBOL(cxgb4_uld_put_cqid);

u32 cxgb4_uld_get_qpid(struct cxgb4_rdma_resource *res,
		       struct cxgb4_dev_ucontext *uctx)
{
	struct cxgb4_qid_list *entry;
	u32 qid, i;

	mutex_lock(&uctx->lock);
	if (!list_empty(&uctx->qpids)) {
		entry = list_entry(uctx->qpids.next, struct cxgb4_qid_list,
				   entry);
		list_del(&entry->entry);
		qid = entry->qid;
		kfree(entry);
	} else {
		qid = cxgb4_uld_get_resource(&res->qid_table);
		if (!qid) {
			mutex_lock(&res->stats.lock);
			res->stats.qid.fail++;
			mutex_unlock(&res->stats.lock);
			goto out;
		}

		mutex_lock(&res->stats.lock);
		res->stats.qid.cur += res->qpmask + 1;
		mutex_unlock(&res->stats.lock);
		for (i = qid + 1; i & res->qpmask; i++) {
			entry = kmalloc(sizeof(*entry), GFP_KERNEL);
			if (!entry)
				goto out;

			entry->qid = i;
			list_add_tail(&entry->entry, &uctx->qpids);
		}

		/*
		 * now put the same ids on the cq list since they all
		 * map to the same db/gts page.
		 */
		entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry)
			goto out;

		entry->qid = qid;
		list_add_tail(&entry->entry, &uctx->cqids);
		for (i = qid + 1; i & res->qpmask; i++) {
			entry = kmalloc(sizeof(*entry), GFP_KERNEL);
			if (!entry)
				goto out;

			entry->qid = i;
			list_add_tail(&entry->entry, &uctx->cqids);
		}
	}
out:
	mutex_unlock(&uctx->lock);
	mutex_lock(&res->stats.lock);
	if (res->stats.qid.cur > res->stats.qid.max)
		res->stats.qid.max = res->stats.qid.cur;
	mutex_unlock(&res->stats.lock);

	pr_debug("qid %#x\n", qid);
	return qid;
}
EXPORT_SYMBOL(cxgb4_uld_get_qpid);

void cxgb4_uld_put_qpid(struct cxgb4_dev_ucontext *uctx, u32 qid)
{
	struct cxgb4_qid_list *entry;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;

	pr_debug("qid %#x\n", qid);
	entry->qid = qid;

	mutex_lock(&uctx->lock);
	list_add_tail(&entry->entry, &uctx->qpids);
	mutex_unlock(&uctx->lock);
}
EXPORT_SYMBOL(cxgb4_uld_put_qpid);

void cxgb4_uld_release_dev_ucontext(struct cxgb4_rdma_resource *res,
				    struct cxgb4_dev_ucontext *uctx)
{
	struct list_head *pos, *nxt;
	struct cxgb4_qid_list *entry;

	mutex_lock(&uctx->lock);
	list_for_each_safe(pos, nxt, &uctx->qpids) {
		entry = list_entry(pos, struct cxgb4_qid_list, entry);
		list_del_init(&entry->entry);
		if (!(entry->qid & res->qpmask)) {
			cxgb4_uld_put_resource(&res->qid_table, entry->qid);
			mutex_lock(&res->stats.lock);
			res->stats.qid.cur -= res->qpmask + 1;
			mutex_unlock(&res->stats.lock);
		}

		kfree(entry);
	}

	list_for_each_safe(pos, nxt, &uctx->cqids) {
		entry = list_entry(pos, struct cxgb4_qid_list, entry);
		list_del_init(&entry->entry);
		kfree(entry);
	}
	mutex_unlock(&uctx->lock);
}
EXPORT_SYMBOL(cxgb4_uld_release_dev_ucontext);

void cxgb4_uld_init_dev_ucontext(struct cxgb4_dev_ucontext *uctx)
{
	INIT_LIST_HEAD(&uctx->qpids);
	INIT_LIST_HEAD(&uctx->cqids);
	mutex_init(&uctx->lock);
}
EXPORT_SYMBOL(cxgb4_uld_init_dev_ucontext);

int cxgb4_uld_get_pdid(struct cxgb4_rdma_resource *res)
{
	u32 pdid = cxgb4_uld_get_resource(&res->pdid_table);

	mutex_lock(&res->stats.lock);
	if (!pdid) {
		res->stats.pd.fail++;
		mutex_unlock(&res->stats.lock);
		return 0;
	}

	res->stats.pd.cur++;
	if (res->stats.pd.cur > res->stats.pd.max)
		res->stats.pd.max = res->stats.pd.cur;
	mutex_unlock(&res->stats.lock);

	return pdid;
}
EXPORT_SYMBOL(cxgb4_uld_get_pdid);

void cxgb4_uld_put_pdid(struct cxgb4_rdma_resource *res, int pdid)
{
	cxgb4_uld_put_resource(&res->pdid_table, pdid);
	mutex_lock(&res->stats.lock);
	res->stats.pd.cur--;
	mutex_unlock(&res->stats.lock);
}
EXPORT_SYMBOL(cxgb4_uld_put_pdid);

int cxgb4_uld_alloc_srq_idx(struct cxgb4_rdma_resource *res)
{
	u32 idx = cxgb4_alloc_id(&res->srq_table);

	mutex_lock(&res->stats.lock);
	if (idx == UINT_MAX) {
		res->stats.srqt.fail++;
		mutex_unlock(&res->stats.lock);
		return -ENOMEM;
	}

	res->stats.srqt.cur++;
	if (res->stats.srqt.cur > res->stats.srqt.max)
		res->stats.srqt.max = res->stats.srqt.cur;
	mutex_unlock(&res->stats.lock);

	return idx;
}
EXPORT_SYMBOL(cxgb4_uld_alloc_srq_idx);

void cxgb4_uld_free_srq_idx(struct cxgb4_rdma_resource *res, int idx)
{
	cxgb4_free_id(&res->srq_table, idx);
	mutex_lock(&res->stats.lock);
	res->stats.srqt.cur--;
	mutex_unlock(&res->stats.lock);
}
EXPORT_SYMBOL(cxgb4_uld_free_srq_idx);
