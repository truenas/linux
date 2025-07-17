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
#include <linux/spinlock.h>
#include <linux/genalloc.h>
#include "iw_cxgb4.h"

/* nr_* must be power of 2 */
int chrd_init_resource(struct chrd_rdev *rdev, u32 nr_tpt)
{
	int err = 0;
	err = cxgb4_uld_alloc_id_table(&rdev->resource.tpt_table, 0, nr_tpt, 1,
				       CXGB4_ID_TABLE_F_RANDOM);
        if (err)
                goto tpt_err;

	rdev->rdma_res = cxgb4_uld_init_rdma_resource(&rdev->lldi);
	if (!rdev->rdma_res)
		goto resource_err;

        return 0;
 resource_err:
	cxgb4_uld_free_id_table(&rdev->resource.tpt_table);
 tpt_err:
        return -ENOMEM;
}

void chrd_destroy_resource(struct chrd_rdev *rdev)
{
	cxgb4_uld_free_id_table(&rdev->resource.tpt_table);
	cxgb4_uld_destroy_rdma_resource(rdev->rdma_res);
}

/*
 * PBL Memory Manager.  Uses Linux generic allocator.
 */

#define MIN_PBL_SHIFT 5			/* 32B == min PBL size (4 entries) */

u32 chrd_pblpool_alloc(struct chrd_rdev *rdev, int size)
{
	unsigned long addr = gen_pool_alloc(rdev->pbl_pool, size);
	pr_debug("addr 0x%x size %d\n", (u32)addr, size);
	mutex_lock(&rdev->stats.lock);
	if (addr) {
		rdev->stats.pbl.cur += roundup(size, 1 << MIN_PBL_SHIFT);
		if (rdev->stats.pbl.cur > rdev->stats.pbl.max)
			rdev->stats.pbl.max = rdev->stats.pbl.cur;
		kref_get(&rdev->pbl_kref);
	} else
		rdev->stats.pbl.fail++;
	mutex_unlock(&rdev->stats.lock);
	return (u32)addr;
}

static void destroy_pblpool(struct kref *kref)
{
	struct chrd_rdev *rdev;

	rdev = container_of(kref, struct chrd_rdev, pbl_kref);
	gen_pool_destroy(rdev->pbl_pool);
	complete(&rdev->pbl_compl);
}

void chrd_pblpool_free(struct chrd_rdev *rdev, u32 addr, int size)
{
	pr_debug("addr 0x%x size %d\n", addr, size);
	mutex_lock(&rdev->stats.lock);
	rdev->stats.pbl.cur -= roundup(size, 1 << MIN_PBL_SHIFT);
	mutex_unlock(&rdev->stats.lock);
	gen_pool_free(rdev->pbl_pool, (unsigned long)addr, size);
	kref_put(&rdev->pbl_kref, destroy_pblpool);
}

int chrd_pblpool_create(struct chrd_rdev *rdev)
{
	unsigned pbl_start, pbl_chunk, pbl_top;

	rdev->pbl_pool = gen_pool_create(MIN_PBL_SHIFT, -1);
	if (!rdev->pbl_pool)
		return -ENOMEM;

	pbl_start = rdev->lldi.vr->pbl.start;
	pbl_chunk = rdev->lldi.vr->pbl.size;
	pbl_top = pbl_start + pbl_chunk;

	while (pbl_start < pbl_top) {
		pbl_chunk = min(pbl_top - pbl_start + 1, pbl_chunk);
		if (gen_pool_add(rdev->pbl_pool, pbl_start, pbl_chunk, -1)) {
			pr_debug("failed to add PBL chunk (%x/%x)\n",
				 pbl_start, pbl_chunk);
			if (pbl_chunk <= 1024 << MIN_PBL_SHIFT) {
				pr_warn("Failed to add all PBL chunks (%x/%x)\n",
					pbl_start, pbl_top - pbl_start);
				return 0;
			}
			pbl_chunk >>= 1;
		} else {
			pr_debug("added PBL chunk (%x/%x)\n",
				 pbl_start, pbl_chunk);
			pbl_start += pbl_chunk;
		}
	}
	return 0;
}

void chrd_pblpool_destroy(struct chrd_rdev *rdev)
{
	kref_put(&rdev->pbl_kref, destroy_pblpool);
}

#define MIN_RRQT_SHIFT 6	/*Todo: Asummed to be 64B for each entry*/

u32 chrd_rrqtpool_alloc(struct chrd_rdev *rdev, int size)
{
        unsigned long addr = gen_pool_alloc(rdev->rrqt_pool, size);
	pr_debug("addr 0x%x size %d\n", (u32)addr, size << 6);
        if (!addr)
                pr_warn_ratelimited("Out of RRQT memory\n");

        mutex_lock(&rdev->stats.lock);
        if (addr) {
                rdev->stats.rrqt.cur += roundup(size, 1 << MIN_RRQT_SHIFT);
                if (rdev->stats.rrqt.cur > rdev->stats.rrqt.max)
                        rdev->stats.rrqt.max = rdev->stats.rrqt.cur;
                kref_get(&rdev->rrqt_kref);
        } else
                rdev->stats.rrqt.fail++;
        mutex_unlock(&rdev->stats.lock);
        return (u32)addr;
}

static void destroy_rrqtpool(struct kref *kref)
{
	struct chrd_rdev *rdev;

	rdev = container_of(kref, struct chrd_rdev, rrqt_kref);
	gen_pool_destroy(rdev->rrqt_pool);
	complete(&rdev->rrqt_compl);
}

void chrd_rrqtpool_free(struct chrd_rdev *rdev, u32 addr, int size)
{
	pr_debug("addr 0x%x size %d\n", addr, size);
	mutex_lock(&rdev->stats.lock);
	rdev->stats.rrqt.cur -= roundup(size, 1 << MIN_RRQT_SHIFT);
	mutex_unlock(&rdev->stats.lock);
	gen_pool_free(rdev->rrqt_pool, (unsigned long)addr, size);
	kref_put(&rdev->rrqt_kref, destroy_rrqtpool);
}

int chrd_rrqtpool_create(struct chrd_rdev *rdev)
{
        unsigned rrqt_start, rrqt_chunk, rrqt_top;

        rdev->rrqt_pool = gen_pool_create(MIN_RRQT_SHIFT, -1);
        if (!rdev->rrqt_pool)
                return -ENOMEM;

        rrqt_start = rdev->lldi.vr->rq.start;
        rrqt_chunk = rdev->lldi.vr->rq.size;
        rrqt_top = rrqt_start + rrqt_chunk;

        while (rrqt_start < rrqt_top) {
                rrqt_chunk = min(rrqt_top - rrqt_start + 1, rrqt_chunk);
                if (gen_pool_add(rdev->rrqt_pool, rrqt_start, rrqt_chunk, -1)) {
			pr_debug("failed to add RRQT chunk (%x/%x)\n",
				 rrqt_start, rrqt_chunk);
                        if (rrqt_chunk <= 1024 << MIN_RRQT_SHIFT) {
                                pr_warn("Failed to add all RRQT chunks (%x/%x)\n",
					rrqt_start, rrqt_top - rrqt_start);
                                return 0;
                        }
                        rrqt_chunk >>= 1;
                } else {
			pr_debug("added RRQT chunk (%x/%x)\n",
				 rrqt_start, rrqt_chunk);
                        rrqt_start += rrqt_chunk;
                }
        }
        return 0;
}

void chrd_rrqtpool_destroy(struct chrd_rdev *rdev)
{
	kref_put(&rdev->rrqt_kref, destroy_rrqtpool);
}

u32 chrd_rqtpool_alloc(struct chrd_rdev *rdev, int size)
{
	u32 addr;

	addr = cxgb4_uld_alloc_rqtpool(rdev->rdma_res, size);
	if (addr)
		kref_get(&rdev->rqt_kref);

	return addr;
}

static void destroy_rqtpool(struct kref *kref)
{
	struct chrd_rdev *rdev;

	rdev = container_of(kref, struct chrd_rdev, rqt_kref);
	complete(&rdev->rqt_compl);
}

void chrd_rqtpool_destroy(struct chrd_rdev *rdev)
{
	kref_put(&rdev->rqt_kref, destroy_rqtpool);
}

void chrd_rqtpool_free(struct chrd_rdev *rdev, u32 addr, int size)
{
	cxgb4_uld_free_rqtpool(rdev->rdma_res, addr, size);
	chrd_rqtpool_destroy(rdev);
}
