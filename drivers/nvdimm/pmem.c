// SPDX-License-Identifier: GPL-2.0-only
/*
 * Persistent Memory Driver
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 * Copyright (c) 2015, Christoph Hellwig <hch@lst.de>.
 * Copyright (c) 2015, Boaz Harrosh <boaz@plexistor.com>.
 */

#include <linux/blkdev.h>
#include <linux/pagemap.h>
#include <linux/hdreg.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/set_memory.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/badblocks.h>
#include <linux/memremap.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/vmalloc.h>
#include <linux/blk-mq.h>
#include <linux/pfn_t.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/dax.h>
#include <linux/nd.h>
#include <linux/mm.h>
#include <asm/cacheflush.h>
#include "pmem.h"
#include "btt.h"
#include "pfn.h"
#include "nd.h"

static unsigned int min_dma_size = 24 * 1024;
module_param(min_dma_size, uint, 0644);
MODULE_PARM_DESC(min_dma_size, "Minimal I/O size to use DMA");

struct pmem_dma_tr {
	struct pmem_device	*pmem;
	struct bio		*bio;
	struct device		*dma_dev1;	/* DMA for local PMEM */
	struct device		*dma_dev2;	/* DMA for remote PMEM */
	bool			 single;	/* No remote PMEM access */
	bool			 do_acct;	/* Accounting needed */
	unsigned long		 start;		/* Acoounting start time */
	refcount_t		 inprog;	/* Number of active DMAs */
	dma_addr_t		 laddr;		/* Local PMEM DMA address */
	dma_addr_t		 raddr;		/* Remove PMEM DMA address */
	dma_addr_t		 addr[];	/* BIO DMA addresses */
};

static struct device *to_dev(struct pmem_device *pmem)
{
	/*
	 * nvdimm bus services need a 'dev' parameter, and we record the device
	 * at init in bb.dev.
	 */
	return pmem->bb.dev;
}

static struct nd_region *to_region(struct pmem_device *pmem)
{
	return to_nd_region(to_dev(pmem)->parent);
}

static bool pmem_dma_feq(struct dma_chan *chan, void *data)
{
	return dev_to_node(chan->device->dev) == (long)data;
}

static bool pmem_dma_fne(struct dma_chan *chan, void *data)
{
	return dev_to_node(chan->device->dev) != (long)data;
}

static void pmem_dma_init(struct pmem_device *pmem)
{
	struct device *dev = to_dev(pmem);
	dma_cap_mask_t dma_mask;

	dma_cap_zero(dma_mask);
	dma_cap_set(DMA_MEMCPY, dma_mask);

	/*
	 * Prefer to allocate NUMA-local DMA channel for remote PMEM writes.
	 * Remote writes are slower than local and need all boost we can give.
	 */
	pmem->rdma_chan = dma_request_channel(dma_mask, pmem_dma_feq,
	    (void *)(long)pmem->rnode);
	if (!pmem->rdma_chan)
		pmem->rdma_chan = dma_request_channel(dma_mask, NULL, NULL);
	if (!pmem->rdma_chan) {
		dev_info(dev, "Unable to allocate DMA channel\n");
		return;
	}

	/*
	 * If local PMEM is in different NUMA-node, try to allocate DMA there.
	 * If it is in the same NUMA-node, then DMA allocation from some other
	 * allows to avoid DMA engine bottleneck and shows better throughput.
	 */
	if (pmem->node != dev_to_node(pmem->rdma_chan->device->dev)) {
		pmem->dma_chan = dma_request_channel(dma_mask, pmem_dma_feq,
		    (void *)(long)pmem->node);
	} else {
		pmem->dma_chan = dma_request_channel(dma_mask, pmem_dma_fne,
		    (void *)(long)dev_to_node(pmem->rdma_chan->device->dev));
	}
	if (!pmem->dma_chan)
		pmem->dma_chan = dma_request_channel(dma_mask, NULL, NULL);
	if (!pmem->dma_chan)
		pmem->dma_chan = pmem->rdma_chan;

	/*
	 * After all the dances above, we may use remote PMEM DMA channel for
	 * single destination copies if it is closer to the local PMEM.
	 */
	pmem->rdma_for_single =
	    dev_to_node(pmem->dma_chan->device->dev) != pmem->node &&
	    dev_to_node(pmem->rdma_chan->device->dev) == pmem->node;
}

static void pmem_dma_shutdown(struct pmem_device *pmem)
{
	if (pmem->dma_chan == NULL)
		return;
	dma_release_channel(pmem->dma_chan);
	if (pmem->dma_chan != pmem->rdma_chan)
		dma_release_channel(pmem->rdma_chan);
	pmem->dma_chan = pmem->rdma_chan = NULL;
}

static void pmem_dma_unmap(struct pmem_dma_tr *tr)
{
	struct bio_vec bvec;
	struct bvec_iter iter;
	enum dma_data_direction dir;
	unsigned int size = tr->bio->bi_iter.bi_size;
	int i = 0;

	/* Unmap local PMEM. */
	dir = op_is_write(bio_op(tr->bio)) ? DMA_FROM_DEVICE : DMA_TO_DEVICE;
	if (dma_mapping_error(tr->dma_dev1, tr->laddr))
		goto done;
	dma_unmap_resource(tr->dma_dev1, tr->laddr, size, dir, 0);

	if (!tr->single) {
		/* Unmap remote PMEM. */
		if (dma_mapping_error(tr->dma_dev2, tr->raddr))
			goto done;
		dma_unmap_resource(tr->dma_dev2, tr->raddr, size, dir, 0);
	}

	/* Unmap BIO data. */
	dir = op_is_write(bio_op(tr->bio)) ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
	bio_for_each_bvec(bvec, tr->bio, iter) {
		if (dma_mapping_error(tr->dma_dev1, tr->addr[i]))
			break;
		dma_unmap_page(tr->dma_dev1, tr->addr[i], bvec.bv_len, dir);
		i++;
		if (tr->single)
			continue;
		if (dma_mapping_error(tr->dma_dev2, tr->addr[i]))
			break;
		dma_unmap_page(tr->dma_dev2, tr->addr[i], bvec.bv_len, dir);
		i++;
	}
done:
	kfree(tr);
}

static void pmem_dma_callback(void *data, const struct dmaengine_result *result)
{
	struct pmem_dma_tr *tr = data;
	struct bio *bio = tr->bio;
	struct device *dev = to_dev(tr->pmem);

	if (result->result != DMA_TRANS_NOERROR) {
		dev_err(dev, "DMA error %x\n", result->result);
		if (result->result == DMA_TRANS_ABORTED)
			bio->bi_status = BLK_STS_TRANSPORT;
		else
			bio->bi_status = BLK_STS_IOERR;
	}
	if (refcount_dec_and_test(&tr->inprog)) {
		if (tr->do_acct)
			bio_end_io_acct(bio, tr->start);
		pmem_dma_unmap(tr);
		bio_endio(bio);
	}
}

static bool pmem_dma_submit_bio(struct pmem_device *pmem, struct bio *bio,
    bool do_acct, unsigned long start)
{
	struct device *dev = to_dev(pmem);
	struct dma_chan	*dma_chan1, *dma_chan2;
	struct dma_device *dma_dev1, *dma_dev2;
	struct dma_async_tx_descriptor *tx;
	dma_async_tx_callback_result cb;
	enum dma_data_direction dir;
	dma_cookie_t cookie, last_cookie1 = 0, last_cookie2 = 0;
	struct pmem_dma_tr *tr;
	phys_addr_t laddr, raddr;
	struct bio_vec bvec;
	struct bvec_iter iter;
	unsigned long flags;
	unsigned int dmas, i, vecs = 0;
	sector_t sector;
	static struct dmaengine_result dummy_result = {
		.result = DMA_TRANS_ABORTED,
		.residue = 0
	};

	/* For small I/Os softwate copy is faster. */
	if (bio->bi_iter.bi_size < min_dma_size)
		return false;

	/* Choose DMA channels for local and remote PMEM accesses. */
	laddr = pmem->phys_addr + pmem->data_offset;
	raddr = op_is_write(bio_op(bio)) ? pmem->rphys_addr : 0;
	if (raddr)
		raddr += pmem->data_offset;
	if (!raddr && pmem->rdma_for_single) {
		dma_chan1 = pmem->rdma_chan;
		dma_chan2 = pmem->dma_chan;
	} else {
		dma_chan1 = pmem->dma_chan;
		dma_chan2 = pmem->rdma_chan;
	}
	if (dma_chan1 == NULL || dma_chan2 == NULL)
		return false;

	/* Check the addresses alignment fit DMA device(s) requirements. */
	dma_dev1 = dma_chan1->device;
	dma_dev2 = dma_chan2->device;
	bio_for_each_bvec(bvec, bio, iter) {
		if (!is_dma_copy_aligned(dma_dev1, bvec.bv_offset,
		    laddr + iter.bi_sector * 512, bvec.bv_len))
			return false;
		if (raddr &&
		    !is_dma_copy_aligned(dma_dev2, bvec.bv_offset,
		    raddr + iter.bi_sector * 512, bvec.bv_len))
			return false;
		vecs++;
	}

	/* Collect information needed to complete BIO on DMA completion. */
	dmas = raddr ? 2 : 1;
	tr = kmalloc(offsetof(struct pmem_dma_tr, addr[vecs * dmas]),
	    GFP_NOWAIT | __GFP_ZERO);
	if (!tr) {
		dev_warn(dev, "kmalloc() failed\n");
		return false;
	}
	tr->pmem = pmem;
	tr->bio = bio;
	tr->single = !raddr;
	tr->dma_dev1 = dma_dev1->dev;
	tr->dma_dev2 = dma_dev2->dev;
	refcount_set(&tr->inprog, dmas);
	tr->do_acct = do_acct;
	tr->start = start;

	/* Map local PMEM for the first DMA device. */
	sector = bio->bi_iter.bi_sector;
	dir = op_is_write(bio_op(bio)) ? DMA_FROM_DEVICE : DMA_TO_DEVICE;
	tr->laddr = dma_map_resource(dma_dev1->dev,
	    laddr + sector * 512, bio->bi_iter.bi_size, dir, 0);
	if (dma_mapping_error(dma_dev1->dev, tr->laddr)) {
		dev_warn(dev, "dma_map_page() 1 failed\n");
		pmem_dma_unmap(tr);
		return false;
	}

	if (raddr) {
		/* Map remote PMEM for the second DMA device. */
		tr->raddr = dma_map_resource(dma_dev2->dev,
		    raddr + sector * 512, bio->bi_iter.bi_size, dir, 0);
		if (dma_mapping_error(dma_dev2->dev, tr->raddr)) {
			dev_warn(dev, "dma_map_page() 2 failed\n");
			pmem_dma_unmap(tr);
			return false;
		}
	}

	/* Map BIO data for the DMA device(s). */
	i = 0;
	dir = op_is_write(bio_op(bio)) ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
	bio_for_each_bvec(bvec, bio, iter) {
		tr->addr[i] = dma_map_page(dma_dev1->dev, bvec.bv_page,
		    bvec.bv_offset, bvec.bv_len, dir);
		if (dma_mapping_error(dma_dev1->dev, tr->addr[i])) {
			dev_warn(dev, "dma_map_page() 3 failed\n");
			pmem_dma_unmap(tr);
			return false;
		}
		i++;
		if (!raddr)
			continue;
		tr->addr[i] = dma_map_page(dma_dev2->dev, bvec.bv_page,
		    bvec.bv_offset, bvec.bv_len, dir);
		if (dma_mapping_error(dma_dev2->dev, tr->addr[i])) {
			dev_warn(dev, "dma_map_page() 4 failed\n");
			pmem_dma_unmap(tr);
			return false;
		}
		i++;
	}

	/* Issue the local PMEM I/O. */
	i = 0;
	flags = DMA_CTRL_ACK;
	cb = NULL;
	bio_for_each_bvec(bvec, bio, iter) {
		if (iter.bi_size == bvec.bv_len) {
			flags |= DMA_PREP_INTERRUPT;
			cb = pmem_dma_callback;
		}
		if (op_is_write(bio_op(bio))) {
			tx = dmaengine_prep_dma_memcpy(dma_chan1,
			    tr->laddr + (iter.bi_sector - sector) * 512,
			    tr->addr[i], bvec.bv_len, flags);
		} else {
			tx = dmaengine_prep_dma_memcpy(dma_chan1, tr->addr[i],
			    tr->laddr + (iter.bi_sector - sector) * 512,
			    bvec.bv_len, flags);
		}
		if (!tx) {
			dev_warn(dev, "dmaengine_prep_dma_memcpy() 1 failed\n");
			goto error;
		}
		tx->callback_result = cb;
		tx->callback_param = tr;
		cookie = dmaengine_submit(tx);
		if (dma_submit_error(cookie)) {
			dev_warn(dev, "dmaengine_submit() 1 failed\n");
			goto error;
		}
		last_cookie1 = cookie;
		i += dmas;
	}
	dma_async_issue_pending(dma_chan1);

	if (!raddr)
		return true;

	/* Issue the remote PMEM I/O. */
	i = 1;
	flags = DMA_CTRL_ACK;
	cb = NULL;
	bio_for_each_bvec(bvec, bio, iter) {
		if (iter.bi_size == bvec.bv_len) {
			flags |= DMA_PREP_INTERRUPT;
			cb = pmem_dma_callback;
		}
		tx = dmaengine_prep_dma_memcpy(dma_chan2,
		    tr->raddr + (iter.bi_sector - sector) * 512,
		    tr->addr[i], bvec.bv_len, flags);
		if (!tx) {
			dev_warn(dev, "dmaengine_prep_dma_memcpy() 2 failed\n");
			goto error2;
		}
		tx->callback_result = cb;
		tx->callback_param = tr;
		cookie = dmaengine_submit(tx);
		if (dma_submit_error(cookie)) {
			dev_warn(dev, "dmaengine_submit() 2 failed\n");
			goto error2;
		}
		last_cookie2 = cookie;
		i += 2;
	}
	dma_async_issue_pending(dma_chan2);
	return true;

error:
	/*
	 * Some error has happened during the local PMEM I/O issue.
	 * Since none of issued transactions had callback, just wait for
	 * them to complete, free memory and fall back to software copy.
	 */
	if (last_cookie1) {
		dma_async_issue_pending(dma_chan1);
		dma_sync_wait(dma_chan1, last_cookie1);
	}
	pmem_dma_unmap(tr);
	return false;

error2:
	/*
	 * Some error has happened during the remote PMEM I/O issue.
	 * The local PMEM I/O is already running and we can't stop it.
	 * Since none of issued remote transactions had callback, wait for
	 * them to complete and return I/O error when local I/O completes.
	 */
	if (last_cookie2) {
		dma_async_issue_pending(dma_chan2);
		dma_sync_wait(dma_chan2, last_cookie2);
	}
	pmem_dma_callback(tr, &dummy_result);
	return true;
}

static int pmem_open(struct block_device *bdev, fmode_t mode)
{
	struct pmem_device *pmem = bdev->bd_disk->private_data;
	struct pmem_label *label = pmem->label;

	if ((pmem->opened++) == 0)
		pmem_dma_init(pmem);
	if (label && (mode & FMODE_WRITE))
		label->opened++;
	return 0;
}

static void pmem_release(struct gendisk *disk, fmode_t mode)
{
	struct pmem_device *pmem = disk->private_data;
	struct pmem_label *label = pmem->label;

	if ((--pmem->opened) == 0)
		pmem_dma_shutdown(pmem);
	if (label && (mode & FMODE_WRITE))
		label->opened--;
}

static void hwpoison_clear(struct pmem_device *pmem,
		phys_addr_t phys, unsigned int len)
{
	unsigned long pfn_start, pfn_end, pfn;

	/* only pmem in the linear map supports HWPoison */
	if (is_vmalloc_addr(pmem->virt_addr))
		return;

	pfn_start = PHYS_PFN(phys);
	pfn_end = pfn_start + PHYS_PFN(len);
	for (pfn = pfn_start; pfn < pfn_end; pfn++) {
		struct page *page = pfn_to_page(pfn);

		/*
		 * Note, no need to hold a get_dev_pagemap() reference
		 * here since we're in the driver I/O path and
		 * outstanding I/O requests pin the dev_pagemap.
		 */
		if (test_and_clear_pmem_poison(page))
			clear_mce_nospec(pfn);
	}
}

static blk_status_t pmem_clear_poison(struct pmem_device *pmem,
		phys_addr_t offset, unsigned int len)
{
	struct device *dev = to_dev(pmem);
	sector_t sector;
	long cleared;
	blk_status_t rc = BLK_STS_OK;

	sector = (offset - pmem->data_offset) / 512;

	cleared = nvdimm_clear_poison(dev, pmem->phys_addr + offset, len);
	if (cleared < len)
		rc = BLK_STS_IOERR;
	if (cleared > 0 && cleared / 512) {
		hwpoison_clear(pmem, pmem->phys_addr + offset, cleared);
		cleared /= 512;
		dev_dbg(dev, "%#llx clear %ld sector%s\n",
				(unsigned long long) sector, cleared,
				cleared > 1 ? "s" : "");
		badblocks_clear(&pmem->bb, sector, cleared);
		if (pmem->bb_state)
			sysfs_notify_dirent(pmem->bb_state);
	}

	arch_invalidate_pmem(pmem->virt_addr + offset, len);

	return rc;
}

static void write_pmem(void *pmem_addr, struct page *page,
		unsigned int off, unsigned int len)
{
	void *mem;

	BUG_ON(off + len > PAGE_SIZE);
	mem = kmap_local_page(page);
	memcpy_flushcache(pmem_addr, mem + off, len);
	kunmap_local(mem);
}

static void write_pmem2(void *pmem_addr, void *pmem_addr2, struct page *page,
		unsigned int off, unsigned int len)
{
	void *mem;

	BUG_ON(off + len > PAGE_SIZE);
	mem = kmap_local_page(page);
	memcpy_flushcache(pmem_addr, mem + off, len);
	memcpy(pmem_addr2, mem + off, len);
	kunmap_local(mem);
}

static blk_status_t read_pmem(struct page *page, unsigned int off,
		void *pmem_addr, unsigned int len)
{
	unsigned long rem;
	void *mem;

	BUG_ON(off + len > PAGE_SIZE);
	mem = kmap_local_page(page);
	rem = copy_mc_to_kernel(mem + off, pmem_addr, len);
	kunmap_local(mem);
	if (rem)
		return BLK_STS_IOERR;
	return BLK_STS_OK;
}

static blk_status_t pmem_do_read(struct pmem_device *pmem,
			struct page *page, unsigned int page_off,
			sector_t sector, unsigned int len)
{
	blk_status_t rc;
	phys_addr_t pmem_off = sector * 512 + pmem->data_offset;
	void *pmem_addr = pmem->virt_addr + pmem_off;

	if (unlikely(is_bad_pmem(&pmem->bb, sector, len)))
		return BLK_STS_IOERR;

	rc = read_pmem(page, page_off, pmem_addr, len);
	flush_dcache_page(page);
	return rc;
}

static blk_status_t pmem_do_write(struct pmem_device *pmem,
			struct page *page, unsigned int page_off,
			sector_t sector, unsigned int len)
{
	blk_status_t rc = BLK_STS_OK;
	bool bad_pmem = false;
	phys_addr_t pmem_off = sector * 512 + pmem->data_offset;
	void *pmem_addr = pmem->virt_addr + pmem_off;
	void *rpmem_addr = pmem->rvirt_addr;

	if (unlikely(is_bad_pmem(&pmem->bb, sector, len)))
		bad_pmem = true;

	/*
	 * Note that we write the data both before and after
	 * clearing poison.  The write before clear poison
	 * handles situations where the latest written data is
	 * preserved and the clear poison operation simply marks
	 * the address range as valid without changing the data.
	 * In this case application software can assume that an
	 * interrupted write will either return the new good
	 * data or an error.
	 *
	 * However, if pmem_clear_poison() leaves the data in an
	 * indeterminate state we need to perform the write
	 * after clear poison.
	 */
	flush_dcache_page(page);
	if (rpmem_addr) {
		write_pmem2(pmem_addr, rpmem_addr + pmem_off, page, page_off,
		    len);
	} else
		write_pmem(pmem_addr, page, page_off, len);
	if (unlikely(bad_pmem)) {
		rc = pmem_clear_poison(pmem, pmem_off, len);
		write_pmem(pmem_addr, page, page_off, len);
	}

	return rc;
}

static blk_qc_t pmem_submit_bio(struct bio *bio)
{
	int ret = 0;
	blk_status_t rc = 0;
	bool do_acct;
	unsigned long start;
	struct bio_vec bvec;
	struct bvec_iter iter;
	struct pmem_device *pmem = bio->bi_bdev->bd_disk->private_data;
	struct nd_region *nd_region = to_region(pmem);
	struct pmem_label *label = pmem->label;
	struct pmem_label *rlabel = pmem->rlabel;

	if (bio->bi_opf & REQ_PREFLUSH)
		ret = nvdimm_flush(nd_region, bio);

	do_acct = blk_queue_io_stat(bio->bi_bdev->bd_disk->queue);
	if (do_acct)
		start = bio_start_io_acct(bio);
	if (op_is_write(bio_op(bio)) && label) {
		if (unlikely(label->empty)) {
			label->empty = 0;
			if (rlabel)
				rlabel->empty = 0;
		}
		if (!rlabel && unlikely(!label->dirty)) {
			label->dirty = 1;
			arch_wb_cache_pmem(label, sizeof(struct pmem_label));
		}
	}
	if (pmem_dma_submit_bio(pmem, bio, do_acct, start))
		return BLK_QC_T_NONE;
	bio_for_each_segment(bvec, bio, iter) {
		if (op_is_write(bio_op(bio)))
			rc = pmem_do_write(pmem, bvec.bv_page, bvec.bv_offset,
				iter.bi_sector, bvec.bv_len);
		else
			rc = pmem_do_read(pmem, bvec.bv_page, bvec.bv_offset,
				iter.bi_sector, bvec.bv_len);
		if (rc) {
			bio->bi_status = rc;
			break;
		}
	}
	if (do_acct)
		bio_end_io_acct(bio, start);

	if (bio->bi_opf & REQ_FUA)
		ret = nvdimm_flush(nd_region, bio);

	if (ret)
		bio->bi_status = errno_to_blk_status(ret);

	bio_endio(bio);
	return BLK_QC_T_NONE;
}

static int pmem_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, unsigned int op)
{
	struct pmem_device *pmem = bdev->bd_disk->private_data;
	blk_status_t rc;

	if (op_is_write(op))
		rc = pmem_do_write(pmem, page, 0, sector, thp_size(page));
	else
		rc = pmem_do_read(pmem, page, 0, sector, thp_size(page));
	/*
	 * The ->rw_page interface is subtle and tricky.  The core
	 * retries on any error, so we can only invoke page_endio() in
	 * the successful completion case.  Otherwise, we'll see crashes
	 * caused by double completion.
	 */
	if (rc == 0)
		page_endio(page, op_is_write(op), 0);

	return blk_status_to_errno(rc);
}

/* see "strong" declaration in tools/testing/nvdimm/pmem-dax.c */
__weak long __pmem_direct_access(struct pmem_device *pmem, pgoff_t pgoff,
		long nr_pages, void **kaddr, pfn_t *pfn)
{
	resource_size_t offset = PFN_PHYS(pgoff) + pmem->data_offset;

	if (unlikely(is_bad_pmem(&pmem->bb, PFN_PHYS(pgoff) / 512,
					PFN_PHYS(nr_pages))))
		return -EIO;

	if (kaddr)
		*kaddr = pmem->virt_addr + offset;
	if (pfn)
		*pfn = phys_to_pfn_t(pmem->phys_addr + offset, pmem->pfn_flags);

	/*
	 * If badblocks are present, limit known good range to the
	 * requested range.
	 */
	if (unlikely(pmem->bb.count))
		return nr_pages;
	return PHYS_PFN(pmem->size - pmem->pfn_pad - offset);
}

static const struct block_device_operations pmem_fops = {
	.owner =		THIS_MODULE,
	.open =			pmem_open,
	.release =		pmem_release,
	.submit_bio =		pmem_submit_bio,
	.rw_page =		pmem_rw_page,
};

static int pmem_dax_zero_page_range(struct dax_device *dax_dev, pgoff_t pgoff,
				    size_t nr_pages)
{
	struct pmem_device *pmem = dax_get_private(dax_dev);

	return blk_status_to_errno(pmem_do_write(pmem, ZERO_PAGE(0), 0,
				   PFN_PHYS(pgoff) >> SECTOR_SHIFT,
				   PAGE_SIZE));
}

static long pmem_dax_direct_access(struct dax_device *dax_dev,
		pgoff_t pgoff, long nr_pages, void **kaddr, pfn_t *pfn)
{
	struct pmem_device *pmem = dax_get_private(dax_dev);

	return __pmem_direct_access(pmem, pgoff, nr_pages, kaddr, pfn);
}

/*
 * Use the 'no check' versions of copy_from_iter_flushcache() and
 * copy_mc_to_iter() to bypass HARDENED_USERCOPY overhead. Bounds
 * checking, both file offset and device offset, is handled by
 * dax_iomap_actor()
 */
static size_t pmem_copy_from_iter(struct dax_device *dax_dev, pgoff_t pgoff,
		void *addr, size_t bytes, struct iov_iter *i)
{
	return _copy_from_iter_flushcache(addr, bytes, i);
}

static size_t pmem_copy_to_iter(struct dax_device *dax_dev, pgoff_t pgoff,
		void *addr, size_t bytes, struct iov_iter *i)
{
	return _copy_mc_to_iter(addr, bytes, i);
}

static const struct dax_operations pmem_dax_ops = {
	.direct_access = pmem_dax_direct_access,
	.dax_supported = generic_fsdax_supported,
	.copy_from_iter = pmem_copy_from_iter,
	.copy_to_iter = pmem_copy_to_iter,
	.zero_page_range = pmem_dax_zero_page_range,
};

static ssize_t label_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct pmem_device *pmem = dev_to_disk(dev)->private_data;
	struct pmem_label *label = pmem->label;

	if (label) {
		memcpy(buf, label, sizeof(*label));
		return sizeof(*label);
	}
	return -ENXIO;
}
static DEVICE_ATTR_RO(label);

static ssize_t uuid_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct pmem_device *pmem = dev_to_disk(dev)->private_data;
	struct pmem_label *label = pmem->label;

	if (label)
		return sprintf(buf, "%016llX\n", label->array);
	return -ENXIO;
}
static DEVICE_ATTR_RO(uuid);

static struct attribute *label_attributes[] = {
	&dev_attr_label.attr,
	&dev_attr_uuid.attr,
	NULL,
};

static umode_t label_visible(struct kobject *kobj, struct attribute *a, int n)
{
	struct device *dev = container_of(kobj, typeof(*dev), kobj);
	struct pmem_device *pmem = dev_to_disk(dev)->private_data;

	if (!pmem->label)
		return 0;
	return a->mode;
}

static const struct attribute_group label_attribute_group = {
	.attrs		= label_attributes,
	.is_visible	= label_visible,
};

static const struct attribute_group *pmem_attribute_groups[] = {
	&label_attribute_group,
	&dax_attribute_group,
	NULL,
};

static void pmem_release_disk(void *__pmem)
{
	struct pmem_device *pmem = __pmem;

	kill_dax(pmem->dax_dev);
	put_dax(pmem->dax_dev);
	del_gendisk(pmem->disk);

	blk_cleanup_disk(pmem->disk);
}

static int pmem_attach_disk(struct device *dev,
		struct nd_namespace_common *ndns)
{
	struct nd_namespace_io *nsio = to_nd_namespace_io(&ndns->dev);
	struct nd_region *nd_region = to_nd_region(dev->parent);
	int nid = dev_to_node(dev), fua;
	struct resource *res = &nsio->res;
	struct range bb_range;
	struct nd_pfn *nd_pfn = NULL;
	struct dax_device *dax_dev;
	struct nd_pfn_sb *pfn_sb;
	struct pmem_device *pmem;
	struct request_queue *q;
	struct gendisk *disk;
	void *addr;
	int rc;
	unsigned long flags = 0UL;

	pmem = devm_kzalloc(dev, sizeof(*pmem), GFP_KERNEL);
	if (!pmem)
		return -ENOMEM;

	rc = devm_namespace_enable(dev, ndns, nd_info_block_reserve());
	if (rc)
		return rc;

	/* while nsio_rw_bytes is active, parse a pfn info block if present */
	if (is_nd_pfn(dev)) {
		nd_pfn = to_nd_pfn(dev);
		rc = nvdimm_setup_pfn(nd_pfn, &pmem->pgmap);
		if (rc)
			return rc;
	}

	/* we're attaching a block device, disable raw namespace access */
	devm_namespace_disable(dev, ndns);

	dev_set_drvdata(dev, pmem);
	pmem->phys_addr = res->start;
	pmem->size = resource_size(res);
	fua = nvdimm_has_flush(nd_region);
	if (!IS_ENABLED(CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE) || fua < 0) {
		dev_warn(dev, "unable to guarantee persistence of writes\n");
		fua = 0;
	}

	if (!devm_request_mem_region(dev, res->start, resource_size(res),
				dev_name(&ndns->dev))) {
		dev_warn(dev, "could not reserve region %pR\n", res);
		return -EBUSY;
	}

	disk = blk_alloc_disk(nid);
	if (!disk)
		return -ENOMEM;
	q = disk->queue;

	pmem->disk = disk;
	pmem->pgmap.owner = pmem;
	pmem->pfn_flags = PFN_DEV;
	if (is_nd_pfn(dev)) {
		pmem->pgmap.type = MEMORY_DEVICE_FS_DAX;
		addr = devm_memremap_pages(dev, &pmem->pgmap);
		pfn_sb = nd_pfn->pfn_sb;
		pmem->data_offset = le64_to_cpu(pfn_sb->dataoff);
		pmem->pfn_pad = resource_size(res) -
			range_len(&pmem->pgmap.range);
		pmem->pfn_flags |= PFN_MAP;
		bb_range = pmem->pgmap.range;
		bb_range.start += pmem->data_offset;
	} else if (pmem_should_map_pages(dev)) {
		pmem->pgmap.range.start = res->start;
		pmem->pgmap.range.end = res->end;
		pmem->pgmap.nr_range = 1;
		pmem->pgmap.type = MEMORY_DEVICE_FS_DAX;
		addr = devm_memremap_pages(dev, &pmem->pgmap);
		pmem->pfn_flags |= PFN_MAP;
		bb_range = pmem->pgmap.range;
	} else {
		addr = devm_memremap(dev, pmem->phys_addr,
				pmem->size, ARCH_MEMREMAP_PMEM);
		bb_range.start =  res->start;
		bb_range.end = res->end;
	}

	if (IS_ERR(addr)) {
		rc = PTR_ERR(addr);
		goto out;
	}
	pmem->virt_addr = addr;
	pmem->rnode = pmem->node = dev_to_node(dev);

	/* Register raw pmems for NTB mirroring. */
	if (!is_nd_pfn(dev) && !is_nd_dax(dev) &&
	    uuid_is_null((const uuid_t *)nd_dev_to_uuid(&ndns->dev))) {
		pmem->bb.dev = dev;
		ntb_pmem_register(pmem);
	}

	blk_queue_write_cache(q, true, fua);
	blk_queue_physical_block_size(q, PAGE_SIZE);
	blk_queue_logical_block_size(q, pmem_sector_size(ndns));
	blk_queue_max_hw_sectors(q, UINT_MAX);
	blk_queue_flag_set(QUEUE_FLAG_NONROT, q);
	/* Block DAX if we are registered for NTB mirroring. */
	if ((pmem->pfn_flags & PFN_MAP) && !pmem->label)
		blk_queue_flag_set(QUEUE_FLAG_DAX, q);

	disk->fops		= &pmem_fops;
	disk->private_data	= pmem;
	disk->events		= DISK_EVENT_MEDIA_CHANGE;
	disk->event_flags	= DISK_EVENT_FLAG_UEVENT;
	nvdimm_namespace_disk_name(ndns, disk->disk_name);
	set_capacity(disk, (pmem->size - pmem->pfn_pad - pmem->data_offset)
			/ 512);
	if (devm_init_badblocks(dev, &pmem->bb))
		return -ENOMEM;
	nvdimm_badblocks_populate(nd_region, &pmem->bb, &bb_range);
	disk->bb = &pmem->bb;

	if (is_nvdimm_sync(nd_region))
		flags = DAXDEV_F_SYNC;
	dax_dev = alloc_dax(pmem, disk->disk_name, &pmem_dax_ops, flags);
	if (IS_ERR(dax_dev)) {
		rc = PTR_ERR(dax_dev);
		goto out;
	}
	dax_write_cache(dax_dev, nvdimm_has_cache(nd_region));
	pmem->dax_dev = dax_dev;

	device_add_disk(dev, disk, pmem_attribute_groups);
	if (devm_add_action_or_reset(dev, pmem_release_disk, pmem))
		return -ENOMEM;

	nvdimm_check_and_set_ro(disk);

	pmem->bb_state = sysfs_get_dirent(disk_to_dev(disk)->kobj.sd,
					  "badblocks");
	if (!pmem->bb_state)
		dev_warn(dev, "'badblocks' notification disabled\n");
	return 0;
out:
	blk_cleanup_disk(pmem->disk);
	return rc;
}

static int nd_pmem_probe(struct device *dev)
{
	int ret;
	struct nd_namespace_common *ndns;

	ndns = nvdimm_namespace_common_probe(dev);
	if (IS_ERR(ndns))
		return PTR_ERR(ndns);

	if (is_nd_btt(dev))
		return nvdimm_namespace_attach_btt(ndns);

	if (is_nd_pfn(dev))
		return pmem_attach_disk(dev, ndns);

	ret = devm_namespace_enable(dev, ndns, nd_info_block_reserve());
	if (ret)
		return ret;

	ret = nd_btt_probe(dev, ndns);
	if (ret == 0)
		return -ENXIO;

	/*
	 * We have two failure conditions here, there is no
	 * info reserver block or we found a valid info reserve block
	 * but failed to initialize the pfn superblock.
	 *
	 * For the first case consider namespace as a raw pmem namespace
	 * and attach a disk.
	 *
	 * For the latter, consider this a success and advance the namespace
	 * seed.
	 */
	ret = nd_pfn_probe(dev, ndns);
	if (ret == 0)
		return -ENXIO;
	else if (ret == -EOPNOTSUPP)
		return ret;

	ret = nd_dax_probe(dev, ndns);
	if (ret == 0)
		return -ENXIO;
	else if (ret == -EOPNOTSUPP)
		return ret;

	/* probe complete, attach handles namespace enabling */
	devm_namespace_disable(dev, ndns);

	return pmem_attach_disk(dev, ndns);
}

static void nd_pmem_remove(struct device *dev)
{
	struct pmem_device *pmem = dev_get_drvdata(dev);

	if (is_nd_btt(dev))
		nvdimm_namespace_detach_btt(to_nd_btt(dev));
	else {
		/* Unregister from NTB mirroring. */
		if (pmem->label)
			ntb_pmem_unregister(pmem);

		/*
		 * Note, this assumes nd_device_lock() context to not
		 * race nd_pmem_notify()
		 */
		sysfs_put(pmem->bb_state);
		pmem->bb_state = NULL;
	}
	nvdimm_flush(to_nd_region(dev->parent), NULL);
}

static void nd_pmem_shutdown(struct device *dev)
{
	nvdimm_flush(to_nd_region(dev->parent), NULL);
}

static void pmem_revalidate_poison(struct device *dev)
{
	struct nd_region *nd_region;
	resource_size_t offset = 0, end_trunc = 0;
	struct nd_namespace_common *ndns;
	struct nd_namespace_io *nsio;
	struct badblocks *bb;
	struct range range;
	struct kernfs_node *bb_state;

	if (is_nd_btt(dev)) {
		struct nd_btt *nd_btt = to_nd_btt(dev);

		ndns = nd_btt->ndns;
		nd_region = to_nd_region(ndns->dev.parent);
		nsio = to_nd_namespace_io(&ndns->dev);
		bb = &nsio->bb;
		bb_state = NULL;
	} else {
		struct pmem_device *pmem = dev_get_drvdata(dev);

		nd_region = to_region(pmem);
		bb = &pmem->bb;
		bb_state = pmem->bb_state;

		if (is_nd_pfn(dev)) {
			struct nd_pfn *nd_pfn = to_nd_pfn(dev);
			struct nd_pfn_sb *pfn_sb = nd_pfn->pfn_sb;

			ndns = nd_pfn->ndns;
			offset = pmem->data_offset +
					__le32_to_cpu(pfn_sb->start_pad);
			end_trunc = __le32_to_cpu(pfn_sb->end_trunc);
		} else {
			ndns = to_ndns(dev);
		}

		nsio = to_nd_namespace_io(&ndns->dev);
	}

	range.start = nsio->res.start + offset;
	range.end = nsio->res.end - end_trunc;
	nvdimm_badblocks_populate(nd_region, bb, &range);
	if (bb_state)
		sysfs_notify_dirent(bb_state);
}

static void pmem_revalidate_region(struct device *dev)
{
	struct pmem_device *pmem;

	if (is_nd_btt(dev)) {
		struct nd_btt *nd_btt = to_nd_btt(dev);
		struct btt *btt = nd_btt->btt;

		nvdimm_check_and_set_ro(btt->btt_disk);
		return;
	}

	pmem = dev_get_drvdata(dev);
	nvdimm_check_and_set_ro(pmem->disk);
}

static void nd_pmem_notify(struct device *dev, enum nvdimm_event event)
{
	switch (event) {
	case NVDIMM_REVALIDATE_POISON:
		pmem_revalidate_poison(dev);
		break;
	case NVDIMM_REVALIDATE_REGION:
		pmem_revalidate_region(dev);
		break;
	default:
		dev_WARN_ONCE(dev, 1, "notify: unknown event: %d\n", event);
		break;
	}
}

MODULE_ALIAS("pmem");
MODULE_ALIAS_ND_DEVICE(ND_DEVICE_NAMESPACE_IO);
MODULE_ALIAS_ND_DEVICE(ND_DEVICE_NAMESPACE_PMEM);
static struct nd_device_driver nd_pmem_driver = {
	.probe = nd_pmem_probe,
	.remove = nd_pmem_remove,
	.notify = nd_pmem_notify,
	.shutdown = nd_pmem_shutdown,
	.drv = {
		.name = "nd_pmem",
	},
	.type = ND_DRIVER_NAMESPACE_IO | ND_DRIVER_NAMESPACE_PMEM,
};

module_nd_driver(nd_pmem_driver);

MODULE_AUTHOR("Ross Zwisler <ross.zwisler@linux.intel.com>");
MODULE_LICENSE("GPL v2");
