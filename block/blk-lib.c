// SPDX-License-Identifier: GPL-2.0
/*
 * Functions related to generic helpers functions
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/scatterlist.h>

#include "blk.h"

/* Keeps track of all outstanding copy IO */
struct blkdev_copy_io {
	atomic_t refcount;
	ssize_t copied;
	int status;
	struct task_struct *waiter;
	void (*endio)(void *private, int status, ssize_t copied);
	void *private;
};

/* Keeps track of single outstanding copy offload IO */
struct blkdev_copy_offload_io {
	struct blkdev_copy_io *cio;
	loff_t offset;
};

/* Keeps track of single outstanding copy emulation IO */
struct blkdev_copy_emulation_io {
	struct blkdev_copy_io *cio;
	struct work_struct emulation_work;
	void *buf;
	ssize_t buf_len;
	loff_t pos_in;
	loff_t pos_out;
	ssize_t len;
	struct block_device *bdev_in;
	struct block_device *bdev_out;
	gfp_t gfp;
};

static sector_t bio_discard_limit(struct block_device *bdev, sector_t sector)
{
	unsigned int discard_granularity = bdev_discard_granularity(bdev);
	sector_t granularity_aligned_sector;

	if (bdev_is_partition(bdev))
		sector += bdev->bd_start_sect;

	granularity_aligned_sector =
		round_up(sector, discard_granularity >> SECTOR_SHIFT);

	/*
	 * Make sure subsequent bios start aligned to the discard granularity if
	 * it needs to be split.
	 */
	if (granularity_aligned_sector != sector)
		return granularity_aligned_sector - sector;

	/*
	 * Align the bio size to the discard granularity to make splitting the bio
	 * at discard granularity boundaries easier in the driver if needed.
	 */
	return round_down(UINT_MAX, discard_granularity) >> SECTOR_SHIFT;
}

int __blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, struct bio **biop)
{
	struct bio *bio = *biop;
	sector_t bs_mask;

	if (bdev_read_only(bdev))
		return -EPERM;
	if (!bdev_max_discard_sectors(bdev))
		return -EOPNOTSUPP;

	/* In case the discard granularity isn't set by buggy device driver */
	if (WARN_ON_ONCE(!bdev_discard_granularity(bdev))) {
		pr_err_ratelimited("%pg: Error: discard_granularity is 0.\n",
				   bdev);
		return -EOPNOTSUPP;
	}

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

	if (!nr_sects)
		return -EINVAL;

	while (nr_sects) {
		sector_t req_sects =
			min(nr_sects, bio_discard_limit(bdev, sector));

		bio = blk_next_bio(bio, bdev, 0, REQ_OP_DISCARD, gfp_mask);
		bio->bi_iter.bi_sector = sector;
		bio->bi_iter.bi_size = req_sects << 9;
		sector += req_sects;
		nr_sects -= req_sects;

		/*
		 * We can loop for a long time in here, if someone does
		 * full device discards (like mkfs). Be nice and allow
		 * us to schedule out to avoid softlocking if preempt
		 * is disabled.
		 */
		cond_resched();
	}

	*biop = bio;
	return 0;
}
EXPORT_SYMBOL(__blkdev_issue_discard);

/**
 * blkdev_issue_discard - queue a discard
 * @bdev:	blockdev to issue discard for
 * @sector:	start sector
 * @nr_sects:	number of sectors to discard
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 *
 * Description:
 *    Issue a discard request for the sectors in question.
 */
int blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask)
{
	struct bio *bio = NULL;
	struct blk_plug plug;
	int ret;

	blk_start_plug(&plug);
	ret = __blkdev_issue_discard(bdev, sector, nr_sects, gfp_mask, &bio);
	if (!ret && bio) {
		ret = submit_bio_wait(bio);
		if (ret == -EOPNOTSUPP)
			ret = 0;
		bio_put(bio);
	}
	blk_finish_plug(&plug);

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_discard);

static inline ssize_t blkdev_copy_sanity_check(struct block_device *bdev_in,
					       loff_t pos_in,
					       struct block_device *bdev_out,
					       loff_t pos_out, size_t len)
{
	unsigned int align = max(bdev_logical_block_size(bdev_out),
				 bdev_logical_block_size(bdev_in)) - 1;

	if ((pos_in & align) || (pos_out & align) || (len & align) || !len ||
	    len >= BLK_COPY_MAX_BYTES)
		return -EINVAL;

	return 0;
}

static inline void blkdev_copy_endio(struct blkdev_copy_io *cio)
{
	if (cio->endio) {
		cio->endio(cio->private, cio->status, cio->copied);
		kfree(cio);
	} else {
		struct task_struct *waiter = cio->waiter;

		WRITE_ONCE(cio->waiter, NULL);
		blk_wake_io_task(waiter);
	}
}

/*
 * This must only be called once all bios have been issued so that the refcount
 * can only decrease. This just waits for all bios to complete.
 * Returns the length of bytes copied or error
 */
static ssize_t blkdev_copy_wait_for_completion_io(struct blkdev_copy_io *cio)
{
	ssize_t ret;

	for (;;) {
		__set_current_state(TASK_UNINTERRUPTIBLE);
		if (!READ_ONCE(cio->waiter))
			break;
		blk_io_schedule();
	}
	__set_current_state(TASK_RUNNING);
	ret = cio->copied;
	kfree(cio);

	return ret;
}

static void blkdev_copy_offload_src_endio(struct bio *bio)
{
	struct blkdev_copy_offload_io *offload_io = bio->bi_private;
	struct blkdev_copy_io *cio = offload_io->cio;

	if (bio->bi_status) {
		cio->copied = min_t(ssize_t, offload_io->offset, cio->copied);
		if (!cio->status)
			cio->status = blk_status_to_errno(bio->bi_status);
	}
	bio_put(bio);
	kfree(offload_io);

	if (atomic_dec_and_test(&cio->refcount))
		blkdev_copy_endio(cio);
}

/*
 * @bdev:	block device
 * @pos_in:	source offset
 * @pos_out:	destination offset
 * @len:	length in bytes to be copied
 * @endio:	endio function to be called on completion of copy operation,
 *		for synchronous operation this should be NULL
 * @private:	endio function will be called with this private data,
 *		for synchronous operation this should be NULL
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 *
 * For synchronous operation returns the length of bytes copied or error
 * For asynchronous operation returns -EIOCBQUEUED or error
 *
 * Description:
 *	Copy source offset to destination offset within block device, using
 *	device's native copy offload feature.
 *	We perform copy operation using 2 bio's.
 *	1. We take a plug and send a REQ_OP_COPY_DST bio along with destination
 *	sector and length. Once this bio reaches request layer, we form a
 *	request and wait for dst bio to arrive.
 *	2. We issue REQ_OP_COPY_SRC bio along with source sector, length.
 *	Once this bio reaches request layer and find a request with previously
 *	sent destination info we merge the source bio and return.
 *	3. Release the plug and request is sent to driver
 *	This design works only for drivers with request queue.
 */
ssize_t blkdev_copy_offload(struct block_device *bdev, loff_t pos_in,
			    loff_t pos_out, size_t len,
			    void (*endio)(void *, int, ssize_t),
			    void *private, gfp_t gfp)
{
	struct blkdev_copy_io *cio;
	struct blkdev_copy_offload_io *offload_io;
	struct bio *src_bio, *dst_bio;
	size_t rem, chunk;
	size_t max_copy_bytes = bdev_max_copy_sectors(bdev) << SECTOR_SHIFT;
	ssize_t ret;
	struct blk_plug plug;

	if (!max_copy_bytes)
		return -EOPNOTSUPP;

	ret = blkdev_copy_sanity_check(bdev, pos_in, bdev, pos_out, len);
	if (ret)
		return ret;

	cio = kzalloc(sizeof(*cio), gfp);
	if (!cio)
		return -ENOMEM;
	atomic_set(&cio->refcount, 1);
	cio->waiter = current;
	cio->endio = endio;
	cio->private = private;

	/*
	 * If there is a error, copied will be set to least successfully
	 * completed copied length
	 */
	cio->copied = len;
	for (rem = len; rem > 0; rem -= chunk) {
		chunk = min(rem, max_copy_bytes);

		offload_io = kzalloc(sizeof(*offload_io), gfp);
		if (!offload_io)
			goto err_free_cio;
		offload_io->cio = cio;
		/*
		 * For partial completion, we use offload_io->offset to truncate
		 * successful copy length
		 */
		offload_io->offset = len - rem;

		dst_bio = bio_alloc(bdev, 0, REQ_OP_COPY_DST, gfp);
		if (!dst_bio)
			goto err_free_offload_io;
		dst_bio->bi_iter.bi_size = chunk;
		dst_bio->bi_iter.bi_sector = pos_out >> SECTOR_SHIFT;

		blk_start_plug(&plug);
		src_bio = blk_next_bio(dst_bio, bdev, 0, REQ_OP_COPY_SRC, gfp);
		if (!src_bio)
			goto err_free_dst_bio;
		src_bio->bi_iter.bi_size = chunk;
		src_bio->bi_iter.bi_sector = pos_in >> SECTOR_SHIFT;
		src_bio->bi_end_io = blkdev_copy_offload_src_endio;
		src_bio->bi_private = offload_io;

		atomic_inc(&cio->refcount);
		submit_bio(src_bio);
		blk_finish_plug(&plug);
		pos_in += chunk;
		pos_out += chunk;
	}

	if (atomic_dec_and_test(&cio->refcount))
		blkdev_copy_endio(cio);
	if (endio)
		return -EIOCBQUEUED;

	return blkdev_copy_wait_for_completion_io(cio);

err_free_dst_bio:
	bio_put(dst_bio);
err_free_offload_io:
	kfree(offload_io);
err_free_cio:
	cio->copied = min_t(ssize_t, cio->copied, (len - rem));
	cio->status = -ENOMEM;
	if (rem == len) {
		ret = cio->status;
		kfree(cio);
		return ret;
	}
	if (cio->endio)
		return cio->status;

	return blkdev_copy_wait_for_completion_io(cio);
}
EXPORT_SYMBOL_GPL(blkdev_copy_offload);

static void *blkdev_copy_alloc_buf(ssize_t req_size, ssize_t *alloc_size,
				   gfp_t gfp)
{
	int min_size = PAGE_SIZE;
	char *buf;

	while (req_size >= min_size) {
		buf = kvmalloc(req_size, gfp);
		if (buf) {
			*alloc_size = req_size;
			return buf;
		}
		req_size >>= 1;
	}

	return NULL;
}

static struct bio *bio_map_buf(void *data, unsigned int len, gfp_t gfp)
{
	unsigned long kaddr = (unsigned long)data;
	unsigned long end = (kaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	unsigned long start = kaddr >> PAGE_SHIFT;
	const int nr_pages = end - start;
	bool is_vmalloc = is_vmalloc_addr(data);
	struct page *page;
	int offset, i;
	struct bio *bio;

	bio = bio_kmalloc(nr_pages, gfp);
	if (!bio)
		return ERR_PTR(-ENOMEM);
	bio_init(bio, NULL, bio->bi_inline_vecs, nr_pages, 0);

	if (is_vmalloc) {
		flush_kernel_vmap_range(data, len);
		bio->bi_private = data;
	}

	offset = offset_in_page(kaddr);
	for (i = 0; i < nr_pages; i++) {
		unsigned int bytes = PAGE_SIZE - offset;

		if (len <= 0)
			break;

		if (bytes > len)
			bytes = len;

		if (!is_vmalloc)
			page = virt_to_page(data);
		else
			page = vmalloc_to_page(data);
		if (bio_add_page(bio, page, bytes, offset) < bytes) {
			/* we don't support partial mappings */
			bio_uninit(bio);
			kfree(bio);
			return ERR_PTR(-EINVAL);
		}

		data += bytes;
		len -= bytes;
		offset = 0;
	}

	return bio;
}

static void blkdev_copy_emulation_work(struct work_struct *work)
{
	struct blkdev_copy_emulation_io *emulation_io = container_of(work,
			struct blkdev_copy_emulation_io, emulation_work);
	struct blkdev_copy_io *cio = emulation_io->cio;
	struct bio *read_bio, *write_bio;
	loff_t pos_in = emulation_io->pos_in, pos_out = emulation_io->pos_out;
	ssize_t rem, chunk;
	int ret = 0;

	for (rem = emulation_io->len; rem > 0; rem -= chunk) {
		chunk = min_t(int, emulation_io->buf_len, rem);

		read_bio = bio_map_buf(emulation_io->buf,
				       emulation_io->buf_len,
				       emulation_io->gfp);
		if (IS_ERR(read_bio)) {
			ret = PTR_ERR(read_bio);
			break;
		}
		read_bio->bi_opf = REQ_OP_READ | REQ_SYNC;
		bio_set_dev(read_bio, emulation_io->bdev_in);
		read_bio->bi_iter.bi_sector = pos_in >> SECTOR_SHIFT;
		read_bio->bi_iter.bi_size = chunk;
		ret = submit_bio_wait(read_bio);
		kfree(read_bio);
		if (ret)
			break;

		write_bio = bio_map_buf(emulation_io->buf,
					emulation_io->buf_len,
					emulation_io->gfp);
		if (IS_ERR(write_bio)) {
			ret = PTR_ERR(write_bio);
			break;
		}
		write_bio->bi_opf = REQ_OP_WRITE | REQ_SYNC;
		bio_set_dev(write_bio, emulation_io->bdev_out);
		write_bio->bi_iter.bi_sector = pos_out >> SECTOR_SHIFT;
		write_bio->bi_iter.bi_size = chunk;
		ret = submit_bio_wait(write_bio);
		kfree(write_bio);
		if (ret)
			break;

		pos_in += chunk;
		pos_out += chunk;
	}
	cio->status = ret;
	kvfree(emulation_io->buf);
	kfree(emulation_io);
	blkdev_copy_endio(cio);
}

static inline ssize_t queue_max_hw_bytes(struct request_queue *q)
{
	return min_t(ssize_t, queue_max_hw_sectors(q) << SECTOR_SHIFT,
		     queue_max_segments(q) << PAGE_SHIFT);
}
/*
 * @bdev_in:	source block device
 * @pos_in:	source offset
 * @bdev_out:	destination block device
 * @pos_out:	destination offset
 * @len:	length in bytes to be copied
 * @endio:	endio function to be called on completion of copy operation,
 *		for synchronous operation this should be NULL
 * @private:	endio function will be called with this private data,
 *		for synchronous operation this should be NULL
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 *
 * For synchronous operation returns the length of bytes copied or error
 * For asynchronous operation returns -EIOCBQUEUED or error
 *
 * Description:
 *	If native copy offload feature is absent, caller can use this function
 *	to perform copy.
 *	We store information required to perform the copy along with temporary
 *	buffer allocation. We async punt copy emulation to a worker. And worker
 *	performs copy in 2 steps.
 *	1. Read data from source to temporary buffer
 *	2. Write data to destination from temporary buffer
 */
ssize_t blkdev_copy_emulation(struct block_device *bdev_in, loff_t pos_in,
			      struct block_device *bdev_out, loff_t pos_out,
			      size_t len, void (*endio)(void *, int, ssize_t),
			      void *private, gfp_t gfp)
{
	struct request_queue *in = bdev_get_queue(bdev_in);
	struct request_queue *out = bdev_get_queue(bdev_out);
	struct blkdev_copy_emulation_io *emulation_io;
	struct blkdev_copy_io *cio;
	ssize_t ret;
	size_t max_hw_bytes = min(queue_max_hw_bytes(in),
				  queue_max_hw_bytes(out));

	ret = blkdev_copy_sanity_check(bdev_in, pos_in, bdev_out, pos_out, len);
	if (ret)
		return ret;

	cio = kzalloc(sizeof(*cio), gfp);
	if (!cio)
		return -ENOMEM;

	cio->waiter = current;
	cio->copied = len;
	cio->endio = endio;
	cio->private = private;

	emulation_io = kzalloc(sizeof(*emulation_io), gfp);
	if (!emulation_io)
		goto err_free_cio;
	emulation_io->cio = cio;
	INIT_WORK(&emulation_io->emulation_work, blkdev_copy_emulation_work);
	emulation_io->pos_in = pos_in;
	emulation_io->pos_out = pos_out;
	emulation_io->len = len;
	emulation_io->bdev_in = bdev_in;
	emulation_io->bdev_out = bdev_out;
	emulation_io->gfp = gfp;

	emulation_io->buf = blkdev_copy_alloc_buf(min(max_hw_bytes, len),
						  &emulation_io->buf_len, gfp);
	if (!emulation_io->buf)
		goto err_free_emulation_io;

	schedule_work(&emulation_io->emulation_work);

	if (cio->endio)
		return -EIOCBQUEUED;

	return blkdev_copy_wait_for_completion_io(cio);

err_free_emulation_io:
	kfree(emulation_io);
err_free_cio:
	kfree(cio);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(blkdev_copy_emulation);

static int __blkdev_issue_write_zeroes(struct block_device *bdev,
		sector_t sector, sector_t nr_sects, gfp_t gfp_mask,
		struct bio **biop, unsigned flags)
{
	struct bio *bio = *biop;
	unsigned int max_sectors;

	if (bdev_read_only(bdev))
		return -EPERM;

	/* Ensure that max_sectors doesn't overflow bi_size */
	max_sectors = bdev_write_zeroes_sectors(bdev);

	if (max_sectors == 0)
		return -EOPNOTSUPP;

	while (nr_sects) {
		unsigned int len = min_t(sector_t, nr_sects, max_sectors);

		bio = blk_next_bio(bio, bdev, 0, REQ_OP_WRITE_ZEROES, gfp_mask);
		bio->bi_iter.bi_sector = sector;
		if (flags & BLKDEV_ZERO_NOUNMAP)
			bio->bi_opf |= REQ_NOUNMAP;

		bio->bi_iter.bi_size = len << SECTOR_SHIFT;
		nr_sects -= len;
		sector += len;
		cond_resched();
	}

	*biop = bio;
	return 0;
}

/*
 * Convert a number of 512B sectors to a number of pages.
 * The result is limited to a number of pages that can fit into a BIO.
 * Also make sure that the result is always at least 1 (page) for the cases
 * where nr_sects is lower than the number of sectors in a page.
 */
static unsigned int __blkdev_sectors_to_bio_pages(sector_t nr_sects)
{
	sector_t pages = DIV_ROUND_UP_SECTOR_T(nr_sects, PAGE_SIZE / 512);

	return min(pages, (sector_t)BIO_MAX_VECS);
}

static int __blkdev_issue_zero_pages(struct block_device *bdev,
		sector_t sector, sector_t nr_sects, gfp_t gfp_mask,
		struct bio **biop)
{
	struct bio *bio = *biop;
	int bi_size = 0;
	unsigned int sz;

	if (bdev_read_only(bdev))
		return -EPERM;

	while (nr_sects != 0) {
		bio = blk_next_bio(bio, bdev, __blkdev_sectors_to_bio_pages(nr_sects),
				   REQ_OP_WRITE, gfp_mask);
		bio->bi_iter.bi_sector = sector;

		while (nr_sects != 0) {
			sz = min((sector_t) PAGE_SIZE, nr_sects << 9);
			bi_size = bio_add_page(bio, ZERO_PAGE(0), sz, 0);
			nr_sects -= bi_size >> 9;
			sector += bi_size >> 9;
			if (bi_size < sz)
				break;
		}
		cond_resched();
	}

	*biop = bio;
	return 0;
}

/**
 * __blkdev_issue_zeroout - generate number of zero filed write bios
 * @bdev:	blockdev to issue
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @biop:	pointer to anchor bio
 * @flags:	controls detailed behavior
 *
 * Description:
 *  Zero-fill a block range, either using hardware offload or by explicitly
 *  writing zeroes to the device.
 *
 *  If a device is using logical block provisioning, the underlying space will
 *  not be released if %flags contains BLKDEV_ZERO_NOUNMAP.
 *
 *  If %flags contains BLKDEV_ZERO_NOFALLBACK, the function will return
 *  -EOPNOTSUPP if no explicit hardware offload for zeroing is provided.
 */
int __blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, struct bio **biop,
		unsigned flags)
{
	int ret;
	sector_t bs_mask;

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

	ret = __blkdev_issue_write_zeroes(bdev, sector, nr_sects, gfp_mask,
			biop, flags);
	if (ret != -EOPNOTSUPP || (flags & BLKDEV_ZERO_NOFALLBACK))
		return ret;

	return __blkdev_issue_zero_pages(bdev, sector, nr_sects, gfp_mask,
					 biop);
}
EXPORT_SYMBOL(__blkdev_issue_zeroout);

/**
 * blkdev_issue_zeroout - zero-fill a block range
 * @bdev:	blockdev to write
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @flags:	controls detailed behavior
 *
 * Description:
 *  Zero-fill a block range, either using hardware offload or by explicitly
 *  writing zeroes to the device.  See __blkdev_issue_zeroout() for the
 *  valid values for %flags.
 */
int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, unsigned flags)
{
	int ret = 0;
	sector_t bs_mask;
	struct bio *bio;
	struct blk_plug plug;
	bool try_write_zeroes = !!bdev_write_zeroes_sectors(bdev);

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

retry:
	bio = NULL;
	blk_start_plug(&plug);
	if (try_write_zeroes) {
		ret = __blkdev_issue_write_zeroes(bdev, sector, nr_sects,
						  gfp_mask, &bio, flags);
	} else if (!(flags & BLKDEV_ZERO_NOFALLBACK)) {
		ret = __blkdev_issue_zero_pages(bdev, sector, nr_sects,
						gfp_mask, &bio);
	} else {
		/* No zeroing offload support */
		ret = -EOPNOTSUPP;
	}
	if (ret == 0 && bio) {
		ret = submit_bio_wait(bio);
		bio_put(bio);
	}
	blk_finish_plug(&plug);
	if (ret && try_write_zeroes) {
		if (!(flags & BLKDEV_ZERO_NOFALLBACK)) {
			try_write_zeroes = false;
			goto retry;
		}
		if (!bdev_write_zeroes_sectors(bdev)) {
			/*
			 * Zeroing offload support was indicated, but the
			 * device reported ILLEGAL REQUEST (for some devices
			 * there is no non-destructive way to verify whether
			 * WRITE ZEROES is actually supported).
			 */
			ret = -EOPNOTSUPP;
		}
	}

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_zeroout);

int blkdev_issue_secure_erase(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp)
{
	sector_t bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	unsigned int max_sectors = bdev_max_secure_erase_sectors(bdev);
	struct bio *bio = NULL;
	struct blk_plug plug;
	int ret = 0;

	/* make sure that "len << SECTOR_SHIFT" doesn't overflow */
	if (max_sectors > UINT_MAX >> SECTOR_SHIFT)
		max_sectors = UINT_MAX >> SECTOR_SHIFT;
	max_sectors &= ~bs_mask;

	if (max_sectors == 0)
		return -EOPNOTSUPP;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;
	if (bdev_read_only(bdev))
		return -EPERM;

	blk_start_plug(&plug);
	while (nr_sects) {
		unsigned int len = min_t(sector_t, nr_sects, max_sectors);

		bio = blk_next_bio(bio, bdev, 0, REQ_OP_SECURE_ERASE, gfp);
		bio->bi_iter.bi_sector = sector;
		bio->bi_iter.bi_size = len << SECTOR_SHIFT;

		sector += len;
		nr_sects -= len;
		cond_resched();
	}
	if (bio) {
		ret = submit_bio_wait(bio);
		bio_put(bio);
	}
	blk_finish_plug(&plug);

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_secure_erase);
