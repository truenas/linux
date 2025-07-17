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
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <rdma/ib_umem.h>
#include <asm/atomic.h>

#include "iw_cxgb4.h"

int use_dsgl = 1;
module_param(use_dsgl, int, 0644);
MODULE_PARM_DESC(use_dsgl, "Use DSGL for PBL/FastReg (default=1)");

#define T7_ULPTX_MIN_IO 1
#define T4_ULPTX_MIN_IO 32
#define CHRD_MAX_INLINE_SIZE 96
#define T4_ULPTX_MAX_DMA 1024
#define CHRD_INLINE_THRESHOLD 128

static int inline_threshold = CHRD_INLINE_THRESHOLD;
module_param(inline_threshold, int, 0644);
MODULE_PARM_DESC(inline_threshold, "inline vs dsgl threshold (default=128)");

static int mr_exceeds_hw_limits(struct chrd_dev *dev, u64 length)
{
	return (is_t4(dev->rdev.lldi.adapter_type) ||
		is_t5(dev->rdev.lldi.adapter_type)) &&
	       length >= 8*1024*1024*1024ULL;
}

static int _chrd_write_mem_dma_aligned(struct chrd_rdev *rdev, u32 addr, u32 len,
				dma_addr_t data, struct sk_buff *skb,
				struct chrd_wr_wait *wr_waitp)
{
	struct ulp_mem_io *req;
	struct ulptx_sgl *sgl;
	u8 wr_len;
	int ret = 0;

	addr &= 0x7FFFFFF;	/*Todo: hardcoded value */

	if (wr_waitp)
		chrd_init_wr_wait(wr_waitp);
	wr_len = roundup(sizeof *req + sizeof *sgl, 16);

	if(!skb) {
		skb = alloc_skb(wr_len, GFP_KERNEL | __GFP_NOFAIL);
		if (!skb)
			return -ENOMEM;
	}
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, NCHAN);

	req = (struct ulp_mem_io *)__skb_put(skb, wr_len);
	memset(req, 0, wr_len);
	INIT_ULPTX_WR(req, wr_len, 0, 0);
	req->wr.wr_hi = cpu_to_be32(V_FW_WR_OP(FW_ULPTX_WR) |
				    (wr_waitp ? F_FW_WR_COMPL : 0));
	req->wr.wr_lo = wr_waitp ? (__force __be64)(uintptr_t)wr_waitp : 0;
	req->wr.wr_mid = cpu_to_be32(V_FW_WR_LEN16(DIV_ROUND_UP(wr_len, 16)));
	req->cmd = cpu_to_be32(V_ULPTX_CMD(ULP_TX_MEM_WRITE) |
			       V_T5_ULP_MEMIO_ORDER(1) |
			       V_T5_ULP_MEMIO_FID(rdev->lldi.rxq_ids[0]));

	if (is_t7(rdev->lldi.adapter_type))
		req->dlen = cpu_to_be32(V_T7_ULP_MEMIO_DATA_LEN(len>>5));
	else
		req->dlen = cpu_to_be32(V_ULP_MEMIO_DATA_LEN(len>>5));

	req->len16 = cpu_to_be32(DIV_ROUND_UP(wr_len-sizeof(req->wr), 16));
	req->lock_addr = cpu_to_be32(V_ULP_MEMIO_ADDR(addr));

	sgl = (struct ulptx_sgl *)(req + 1);
	sgl->cmd_nsge = cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
				    V_ULPTX_NSGE(1));
	sgl->len0 = cpu_to_be32(len);
	sgl->addr0 = cpu_to_be64(data);

	if (wr_waitp)
		ret = chrd_ref_send_wait(rdev, skb, wr_waitp, 0, 0, __func__);
	else
		ret = chrd_ofld_send(rdev, skb);

	return ret;
}

static int _chrd_write_mem_inline(struct chrd_rdev *rdev, u32 addr, u32 len,
				  void *data, struct sk_buff *skb,
				  struct chrd_wr_wait *wr_waitp)
{
	struct ulp_mem_io *req;
	struct ulptx_idata *sc;
	u8 wr_len, *to_dp, *from_dp;
	int copy_len, num_wqe, i, ret = 0;
	__be32 cmd = cpu_to_be32(V_ULPTX_CMD(ULP_TX_MEM_WRITE));

	if (is_t4(rdev->lldi.adapter_type))
		cmd |= cpu_to_be32(V_ULP_MEMIO_ORDER(1));
	else
		cmd |= cpu_to_be32(V_T5_ULP_MEMIO_IMM(1));

	addr &= 0x7FFFFFF;
	pr_debug("addr 0x%x len %u\n", addr, len);
	num_wqe = DIV_ROUND_UP(len, CHRD_MAX_INLINE_SIZE);
	chrd_init_wr_wait(wr_waitp);
	for (i = 0; i < num_wqe; i++) {

		copy_len = len > CHRD_MAX_INLINE_SIZE ? CHRD_MAX_INLINE_SIZE :
			   len;
		wr_len = roundup(sizeof *req + sizeof *sc +
				 roundup(copy_len, T4_ULPTX_MIN_IO), 16);
		if (!skb) {
			skb = alloc_skb(wr_len, GFP_KERNEL | __GFP_NOFAIL);
			if (!skb)
				return -ENOMEM;
		}
		set_wr_txq(skb, CPL_PRIORITY_CONTROL, NCHAN);

		req = (struct ulp_mem_io *)__skb_put(skb, wr_len);
		memset(req, 0, wr_len);
		INIT_ULPTX_WR(req, wr_len, 0, 0);

		if (i == (num_wqe-1)) {
			req->wr.wr_hi = cpu_to_be32(V_FW_WR_OP(FW_ULPTX_WR) |
						    F_FW_WR_COMPL);
			req->wr.wr_lo = (__force __be64)(uintptr_t)wr_waitp;
		} else
			req->wr.wr_hi = cpu_to_be32(V_FW_WR_OP(FW_ULPTX_WR));
		req->wr.wr_mid = cpu_to_be32(
				       V_FW_WR_LEN16(DIV_ROUND_UP(wr_len, 16)));

		req->cmd = cmd;
		if (is_t7(rdev->lldi.adapter_type))
			req->dlen = cpu_to_be32(V_T7_ULP_MEMIO_DATA_LEN(
				    DIV_ROUND_UP(copy_len, T4_ULPTX_MIN_IO)));
		else
			req->dlen = cpu_to_be32(V_ULP_MEMIO_DATA_LEN(
				    DIV_ROUND_UP(copy_len, T4_ULPTX_MIN_IO)));
		req->len16 = cpu_to_be32(DIV_ROUND_UP(wr_len-sizeof(req->wr),
						      16));
		req->lock_addr = cpu_to_be32(V_ULP_MEMIO_ADDR(addr + i * 3));

		sc = (struct ulptx_idata *)(req + 1);
		sc->cmd_more = cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM));
		sc->len = cpu_to_be32(roundup(copy_len, T4_ULPTX_MIN_IO));

		to_dp = (u8 *)(sc + 1);
		from_dp = (u8 *)data + i * CHRD_MAX_INLINE_SIZE;
		if (data)
			memcpy(to_dp, from_dp, copy_len);
		else
			memset(to_dp, 0, copy_len);
		if (copy_len % T4_ULPTX_MIN_IO)
			memset(to_dp + copy_len, 0, T4_ULPTX_MIN_IO -
			       (copy_len % T4_ULPTX_MIN_IO));
		if (i == (num_wqe-1))
			ret = chrd_ref_send_wait(rdev, skb, wr_waitp, 0, 0,
						 __func__);
		else
			ret = chrd_ofld_send(rdev, skb);
		if (ret)
			break;
		skb = NULL;
		len -= CHRD_MAX_INLINE_SIZE;
	}

	return ret;
}

static int _chrd_write_mem_dma(struct chrd_rdev *rdev, u32 addr, u32 len, void *data,
			       struct sk_buff *skb,
			       struct chrd_wr_wait *wr_waitp)
{
	u32 remain = len;
	u32 dmalen;
	int ret = 0;
	dma_addr_t daddr;
	dma_addr_t save;

	daddr = dma_map_single(rdev->lldi.dev, data, len, DMA_TO_DEVICE);
	if (dma_mapping_error(rdev->lldi.dev, daddr))
		return -1;
	save = daddr;
	
	while (remain > inline_threshold) {
		if (remain < T4_ULPTX_MAX_DMA) {
			if (remain & ~T4_ULPTX_MIN_IO)
				dmalen = remain & ~(T4_ULPTX_MIN_IO-1);
			else
				dmalen = remain;
		} else
			dmalen = T4_ULPTX_MAX_DMA;
		remain -= dmalen;
		ret =_chrd_write_mem_dma_aligned(rdev, addr, dmalen, daddr,
						 skb, remain ? NULL : wr_waitp);
		if (ret)
			goto out;
		addr += dmalen >> 5;
		data += dmalen;
		daddr += dmalen;
	}
	if (remain)
		ret = _chrd_write_mem_inline(rdev, addr, remain, data, skb,
					     wr_waitp);
out:
	dma_unmap_single(rdev->lldi.dev, save, len, DMA_TO_DEVICE);
	return ret;
}

/*
 * write len bytes of data into addr (32B aligned address)
 * If data is NULL, clear len byte of memory to zero.
 */
static int write_adapter_mem(struct chrd_rdev *rdev, u32 addr, u32 len,
			     void *data, struct sk_buff *skb,
			     struct chrd_wr_wait *wr_waitp)
{
	int ret;

	if (!rdev->lldi.ulptx_memwrite_dsgl || !use_dsgl) {
		ret = _chrd_write_mem_inline(rdev, addr, len, data, skb,
					      wr_waitp);
		goto out;
	}

	if (len <= inline_threshold) {
		ret = _chrd_write_mem_inline(rdev, addr, len, data, skb,
					     wr_waitp);
		goto out;
	}

	ret = _chrd_write_mem_dma(rdev, addr, len, data, skb, wr_waitp);
	if (ret) {
		pr_warn_ratelimited("%s: dma map failure (non fatal)\n",
				    rdev->lldi.name);
		ret = _chrd_write_mem_inline(rdev, addr, len, data, skb,
					     wr_waitp);
	}
out:
	return ret;
}

/*
 * Build and write a TPT entry.
 * IN: stag key, pdid, perm, bind_enabled, zbva, to, len, page_size,
 *     pbl_size and pbl_addr
 * OUT: stag index
 */
static int write_tpt_entry(struct chrd_rdev *rdev, u32 reset_tpt_entry,
			   u32 *stag, u8 stag_state, u32 pdid,
			   enum fw_ri_stag_type type, enum fw_ri_mem_perms perm,
			   int bind_enabled, u32 zbva, u64 to,
			   u64 len, u8 page_size, u32 pbl_size, u32 pbl_addr,
			   struct sk_buff *skb, struct chrd_wr_wait *wr_waitp)
{
	int err;
	struct fw_ri_tpte *tpt;
	u32 stag_idx;
	static atomic_t key;

	tpt = kmalloc(sizeof(*tpt), GFP_KERNEL);
	if (!tpt)
		return -ENOMEM;

	stag_state = stag_state > 0;
	stag_idx = (*stag) >> 8;

	if ((!reset_tpt_entry) && (*stag == T4_STAG_UNSET)) {
		stag_idx = cxgb4_uld_get_resource(&rdev->resource.tpt_table);
		if (!stag_idx) {
			mutex_lock(&rdev->stats.lock);
			rdev->stats.stag.fail++;
			mutex_unlock(&rdev->stats.lock);
			kfree(tpt);
			return -ENOMEM;
		}
		mutex_lock(&rdev->stats.lock);
		rdev->stats.stag.cur += 32;
		if (rdev->stats.stag.cur > rdev->stats.stag.max)
			rdev->stats.stag.max = rdev->stats.stag.cur;
		mutex_unlock(&rdev->stats.lock);
		*stag = (stag_idx << 8) | (atomic_inc_return(&key) & 0xff);
	}
	pr_debug("stag_state 0x%0x type 0x%0x pdid 0x%0x, stag_idx 0x%x\n",
		 stag_state, type, pdid, stag_idx);

	/* write TPT entry */
	if (reset_tpt_entry)
		memset(tpt, 0, sizeof(*tpt));
	else {
		if (page_size > T6_MAX_PAGE_SIZE)
			return -EINVAL;
		tpt->valid_to_pdid = cpu_to_be32(F_FW_RI_TPTE_VALID |
			V_FW_RI_TPTE_STAGKEY((*stag & M_FW_RI_TPTE_STAGKEY)) |
			V_FW_RI_TPTE_STAGSTATE(stag_state) |
			V_FW_RI_TPTE_STAGTYPE(type) | V_FW_RI_TPTE_PDID(pdid));
		tpt->locread_to_qpid = cpu_to_be32(V_FW_RI_TPTE_PERM(perm) |
			(bind_enabled ? F_FW_RI_TPTE_MWBINDEN : 0) |
			V_FW_RI_TPTE_ADDRTYPE((zbva ? FW_RI_ZERO_BASED_TO :
						      FW_RI_VA_BASED_TO))|
			V_FW_RI_TPTE_PS(page_size));
		tpt->nosnoop_pbladdr = !pbl_size ? 0 : cpu_to_be32(
			V_FW_RI_TPTE_PBLADDR(PBL_OFF(rdev, pbl_addr)>>3));
		tpt->len_lo = cpu_to_be32((u32)(len & 0xffffffffUL));
		tpt->va_hi = cpu_to_be32((u32)(to >> 32));
		tpt->va_lo_fbo = cpu_to_be32((u32)(to & 0xffffffffUL));
		tpt->dca_mwbcnt_pstag = cpu_to_be32(0);
		tpt->len_hi = cpu_to_be32((u32)(len >> 32));
	}
	err = write_adapter_mem(rdev, stag_idx +
				(rdev->lldi.vr->stag.start >> 5),
				sizeof(*tpt), tpt, skb, wr_waitp);

	if (reset_tpt_entry) {
		cxgb4_uld_put_resource(&rdev->resource.tpt_table, stag_idx);
		mutex_lock(&rdev->stats.lock);
 		rdev->stats.stag.cur -= 32;
		mutex_unlock(&rdev->stats.lock);
	}
	kfree(tpt);
	return err;
}

static int write_pbl(struct chrd_rdev *rdev, __be64 *pbl,
		     u32 pbl_addr, u32 pbl_size, struct chrd_wr_wait *wr_waitp)
{
	int err;

	pr_debug("*pdb_addr 0x%x, pbl_base 0x%x, pbl_size %d\n",
		 pbl_addr, rdev->lldi.vr->pbl.start, pbl_size);

	err = write_adapter_mem(rdev, pbl_addr >> 5, pbl_size << 3, pbl, NULL,
				wr_waitp);
	return err;
}

static int dereg_mem(struct chrd_rdev *rdev, u32 stag, u32 pbl_size,
		     u32 pbl_addr, struct sk_buff *skb,
		     struct chrd_wr_wait *wr_waitp)
{
	return write_tpt_entry(rdev, 1, &stag, 0, 0, 0, 0, 0, 0, 0UL, 0, 0,
			       pbl_size, pbl_addr, skb, wr_waitp);
}

static int allocate_window(struct chrd_rdev *rdev, u32 * stag, u32 pdid,
			   struct chrd_wr_wait *wr_waitp)
{
	*stag = T4_STAG_UNSET;
	return write_tpt_entry(rdev, 0, stag, 0, pdid, FW_RI_STAG_MW, 0, 0, 0,
			       0UL, 0, 0, 0, 0, NULL, wr_waitp);
}

static int deallocate_window(struct chrd_rdev *rdev, u32 stag,
			     struct sk_buff *skb,
			     struct chrd_wr_wait *wr_waitp)
{
	return write_tpt_entry(rdev, 1, &stag, 0, 0, 0, 0, 0, 0, 0UL, 0, 0, 0,
			       0, skb, wr_waitp);
}

static int allocate_stag(struct chrd_rdev *rdev, u32 *stag, u32 pdid,
			 u32 pbl_size, u32 pbl_addr,
			 struct chrd_wr_wait *wr_waitp)
{
	*stag = T4_STAG_UNSET;
	return write_tpt_entry(rdev, 0, stag, 0, pdid, FW_RI_STAG_NSMR, 0, 0, 0,
			       0UL, 0, 0, pbl_size, pbl_addr, NULL, wr_waitp);
}

static int finish_mem_reg(struct chrd_mr *mhp, u32 stag)
{
	u32 mmid;

	mhp->attr.state = 1;
	mhp->attr.stag = stag;
	mmid = stag >> 8;
	mhp->ibmr.rkey = mhp->ibmr.lkey = stag;
	pr_debug("mmid 0x%x mhp %p\n", mmid, mhp);
	return xa_insert_irq(&mhp->rhp->mrs, mmid, mhp, GFP_KERNEL);
}

static int register_mem(struct chrd_dev *rhp, struct chrd_pd *php,
		      struct chrd_mr *mhp, int shift)
{
	u32 stag = T4_STAG_UNSET;
	int ret;

	ret = write_tpt_entry(&rhp->rdev, 0, &stag, 1, mhp->attr.pdid,
			      FW_RI_STAG_NSMR, mhp->attr.len ? mhp->attr.perms : 0,
			      mhp->attr.mw_bind_enable, mhp->attr.zbva,
			      mhp->attr.va_fbo, mhp->attr.len ? mhp->attr.len : -1, shift - 12,
			      mhp->attr.pbl_size, mhp->attr.pbl_addr, NULL,
			      mhp->wr_waitp);
	if (ret)
		return ret;

	ret = finish_mem_reg(mhp, stag);
	if (ret) {
		dereg_mem(&rhp->rdev, mhp->attr.stag, mhp->attr.pbl_size,
			  mhp->attr.pbl_addr, mhp->dereg_skb, mhp->wr_waitp);
		mhp->dereg_skb = NULL;
	}
	return ret;
}

static int alloc_pbl(struct chrd_mr *mhp, int npages)
{
	mhp->attr.pbl_addr = chrd_pblpool_alloc(&mhp->rhp->rdev,
						    npages << 3);

	if (!mhp->attr.pbl_addr)
		return -ENOMEM;

	mhp->attr.pbl_size = npages;

	return 0;
}

struct ib_mr *chrd_get_dma_mr(struct ib_pd *pd, int acc)
{
	struct chrd_dev *rhp;
	struct chrd_pd *php;
	struct chrd_mr *mhp;
	int ret;
	u32 stag = T4_STAG_UNSET;

	pr_debug("ib_pd %p\n", pd);
	php = to_chrd_pd(pd);
	rhp = php->rhp;

	mhp = kzalloc(sizeof(*mhp), GFP_KERNEL);
	if (!mhp)
		return ERR_PTR(-ENOMEM);
	mhp->wr_waitp = chrd_alloc_wr_wait(GFP_KERNEL);
	if (!mhp->wr_waitp) {
		ret = -ENOMEM;
		goto err_free_mhp;
	}
	chrd_init_wr_wait(mhp->wr_waitp);

	mhp->dereg_skb = alloc_skb(SGE_MAX_WR_LEN, GFP_KERNEL);
	if (!mhp->dereg_skb) {
		ret = -ENOMEM;
		goto err_free_wr_wait;
	}

	mhp->rhp = rhp;
	mhp->attr.pdid = php->pdid;
	mhp->attr.perms = chrd_ib_to_tpt_access(acc);
	mhp->attr.mw_bind_enable = (acc&IB_ACCESS_MW_BIND) == IB_ACCESS_MW_BIND;
	mhp->attr.zbva = 0;
	mhp->attr.va_fbo = 0;
	mhp->attr.page_size = 0;
	mhp->attr.len = ~0ULL;
	mhp->attr.pbl_size = 0;

	ret = write_tpt_entry(&rhp->rdev, 0, &stag, 1, php->pdid,
			      FW_RI_STAG_NSMR, mhp->attr.perms,
			      mhp->attr.mw_bind_enable, 0, 0, ~0ULL, 0, 0, 0,
			      NULL, mhp->wr_waitp);
	if (ret)
		goto err_free_skb;

	ret = finish_mem_reg(mhp, stag);
	if (ret)
		goto err_dereg_mem;
	return &mhp->ibmr;
err_dereg_mem:
	dereg_mem(&rhp->rdev, mhp->attr.stag, mhp->attr.pbl_size,
		  mhp->attr.pbl_addr, mhp->dereg_skb, mhp->wr_waitp);
err_free_wr_wait:
	chrd_put_wr_wait(mhp->wr_waitp);
err_free_skb:
	kfree_skb(mhp->dereg_skb);
err_free_mhp:
	kfree(mhp);
	return ERR_PTR(ret);
}

static int try_huge_pbl(struct chrd_dev *rhp, struct chrd_mr *mhp,
			u64 start, u64 virt_addr, struct ib_udata *udata,
			int *shift)
{
#if defined(CONFIG_HUGETLB_PAGE) && !defined(__powerpc__) && !defined(__ia64__)
	__be64 *pages;
#ifdef HAVE_IB_UMEM_CHUNK
	struct ib_umem_chunk *chunk;
	int j = 0;
#else
	struct scatterlist *sg;
	int entry;
#endif
	unsigned dsize;
	dma_addr_t daddr;
	unsigned cur_size = 0;
	dma_addr_t cur_addr;
	int n;
	struct ib_umem *umem = mhp->umem;
	int err;
	int i;
	int off = start & (HPAGE_SIZE - 1);
	__u64 usr_pbl, *raw_pbl;
	__u64 __user *usr_pbl_ptr;
	int onepbl = 1;
	int s;
	unsigned int pg_sz;

	/* Allow only those MRs that are backed by huge pages(of size: HPAGE_SIZE). */
	pg_sz = ib_umem_find_best_pgsz(mhp->umem, PAGE_SIZE|HPAGE_SIZE, virt_addr);
	if (pg_sz != HPAGE_SIZE) {
		err = -EINVAL;
		goto err;
	}

	n = DIV_ROUND_UP(off + umem->length, HPAGE_SIZE);
	err = alloc_pbl(mhp, n);
	if (err)
		goto err;

	raw_pbl = (__u64 *) __get_free_page(GFP_KERNEL);
	if (!raw_pbl) {
		err = -ENOMEM;
		goto err_pbl;
	}
	err = ib_copy_from_udata(&usr_pbl, udata, sizeof(u64));
	if (err)
		goto err_raw_pbl;
	usr_pbl_ptr = (__u64 __user *)(unsigned long)usr_pbl;

	pages = (__be64 *) __get_free_page(GFP_KERNEL);
	if (!pages) {
		err = -ENOMEM;
		goto err_raw_pbl;
	}

	i = n = 0;

#ifdef HAVE_IB_UMEM_CHUNK
	list_for_each_entry(chunk, &umem->chunk_list, list) {
		for (j = 0; j < chunk->nmap; ++j) {
			daddr = sg_dma_address(&chunk->page_list[j]);
			dsize = sg_dma_len(&chunk->page_list[j]);
#else
		for_each_sgtable_dma_sg(&mhp->umem->sgt_append.sgt, sg, entry) {
			daddr = sg_dma_address(sg);
			dsize = sg_dma_len(sg);
#endif
			if (!cur_size) {
				cur_addr = daddr;
				cur_size = dsize;
			} else if (cur_addr + cur_size != daddr) {
				err = -EINVAL;
				goto pbl_done;
			} else
				cur_size += dsize;

			if (cur_size > HPAGE_SIZE) {
				err = -EINVAL;
				goto pbl_done;
			} else if (cur_size == HPAGE_SIZE) {
				if (cur_addr & (HPAGE_SIZE - 1)) {
					err = -EINVAL;
					goto pbl_done;
				}
				cur_size = 0;
				onepbl = 0;
				raw_pbl[i] = cur_addr;
				pages[i++] = cpu_to_be64(cur_addr);
				if (i == PAGE_SIZE / sizeof *pages) {
					err = write_pbl(&mhp->rhp->rdev,
					      pages,
					      mhp->attr.pbl_addr + (n << 3), i,
					      mhp->wr_waitp);
					if (err)
						goto pbl_done;
					err = copy_to_user(usr_pbl_ptr + n,
							   raw_pbl, PAGE_SIZE);
					if (err)
						goto pbl_done;
					n += i;
					i = 0;
				}
			}
		}
#ifdef HAVE_IB_UMEM_CHUNK
	}
#endif
	if (onepbl) {
		s = 12;
		while ((1 << s) < cur_size)
			s++;
	} else
		s = ffs(HPAGE_SIZE) - 1;

	if (cur_size) {
		if (cur_addr & ((1 << s) - 1)) {
			err = -EINVAL;
			goto pbl_done;
		}
		raw_pbl[i] = cur_addr;
		pages[i++] = cpu_to_be64(cur_addr);
	}
	if (i) {
		err = write_pbl(&mhp->rhp->rdev, pages,
				mhp->attr.pbl_addr + (n << 3), i, mhp->wr_waitp);
		if (!err)
			err = copy_to_user(usr_pbl_ptr + n, raw_pbl,
					   i * sizeof *usr_pbl_ptr);
	}
pbl_done:
	free_page((unsigned long) pages);
	free_page((unsigned long) raw_pbl);
	if (err)
		goto err_pbl;
	*shift = s;
	pr_debug("*shift %d\n", *shift);
	return 0;
err_raw_pbl:
	free_page((unsigned long)raw_pbl);
err_pbl:
	chrd_pblpool_free(&mhp->rhp->rdev, mhp->attr.pbl_addr,
			      mhp->attr.pbl_size << 3);
err:
	return err;
#else
	return -ENOSYS;
#endif
}

#ifdef HAVE_PEER_MEM_SUPPORT
static void release_mr_resources(struct chrd_mr *mr)
{
	struct chrd_dev *dev = mr->rhp;
	u32 mmid;

	mmid = mr->attr.stag >> 8;
	xa_erase_irq(&dev->mrs, mmid);
	if (mr->mpl)
		dma_free_coherent(mr->rhp->rdev.lldi.dev,
				  mr->max_mpl_len, mr->mpl, mr->mpl_addr);
	dereg_mem(&dev->rdev, mr->attr.stag, mr->attr.pbl_size,
		       mr->attr.pbl_addr, mr->dereg_skb, mr->wr_waitp);
	if (mr->attr.pbl_size)
		chrd_pblpool_free(&mr->rhp->rdev, mr->attr.pbl_addr,
				  mr->attr.pbl_size << 3);
	if (mr->kva)
		kfree((void *) (unsigned long) mr->kva);
	ib_umem_release(mr->umem);
	pr_debug("%s mmid 0x%x ptr %p\n", __func__, mmid, mr);
	return;
}

static void invalidate_umem(void *invalidation_cookie,
			    struct ib_umem *umem,
			    unsigned long addr, size_t size)
{
	struct chrd_mr *mr = (struct chrd_mr *)invalidation_cookie;

	mutex_lock(&mr->live_lock);

	/*
	 * This function is called under client peer lock so its resources are
	 * race protected.
	 */
	if (atomic_inc_return(&mr->invalidated) > 1) {
		umem->invalidation_ctx->inflight_invalidation = 1;
		mutex_unlock(&mr->live_lock);
		return;
	}
	if (!mr->live) {
		mutex_unlock(&mr->live_lock);
		return;
	}

	mutex_unlock(&mr->live_lock);
	umem->invalidation_ctx->peer_callback = 1;
	release_mr_resources(mr);
	complete(&mr->invalidation_comp);
}
#endif

struct ib_mr *chrd_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
			       u64 virt, int acc, struct ib_udata *udata)
{
	__be64 *pages;
	int shift = 0, n, len;
#ifdef HAVE_IB_UMEM_CHUNK
	int i, j, k;
	struct ib_umem_chunk *chunk;
#else
	int i, k, entry;
	struct scatterlist *sg;
#endif
	int err = -ENOMEM;
	struct chrd_reg_mr_resp uresp;
	struct chrd_dev *rhp;
	struct chrd_pd *php;
	struct chrd_mr *mhp;
	__u64 usr_pbl, *raw_pbl;
	__u64 __user *usr_pbl_ptr;
	int npages;
	int oldlib = 0;
	static int warned;
#ifdef HAVE_PEER_MEM_SUPPORT
	struct ib_peer_memory_client *ib_peer_mem;
#endif

	pr_debug("ib_pd %p\n", pd);
	if (udata->outlen < sizeof uresp) {
		oldlib = 1;
		if (!warned++)
			pr_warn("Warning - downlevel libcxgb4 (non-fatal), hugepage PBLs disabled\n");
	}

	if (length == ~0ULL)
		return ERR_PTR(-EINVAL);

	if ((length + start) < start)
		return ERR_PTR(-EINVAL);

	php = to_chrd_pd(pd);
	rhp = php->rhp;

	if (mr_exceeds_hw_limits(rhp, length))
		return ERR_PTR(-EINVAL);

	mhp = kzalloc(sizeof(*mhp), GFP_KERNEL);
	if (!mhp)
		return ERR_PTR(-ENOMEM);
	mhp->wr_waitp = chrd_alloc_wr_wait(GFP_KERNEL);
	if (!mhp->wr_waitp)
		goto err_free_mhp;

	mhp->dereg_skb = alloc_skb(SGE_MAX_WR_LEN, GFP_KERNEL);
	if (!mhp->dereg_skb)
		goto err_free_wr_wait;

	mhp->rhp = rhp;

#ifdef HAVE_PEER_MEM_SUPPORT
	mutex_init(&mhp->live_lock);
	mhp->umem = ib_umem_get(udata, start, length, acc, 0,
				IB_PEER_MEM_ALLOW | IB_PEER_MEM_INVAL_SUPP);
#else
	mhp->umem = ib_umem_get(pd->device, start, length, acc);
#endif
	if (IS_ERR(mhp->umem)) {
		goto err_free_skb;
	}

	if (oldlib ||
	    try_huge_pbl(rhp, mhp, start, virt, udata, &shift)) {

#ifdef HAVE_PEER_MEM_SUPPORT
		ib_peer_mem = mhp->umem->ib_peer_mem;
		if (ib_peer_mem) {
			err = ib_umem_activate_invalidation_notifier(mhp->umem,
				invalidate_umem, mhp);
			if (err)
				goto err_umem_release;
		}

		mutex_lock(&mhp->live_lock);
		if (atomic_read(&mhp->invalidated))
			goto err_unlock;

		if (ib_peer_mem) {
			if (acc & IB_ACCESS_MW_BIND) {
				err = -ENOSYS;
				goto err_unlock;
			}
			init_completion(&mhp->invalidation_comp);
		}
#endif

#ifdef HAVE_IB_UMEM_PAGE_SHIFT
		shift = PAGE_SHIFT;
#else
		shift = ffs(PAGE_SIZE) - 1;
#endif

#ifdef HAVE_IB_UMEM_CHUNK
		n = 0;
		list_for_each_entry(chunk, &mhp->umem->chunk_list, list)
			n += chunk->nents;
#else
		n = ib_umem_num_pages(mhp->umem);
#endif

		err = alloc_pbl(mhp, n);
		if (err)
#ifdef HAVE_PEER_MEM_SUPPORT
			goto err_unlock;
#else
			goto err_umem_release;
#endif

		raw_pbl = (__u64 *) __get_free_page(GFP_KERNEL);
		if (!raw_pbl)
			goto err_pbl_free;
		err = ib_copy_from_udata(&usr_pbl, udata, sizeof(u64));
		if (err)
			goto err_raw_pbl;
		usr_pbl_ptr = (__u64 __user *)(unsigned long)usr_pbl;

		pages = (__be64 *) __get_free_page(GFP_KERNEL);
		if (!pages) {
			err = -ENOMEM;
			goto err_raw_pbl;
		}

		npages = n;
		i = n = 0;

#ifdef HAVE_IB_UMEM_CHUNK
		list_for_each_entry(chunk, &mhp->umem->chunk_list, list)
			for (j = 0; j < chunk->nmap; ++j) {
				len = sg_dma_len(&chunk->page_list[j]) >> shift;
				for (k = 0; k < len; ++k) {
					u64 pa = sg_dma_address(&chunk->page_list[j]) +
#ifdef HAVE_IB_UMEM_PAGE_SHIFT
								(k << shift);
#else
						 mhp->umem->page_size * k;
#endif /* HAVE_IB_UMEM_PAGE_SHIFT */
#else
			for_each_sgtable_dma_sg(&mhp->umem->sgt_append.sgt, sg, entry) {
				len = sg_dma_len(sg) >> shift;
				for (k = 0; k < len; ++k) {
					u64 pa = sg_dma_address(sg) +
#ifdef HAVE_IB_UMEM_PAGE_SHIFT
								(k << shift);
#else
						 PAGE_SIZE * k;
#endif /* HAVE_IB_UMEM_PAGE_SHIFT */
#endif /* HAVE_IB_UMEM_CHUNK */

					raw_pbl[i] = pa;
					pages[i++] = cpu_to_be64(pa);
					if (i == PAGE_SIZE / sizeof *pages) {
						err = write_pbl(&mhp->rhp->rdev,
						      pages,mhp->attr.pbl_addr +
						      (n << 3), i, mhp->wr_waitp);
						if (err)
							goto pbl_done;
						err = copy_to_user(usr_pbl_ptr + n,
								   raw_pbl, PAGE_SIZE);
						if (err)
							goto pbl_done;
						n += i;
						i = 0;
					}
				}
			}
		if (i) {
			err = write_pbl(&mhp->rhp->rdev, pages,
					mhp->attr.pbl_addr + (n << 3), i,
					mhp->wr_waitp);
			if (!err)
				err = copy_to_user(usr_pbl_ptr + n, raw_pbl,
						   i * sizeof *usr_pbl_ptr);
		}
pbl_done:
		free_page((unsigned long) pages);
		free_page((unsigned long) raw_pbl);
		if (err)
			goto err_pbl_free;
	}

	mhp->attr.pdid = php->pdid;
	mhp->attr.zbva = 0;
	mhp->attr.perms = chrd_ib_to_tpt_access(acc);
	mhp->attr.va_fbo = virt;
	mhp->attr.page_size = shift - 12;
	mhp->attr.len = length;

	err = register_mem(rhp, php, mhp, shift);
	if (err)
		goto err_pbl_free;

	if (!oldlib) {
		uresp.page_size = 1 << shift;
		err = ib_copy_to_udata(udata, &uresp, sizeof uresp);
		if (err)
			goto err_pbl_free;
	}
#ifdef HAVE_PEER_MEM_SUPPORT
	mhp->live = 1;
	mutex_unlock(&mhp->live_lock);
#endif
	return &mhp->ibmr;

err_raw_pbl:
	free_page((unsigned long)raw_pbl);
err_pbl_free:
	chrd_pblpool_free(&mhp->rhp->rdev, mhp->attr.pbl_addr,
			      mhp->attr.pbl_size << 3);
err_umem_release:
	ib_umem_release(mhp->umem);
#ifdef HAVE_PEER_MEM_SUPPORT
err_unlock:
	mutex_unlock(&mhp->live_lock);
#endif
err_free_skb:
	kfree_skb(mhp->dereg_skb);
err_free_wr_wait:
	chrd_put_wr_wait(mhp->wr_waitp);
err_free_mhp:
	kfree(mhp);
	return ERR_PTR(err);
}

int chrd_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata)
{
	struct chrd_dev *rhp;
	struct chrd_pd *php;
	struct chrd_mw *mhp;
	u32 mmid;
	u32 stag = 0;
	int ret;

	if (ibmw->type != IB_MW_TYPE_1)
		return -EINVAL;

	php = to_chrd_pd(ibmw->pd);
	rhp = php->rhp;
	mhp = kzalloc(sizeof(*mhp), GFP_KERNEL);
	if (!mhp)
		return -ENOMEM;

	mhp->wr_waitp = chrd_alloc_wr_wait(GFP_KERNEL);
	if (!mhp->wr_waitp) {
		ret = -ENOMEM;
		goto free_mhp;
	}

	mhp->dereg_skb = alloc_skb(SGE_MAX_WR_LEN, GFP_KERNEL);
	if (!mhp->dereg_skb) {
		ret = -ENOMEM;
		goto free_wr_wait;
	}

	ret = allocate_window(&rhp->rdev, &stag, php->pdid, mhp->wr_waitp);
	if (ret) {
		goto free_skb;
	}
	mhp->rhp = rhp;
	mhp->attr.pdid = php->pdid;
	mhp->attr.type = FW_RI_STAG_MW;
	mhp->attr.stag = stag;
	mmid = (stag) >> 8;
	mhp->ibmw.rkey = stag;
	if (xa_insert_irq(&rhp->mrs, mmid, mhp, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto dealloc_win;
	}
	pr_debug("mmid 0x%x mhp %p stag 0x%x\n", mmid, mhp, stag);
	return 0;

dealloc_win:
	deallocate_window(&rhp->rdev, mhp->attr.stag, mhp->dereg_skb,
			  mhp->wr_waitp);
free_skb:
	if (mhp->dereg_skb)
		kfree_skb(mhp->dereg_skb);
free_wr_wait:
	chrd_put_wr_wait(mhp->wr_waitp);
free_mhp:
	kfree(mhp);
	return ret;
}

int chrd_dealloc_mw(struct ib_mw *mw)
{
	struct chrd_dev *rhp;
	struct chrd_mw *mhp;
	u32 mmid;

	mhp = to_chrd_mw(mw);
	rhp = mhp->rhp;
	mmid = (mw->rkey) >> 8;
	xa_erase_irq(&rhp->mrs, mmid);
	deallocate_window(&rhp->rdev, mhp->attr.stag, mhp->dereg_skb,
			  mhp->wr_waitp);
	if (mhp->dereg_skb)
		kfree_skb(mhp->dereg_skb);
	pr_debug("ib_mw %p mmid 0x%x ptr %p\n", mw, mmid, mhp);
	chrd_put_wr_wait(mhp->wr_waitp);
	kfree(mhp);
	return 0;
}

struct ib_mr *chrd_alloc_mr(struct ib_pd *pd,
			    enum ib_mr_type mr_type,
			    u32 max_num_sg)
{
	struct chrd_dev *rhp;
	struct chrd_pd *php;
	struct chrd_mr *mhp;
	u32 mmid;
	u32 stag = 0;
	int ret = 0;
	int length = roundup(max_num_sg * sizeof(u64), 32);

	php = to_chrd_pd(pd);
	rhp = php->rhp;

	if (mr_type != IB_MR_TYPE_MEM_REG ||
	    max_num_sg > t4_max_fr_depth(&rhp->rdev, use_dsgl))
		return ERR_PTR(-EINVAL);

	mhp = kzalloc(sizeof(*mhp), GFP_KERNEL);
	if (!mhp) {
		ret = -ENOMEM;
		goto err;
	}

	mhp->wr_waitp = chrd_alloc_wr_wait(GFP_KERNEL);
	if (!mhp->wr_waitp) {
		ret = -ENOMEM;
		goto err_free_mhp;
	}
	chrd_init_wr_wait(mhp->wr_waitp);

	mhp->mpl = dma_alloc_coherent(rhp->rdev.lldi.dev,
				      length, &mhp->mpl_addr, GFP_KERNEL);
	if (!mhp->mpl) {
		ret = -ENOMEM;
		goto err_free_wr_wait;
	}
	mhp->max_mpl_len = length;

	mhp->rhp = rhp;
	ret = alloc_pbl(mhp, max_num_sg);
	if (ret)
		goto err_free_dma;
	mhp->attr.pbl_size = max_num_sg;
	ret = allocate_stag(&rhp->rdev, &stag, php->pdid,
			    mhp->attr.pbl_size, mhp->attr.pbl_addr,
			    mhp->wr_waitp);
	if (ret)
		goto err_free_pbl;
	mhp->attr.pdid = php->pdid;
	mhp->attr.type = FW_RI_STAG_NSMR;
	mhp->attr.stag = stag;
	mhp->attr.state = 0;
	mmid = (stag) >> 8;
	mhp->ibmr.rkey = mhp->ibmr.lkey = stag;
	if (xa_insert_irq(&rhp->mrs, mmid, mhp, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto err_dereg;
	}

	pr_debug("mmid 0x%x mhp %p stag 0x%x max_num_sg %u length %d\n",
		 mmid, mhp, stag, max_num_sg, length);
	return &(mhp->ibmr);
err_dereg:
	dereg_mem(&rhp->rdev, stag, mhp->attr.pbl_size,
		       mhp->attr.pbl_addr, mhp->dereg_skb, mhp->wr_waitp);
err_free_pbl:
	chrd_pblpool_free(&mhp->rhp->rdev, mhp->attr.pbl_addr,
			      mhp->attr.pbl_size << 3);
err_free_dma:
	dma_free_coherent(mhp->rhp->rdev.lldi.dev,
			  mhp->max_mpl_len, mhp->mpl, mhp->mpl_addr);
err_free_wr_wait:
	chrd_put_wr_wait(mhp->wr_waitp);
err_free_mhp:
	kfree(mhp);
err:
	return ERR_PTR(ret);
}

static int chrd_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct chrd_mr *mhp = to_chrd_mr(ibmr);

	if (unlikely(mhp->mpl_len == mhp->attr.pbl_size))
		return -ENOMEM;

	mhp->mpl[mhp->mpl_len++] = addr;

	return 0;
}

int chrd_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
#ifdef IWARP_HAVE_SG_OFFSET
		   int sg_nents, unsigned int *sg_offset)
#else
		   int sg_nents)
#endif
{
	struct chrd_mr *mhp = to_chrd_mr(ibmr);

	mhp->mpl_len = 0;

#ifdef IWARP_HAVE_SG_OFFSET
	return ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset, chrd_set_page);
#else
	return ib_sg_to_pages(ibmr, sg, sg_nents, chrd_set_page);
#endif
}

int chrd_dereg_mr(struct ib_mr *ib_mr, struct ib_udata *udata)
{
#ifdef HAVE_PEER_MEM_SUPPORT
	struct chrd_mr *mhp;

	pr_debug("ib_mr %p\n", ib_mr);

 	mhp = to_chrd_mr(ib_mr);

	/*
	 * If its invalidated or invalidating, then wait for that
	 * to complete which deregisters the MR, and then just
	 * free mhp.  Otherwise we do the invalidation here.
	 */
	if (atomic_inc_return(&mhp->invalidated) > 1) {
		wait_for_completion(&mhp->invalidation_comp);
		goto end;
	}

	release_mr_resources(mhp);
end:
#else
	struct chrd_dev *rhp;
	struct chrd_mr *mhp;
	u32 mmid;

	pr_debug("ib_mr %p\n", ib_mr);

	mhp = to_chrd_mr(ib_mr);
	rhp = mhp->rhp;
	mmid = mhp->attr.stag >> 8;
	xa_erase_irq(&rhp->mrs, mmid);
	if (mhp->mpl)
		dma_free_coherent(mhp->rhp->rdev.lldi.dev,
				  mhp->max_mpl_len, mhp->mpl, mhp->mpl_addr);
	dereg_mem(&rhp->rdev, mhp->attr.stag, mhp->attr.pbl_size,
		       mhp->attr.pbl_addr, mhp->dereg_skb,
		       mhp->wr_waitp);
	if (mhp->attr.pbl_size)
		chrd_pblpool_free(&mhp->rhp->rdev, mhp->attr.pbl_addr,
				  mhp->attr.pbl_size << 3);
	if (mhp->kva)
		kfree((void *) (unsigned long) mhp->kva);
	if (mhp->umem)
		ib_umem_release(mhp->umem);
	pr_debug("mmid 0x%x ptr %p\n", mmid, mhp);
#endif
	chrd_put_wr_wait(mhp->wr_waitp);
	kfree(mhp);
	return 0;
}

void chrd_invalidate_mr(struct chrd_dev *rhp, u32 rkey)
{
	struct chrd_mr *mhp;
	unsigned long flags;

	xa_lock_irqsave(&rhp->mrs, flags);
	mhp = xa_load(&rhp->mrs, rkey >> 8);
	if (mhp)
		mhp->attr.state = 0;
	xa_unlock_irqrestore(&rhp->mrs, flags);
}
